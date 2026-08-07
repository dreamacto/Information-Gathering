#!/usr/bin/env python3
# encoding: utf-8
"""
目录/路径爆破
  优先调用外部 dirsearch（软404过滤成熟），不可用时回退内置扫描器。

用法:
  python dir_scanner.py --project glut
  python dir_scanner.py --project glut --targets glut/glut_priority_targets.txt
"""

import os
import re
import random
import subprocess
import sys
import tempfile
import time
from urllib.parse import urljoin, urlparse

from pentest_utils import (
    resolve_path, build_headers, safe_request, load_progress, save_progress, BASE_DIR,
    get_target_domains, filter_urls_by_domain,
)

WORDLIST_FILE = os.path.join(BASE_DIR, "wordlists", "common_dirs.txt")
ALLOWED_STATUS = (200, 301, 302, 307, 308, 403, 401)

# 常见 dirsearch 路径
from config import tool_path
DIRSEARCH_PATHS = [
    tool_path("dirsearch") or "",
    os.path.join(BASE_DIR, "tools", "dirsearch", "dirsearch.py"),
]


def _find_dirsearch():
    for p in DIRSEARCH_PATHS:
        if os.path.isfile(p):
            return p
    # 最后试试 PATH 里有没有
    try:
        subprocess.run(["dirsearch", "--version"], capture_output=True, timeout=5, check=False)
        return "dirsearch"
    except Exception:
        pass
    return None


def _parse_priority_tiers(fpath):
    """解析 priority_targets.txt，返回 {'T1': [urls], 'T2': [urls], 'T3': [urls]}"""
    tiers = {"T1": [], "T2": [], "T3": []}
    current = None
    with open(fpath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "第一梯队" in line:
                current = "T1"
            elif "第二梯队" in line:
                current = "T2"
            elif "第三梯队" in line:
                current = "T3"
            elif line.startswith("http") and current:
                tiers[current].append(line)
    return tiers


def load_targets(project, targets_file=None):
    if targets_file:
        fpath = targets_file
    else:
        priority = resolve_path(project, "priority_targets.txt")
        if os.path.isfile(priority):
            fpath = priority
            print(f"[+] 自动使用重点目标: {fpath}")
        else:
            fpath = resolve_path(project, "urls.txt")
    if not os.path.isfile(fpath):
        print(f"[-] 找不到 {fpath}"); sys.exit(1)

    # tier selection: use --tier arg or default to T1+T2 in non-interactive mode
    tier_choice = "2"
    if not targets_file and "priority_targets" in fpath:
        tiers = _parse_priority_tiers(fpath)
        print(f"    T1={len(tiers['T1'])} T2={len(tiers['T2'])} T3={len(tiers['T3'])}")
        # check --tier arg
        tier = 0
        try:
            if '--tier' in sys.argv:
                idx = sys.argv.index('--tier')
                tier = int(sys.argv[idx + 1])
        except Exception:
            pass
        if tier > 0:
            tier_choice = str(tier)
        elif not sys.stdin.isatty():
            tier_choice = "2"
            print("    Non-interactive: default T1+T2")
        else:
            try:
                tier_choice = input("    [1]T1 [2]T1+T2 [3]All [4]Cancel: ").strip()
            except EOFError:
                tier_choice = "2"
        if tier_choice == "1":
            result = tiers["T1"]
        elif tier_choice == "2":
            result = tiers["T1"] + tiers["T2"]
        elif tier_choice == "3":
            result = tiers["T1"] + tiers["T2"] + tiers["T3"]
        else:
            print("[!] Cancelled"); sys.exit(0)
        # 域名过滤
        targets = get_target_domains(result)
        filtered = filter_urls_by_domain(result, targets)
        skipped = len(result) - len(filtered)
        if skipped:
            print(f"    [过滤] 排除 {skipped} 个外部链接，域名: {', '.join(sorted(targets))}")
        return filtered

    with open(fpath, "r", encoding="utf-8") as f:
        result = [line.strip() for line in f
                if line.strip() and not line.startswith("#") and line.startswith("http")]
    # 域名过滤
    targets = get_target_domains(result)
    filtered = filter_urls_by_domain(result, targets)
    skipped = len(result) - len(filtered)
    if skipped:
        print(f"[+] 域名白名单: {', '.join(sorted(targets))}（过滤 {skipped} 个外部链接）")
    return filtered


# ==================== 外部 dirsearch 调用 ====================

def _get_404_baseline(base_url, tmpdir):
    """请求随机不存在路径，保存响应为文件供 dirsearch --exclude-response 使用"""
    fake = f"/__nx_{random.randint(10000, 99999)}_{int(time.time()*1000)%1000000}__.html"
    url = urljoin(base_url, fake)
    try:
        resp = safe_request(url, method="GET", timeout=8, retries=1)
        resp.encoding = resp.apparent_encoding
        # 构造类 HTTP 响应的文本（dirsearch 用文本相似度比较）
        status_line = f"HTTP/1.1 {resp.status_code}\n"
        headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body = resp.text[:10000]
        content = f"{status_line}{headers}\n\n{body}"
        fpath = os.path.join(tmpdir, f"baseline_{random.randint(1000,9999)}.txt")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        return fpath
    except Exception:
        return None


def _run_dirsearch(target_url, wordlist, dirsearch_path, outdir, threads=5, delay=0.5):
    """用外部 dirsearch 扫描单个目标，返回 (发现的路径列表, 是否成功)"""
    tmpdir = tempfile.mkdtemp(prefix="ds_")

    baseline_file = _get_404_baseline(target_url, tmpdir)
    if baseline_file:
        print(f"      [基线] {os.path.basename(baseline_file)}")

    ds_outdir = os.path.join(outdir, "dirsearch_outputs")
    os.makedirs(ds_outdir, exist_ok=True)
    output_file = os.path.join(ds_outdir, f"dirsearch_{urlparse(target_url).netloc}.txt")

    cmd = [
        sys.executable, dirsearch_path,
        "-u", target_url,
        "-w", wordlist,
        "-t", str(threads),
        "--delay", str(delay),
        "--timeout", "8",
        "--retries", "1",
        "--random-agent",
        "--format", "plain",
        "-o", output_file,
        "--no-color",
    ]
    if baseline_file:
        cmd.extend(["--exclude-response", baseline_file])

    print(f"      运行: dirsearch -u {target_url} -w ... -t {threads}")
    try:
        result = subprocess.run(cmd, timeout=600, check=False, capture_output=True,
                                encoding="utf-8", errors="replace",
                                cwd=os.path.dirname(dirsearch_path))
        stderr = result.stderr or ""
        if "ModuleNotFoundError" in stderr or "ImportError" in stderr:
            print(f"      [!] dirsearch 缺少依赖，回退内置扫描器")
            return [], False
    except subprocess.TimeoutExpired:
        print("      [!] dirsearch 超时")
        return [], False
    except Exception as e:
        print(f"      [!] dirsearch 出错: {e}")
        return [], False

    found = []
    if os.path.isfile(output_file):
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                # dirsearch plain format: "200   888B   http://host/path"
                m = re.match(r"(\d{3})\s+\S+\s+(https?://\S+)", line)
                if m:
                    status = int(m.group(1))
                    url = m.group(2).strip()
                    if status in ALLOWED_STATUS:
                        found.append({"url": url, "status": str(status), "length": "?"})
    return found, True


# ==================== 内置回退扫描器（精简版） ====================

def _builtin_scan(urls, wordlist, threads, delay_range, outpath):
    """内置扫描，逐目标收集结果"""
    import difflib
    import hashlib
    from collections import Counter
    from concurrent.futures import ThreadPoolExecutor, as_completed

    SOFT_404_TITLE = ["404", "not found", "页面不存在", "找不到", "出错", "错误", "error",
                       "访问被禁", "禁止访问", "forbidden", "无权限", "iis"]
    SOFT_404_BODY = ["页面不存在", "找不到该页面", "您访问的页面不存在",
                      "access denied", "访问被拒绝", "没有权限",
                      "directory listing denied", "runtime error",
                      "server error in '/' application", "whitelabel error page"]

    def _body_hash(body, n=3000):
        return hashlib.md5(body[:n]).hexdigest()

    def _get_baselines(target):
        samples = []
        for p in [f"/__nx_{random.randint(10000,99999)}__",
                  f"/__nx_{random.randint(10000,99999)}__.html"]:
            try:
                r = safe_request(urljoin(target, p), method="GET", timeout=8, retries=1)
                samples.append({"hash": _body_hash(r.content), "len": len(r.content), "body": r.content})
            except Exception:
                pass
        seen = set(); return [s for s in samples if not (s["hash"] in seen or seen.add(s["hash"]))]

    def _check(url):
        try:
            r = safe_request(url, method="HEAD", timeout=6, retries=1)
            if r.status_code not in ALLOWED_STATUS:
                return None
        except Exception:
            return None
        try:
            r = safe_request(url, method="GET", timeout=6, retries=1)
            return {"url": url, "status": str(r.status_code), "len": len(r.content),
                    "hash": _body_hash(r.content), "body": r.content}
        except Exception:
            return {"url": url, "status": "?", "len": 0, "hash": "", "body": b""}

    all_results = {}
    total = 0
    start_time = time.time()
    for target_idx, target in enumerate(urls, 1):
        elapsed = time.time() - start_time
        avg_per = elapsed / max(target_idx - 1, 1)
        remaining = avg_per * (len(urls) - target_idx + 1)
        host = urlparse(target).netloc or target
        print(f"\n[*] [{target_idx}/{len(urls)}] {host} | 已用 {elapsed:.0f}s 剩余 ~{remaining/60:.0f}min")

        baselines = _get_baselines(target)
        print(f"    [*] 基线: {len(baselines)} 个")

        raw = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            fs = {ex.submit(_check, urljoin(target, p)): p for p in wordlist}
            for i, fut in enumerate(as_completed(fs), 1):
                r = fut.result()
                if r:
                    raw.append(r)
                if i < len(wordlist):
                    time.sleep(random.uniform(*delay_range))
                if i % 50 == 0:
                    print(f"    ... {i}/{len(wordlist)}")

        # 过滤
        hash_counts = Counter(r["hash"] for r in raw if r["hash"])
        found = []
        for r in raw:
            body = r.get("body", b"")
            h, ln = r["hash"], r["len"]
            body_str = body[:4000].decode("utf-8", errors="ignore").lower() if body else ""

            # 基线匹配
            skip = False
            for bl in baselines:
                if h == bl["hash"]:
                    skip = True; break
                if abs(ln - bl["len"]) / max(bl["len"], 1) < 0.3:
                    import difflib
                    s = difflib.SequenceMatcher(None,
                        body[:4000].decode("utf-8", errors="ignore"),
                        bl["body"][:4000].decode("utf-8", errors="ignore")).ratio()
                    if s >= 0.90:
                        skip = True; break
            if skip:
                continue
            # 聚类
            if h and hash_counts.get(h, 0) >= 3:
                continue
            # 关键字
            title_match = re.search(rb"<title[^>]*>(.*?)</title>", body[:8000], re.I | re.DOTALL)
            title = title_match.group(1).decode("utf-8", errors="ignore").lower() if title_match else ""
            for kw in SOFT_404_TITLE:
                if kw in title:
                    skip = True; break
            if skip:
                continue
            if ln < 1500:
                for kw in SOFT_404_BODY + SOFT_404_TITLE:
                    if kw in body_str:
                        skip = True; break
            if skip:
                continue
            if "iis" in body_str and ("detail" in body_str or "error" in body_str):
                continue
            if "server error" in body_str and "application" in body_str:
                continue
            if "whitelabel error page" in body_str:
                continue

            found.append({"url": r["url"], "status": r["status"], "length": str(ln)})

        all_results[target] = found
        total += len(found)
        print(f"    发现 {len(found)} 个目录（已过滤）")

    # 保存
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(f"# 目录爆破结果（已过滤软404）\n# 时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        for t, items in all_results.items():
            f.write(f"\n# --- {t} ---\n")
            for item in items:
                f.write(f"{item['url']}  [{item['status']}]\n")
    print(f"\n[√] {outpath}")
    print(f"[√] 共发现 {total} 个目录（已过滤软404）")


# ==================== 主入口 ====================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="目录爆破")
    parser.add_argument("--project", "--abbr", default=None, dest="project")
    parser.add_argument("--targets", default=None, help="指定目标文件")
    parser.add_argument("--tier", type=int, choices=[1,2,3], default=0,
                       help="梯队选择: 1=T1 only, 2=T1+T2, 3=全部 (0=交互式)")
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--delay-min", type=float, default=0.3)
    parser.add_argument("--delay-max", type=float, default=1.0)
    args = parser.parse_args()

    project = args.project
    if not project and not args.targets and not sys.stdin.isatty():
        # 非交互模式必须有project
        print("[-] 非交互模式需要 --project 参数")
        sys.exit(1)
    if not project and not args.targets:
        try:
            project = input("请输入项目缩写（留空=根目录）: ").strip().lower() or None
        except EOFError:
            print("[-] 非交互模式需要 --project 参数")
            sys.exit(1)

    print("=" * 60)
    label = f"[{project or '根目录'}]" if not args.targets else f"[{args.targets}]"
    print(f"  目录爆破 - {label}")
    print("=" * 60)

    urls = load_targets(project, args.targets)
    wordlist_file = WORDLIST_FILE
    if not os.path.isfile(wordlist_file):
        print(f"[-] 字典不存在: {wordlist_file}"); sys.exit(1)

    print(f"[+] 目标: {len(urls)} | 字典: {os.path.basename(wordlist_file)}")
    est = len(urls) * 398 * (args.delay_min + args.delay_max) / 2 / args.threads
    print(f"[+] 预估: {est/60:.1f} 分钟")

    outpath = resolve_path(project, "dirs.txt") if project else "dirs.txt"
    outdir = os.path.dirname(outpath) or "."

    # 加载字典
    wordlist = [l.strip() for l in open(wordlist_file, encoding="utf-8")
                if l.strip() and not l.startswith("#")]

    # 断点续扫
    progress_file = resolve_path(project, "dirs_progress.txt") if project else "dirs_progress.txt"
    scanned = load_progress(progress_file)
    if scanned:
        print(f"[+] 发现上次进度: 已完成 {len(scanned)} 个")
        try:
            choice = input("    [1] 继续上次扫描  [2] 重新开始  [3] 退出: ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "1"
            print("\n    [1] 自动选择: 断点续扫")
        if choice == "2":
            scanned = set()
            with open(progress_file, "w", encoding="utf-8") as _:
                pass
            print("[+] 已清除进度，重新开始")
        elif choice == "3":
            print("[!] 已退出"); sys.exit(0)
        else:
            print(f"[+] 断点续扫: 跳过 {len(scanned)} 个已完成目标")

    # 检测外部 dirsearch
    dirsearch_path = _find_dirsearch()
    use_builtin = True
    if dirsearch_path:
        print(f"[+] 使用外部 dirsearch: {dirsearch_path}")
        start_time = time.time()
        total_targets = len(urls)
        # 找到第一个未扫描的目标开始
        remaining_urls = [u for u in urls if u not in scanned]
        if not remaining_urls:
            print("[√] 所有目标已完成，无需扫描"); return
        # 先测试第一个目标，看 dirsearch 能否正常运行
        test_url = remaining_urls[0]
        idx_offset = len(urls) - len(remaining_urls)
        print(f"\n[*] [{idx_offset+1}/{total_targets}] {urlparse(test_url).netloc or test_url}")
        _, ok = _run_dirsearch(test_url, wordlist_file, dirsearch_path, outdir,
                               threads=args.threads, delay=(args.delay_min + args.delay_max) / 2)
        if ok:
            use_builtin = False
            all_results = {test_url: _}
            save_progress(progress_file, test_url)
            print(f"    [{idx_offset+1}/{total_targets}] 发现 {len(_)} 个目录")
            # 继续扫描剩余目标
            for idx, u in enumerate(remaining_urls[1:], 2):
                real_idx = idx_offset + idx
                elapsed = time.time() - start_time
                avg_per = elapsed / (idx - 1)
                remaining = avg_per * (total_targets - real_idx + 1)
                host = urlparse(u).netloc or u
                print(f"\n[*] [{real_idx}/{total_targets}] {host} | 已用 {elapsed:.0f}s 剩余 ~{remaining/60:.0f}min")
                found, _ = _run_dirsearch(u, wordlist_file, dirsearch_path, outdir,
                                          threads=args.threads,
                                          delay=(args.delay_min + args.delay_max) / 2)
                all_results[u] = found
                save_progress(progress_file, u)
                print(f"    [{real_idx}/{total_targets}] 发现 {len(found)} 个目录")

            # 合并已有结果
            outpath = resolve_path(project, "dirs.txt") if project else "dirs.txt"
            # 读取所有 dirsearch_outputs 下的结果
            ds_outdir = os.path.join(outdir, "dirsearch_outputs")
            merged = {}
            if os.path.isdir(ds_outdir):
                for fname in os.listdir(ds_outdir):
                    fpath = os.path.join(ds_outdir, fname)
                    for line in open(fpath, encoding="utf-8", errors="ignore"):
                        line = line.strip()
                        m = re.match(r"(\d{3})\s+\S+\s+(https?://\S+)", line)
                        if m and int(m.group(1)) in ALLOWED_STATUS:
                            merged.setdefault(fname, []).append((m.group(2), m.group(1)))
            with open(outpath, "w", encoding="utf-8") as f:
                f.write(f"# 目录爆破结果（dirsearch）\n# 时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                for fname, items in merged.items():
                    f.write(f"\n# --- {fname} ---\n")
                    for url, status in items:
                        f.write(f"{url}  [{status}]\n")
            total = sum(len(v) for v in merged.values())
            print(f"\n[√] {outpath}")
            print(f"[√] 累计 {len(merged)} 个目标，共 {total} 个目录")
        else:
            print("[!] dirsearch 运行失败，回退到内置扫描器")

    if use_builtin:
        print("[+] 使用内置扫描器")
        _builtin_scan(urls, wordlist, args.threads, (args.delay_min, args.delay_max), outpath)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 已取消")
    except Exception as e:
        print(f"\n[!] 错误: {e}")
    try:
        input("\n按 Enter 退出...")
    except (EOFError, KeyboardInterrupt):
        pass
