#!/usr/bin/env python3
"""
批量深度扫描引擎 v3.1（支持断点续扫）
  关机不怕 — 开机后加 --resume 自动跳过已完成的目标

  用法: python batch_runner.py                    # 新扫描
        python batch_runner.py --resume            # 断点续扫
        python batch_runner.py --resume --phases scan  # 续扫指定阶段
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable
TARGETS_FILE = os.path.join(BASE_DIR, "targets_ai2.txt")
PROGRESS_FILE = os.path.join(BASE_DIR, "batch4_progress.json")


def load_targets():
    targets = []
    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) >= 3:
                targets.append({
                    "abbr": parts[0].strip(),
                    "domain": parts[1].strip(),
                    "name": parts[2].strip(),
                })
    return targets


def load_progress():
    """加载断点进度"""
    if os.path.isfile(PROGRESS_FILE):
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_progress(data):
    """保存进度（原子写入，防断电损坏）"""
    tmp = PROGRESS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, PROGRESS_FILE)


def is_phase_done(progress, abbr, phase):
    """检查某个目标的某个阶段是否已完成"""
    if abbr not in progress:
        return False
    return progress[abbr].get(phase, False)


def mark_phase_done(progress, abbr, phase):
    """标记阶段完成并立即保存"""
    if abbr not in progress:
        progress[abbr] = {}
    progress[abbr][phase] = True
    progress[abbr]["last_update"] = datetime.now().isoformat()
    save_progress(progress)


def run_phase(name, script, abbr, domain):
    script_path = os.path.join(BASE_DIR, script)
    if not os.path.isfile(script_path):
        print(f"  [!] 脚本不存在: {script_path}")
        return False

    cmd = [PYTHON, script_path, "--project", abbr]
    if "--domain" in open(script_path, encoding="utf-8").read()[:2000]:
        cmd.extend(["--domain", domain])
    if script == "dir_scanner.py":
        cmd.extend(["--tier", "2"])

    print(f"\n  [{name}] {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, timeout=3600, cwd=BASE_DIR,
                              stdin=subprocess.DEVNULL)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"  [!] {name} 超时(1h)")
        return False
    except Exception as e:
        print(f"  [!] {name} 出错: {e}")
        return False


def process_target(target, progress, phases="full", resume=False):
    abbr = target["abbr"]
    domain = target["domain"]
    name = target["name"]

    # 断点续扫：检查是否全部完成
    if resume:
        all_required_done = True
        if phases in ("full", "recon"):
            if not is_phase_done(progress, abbr, "subdomain"): all_required_done = False
            if not is_phase_done(progress, abbr, "info_collect"): all_required_done = False
        if phases in ("full", "scan"):
            if not is_phase_done(progress, abbr, "dir_scan"): all_required_done = False
            if not is_phase_done(progress, abbr, "vuln_scan"): all_required_done = False
            if not is_phase_done(progress, abbr, "api_js"): all_required_done = False
        if phases in ("full", "auth"):
            if not is_phase_done(progress, abbr, "credential"): all_required_done = False
        if all_required_done:
            print(f"  [{abbr}] {name} — 已全部完成，跳过")
            return None  # None表示跳过

    t_idx = targets.index(target) + 1
    print(f"\n{'#'*70}")
    print(f"# [{t_idx}/{len(targets)}] {name}")
    print(f"# 缩写: {abbr} | 域名: {domain}")
    print(f"# 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if resume:
        done_phases = [k for k, v in progress.get(abbr, {}).items()
                      if v is True and k != "last_update"]
        if done_phases:
            print(f"# 已完成阶段: {', '.join(done_phases)}")
    print(f"{'#'*70}")

    results = {}

    # Phase 1: 子域名收集
    if phases in ("full", "recon") and not (resume and is_phase_done(progress, abbr, "subdomain")):
        print(f"\n--- Phase 1: 子域名收集 ---")
        ok = run_phase("子域名收集", "subdomain_collector.py", abbr, domain)
        results["subdomain"] = ok
        if ok: mark_phase_done(progress, abbr, "subdomain")
        time.sleep(3)

    # Phase 2: 信息收集
    if phases in ("full", "recon") and not (resume and is_phase_done(progress, abbr, "info_collect")):
        print(f"\n--- Phase 2: 信息收集+指纹 ---")
        ok = run_phase("信息收集", "school_info_collector.py", abbr, domain)
        results["info_collect"] = ok
        if ok: mark_phase_done(progress, abbr, "info_collect")
        time.sleep(5)

    # Phase 3: 目录爆破
    if phases in ("full", "scan") and not (resume and is_phase_done(progress, abbr, "dir_scan")):
        print(f"\n--- Phase 3: 目录爆破 ---")
        ok = run_phase("目录爆破", "dir_scanner.py", abbr, domain)
        results["dir_scan"] = ok
        if ok: mark_phase_done(progress, abbr, "dir_scan")
        time.sleep(3)

    # Phase 4: 漏洞扫描
    if phases in ("full", "scan") and not (resume and is_phase_done(progress, abbr, "vuln_scan")):
        print(f"\n--- Phase 4: 漏洞扫描 ---")
        ok = run_phase("漏洞调度", "vuln_dispatcher.py", abbr, domain)
        results["vuln_scan"] = ok
        if ok: mark_phase_done(progress, abbr, "vuln_scan")
        time.sleep(3)

    # Phase 5: API+JS
    if phases in ("full", "scan") and not (resume and is_phase_done(progress, abbr, "api_js")):
        print(f"\n--- Phase 5: API+JS分析 ---")
        ok1 = run_phase("API安全", "api_security.py", abbr, domain)
        ok2 = run_phase("JS分析", "js_analyzer.py", abbr, domain)
        results["api_js"] = ok1 or ok2
        if ok1 or ok2: mark_phase_done(progress, abbr, "api_js")
        time.sleep(3)

    # Phase 6: 凭据喷洒
    if phases in ("full", "auth") and not (resume and is_phase_done(progress, abbr, "credential")):
        print(f"\n--- Phase 6: 凭据喷洒 ---")
        ok = run_phase("凭据喷洒", "credential_spray.py", abbr, domain)
        results["credential"] = ok
        if ok: mark_phase_done(progress, abbr, "credential")

    # 汇总
    if results:
        success = sum(1 for v in results.values() if v)
        total = len(results)
        print(f"\n  [{abbr}] 完成: {success}/{total} 阶段成功")
    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="批量深度扫描引擎 v3.1")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int, default=100)
    parser.add_argument("--phases", choices=["full", "recon", "scan", "auth"],
                       default="scan")
    parser.add_argument("--delay", type=int, default=8)
    parser.add_argument("--resume", action="store_true", help="断点续扫")
    args = parser.parse_args()

    global targets
    targets = load_targets()
    targets = targets[args.start:args.end]

    progress = load_progress() if args.resume else {}

    if args.resume:
        already = sum(1 for t in targets
                     if all(progress.get(t["abbr"], {}).get(p, False)
                           for p in ["subdomain","info_collect"]))
        print(f"\n  断点续扫: {already}/{len(targets)} 已完成信息收集")
        print(f"  进度文件: {PROGRESS_FILE}")

    print(f"\n{'='*70}")
    print(f"  批量深度扫描引擎 v3.1")
    print(f"  目标总数: {len(targets)} | 范围: [{args.start}-{args.end})")
    print(f"  扫描深度: {args.phases} | 续扫: {args.resume}")
    print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")

    for i, t in enumerate(targets):
        try:
            results = process_target(t, progress, args.phases, args.resume)
        except KeyboardInterrupt:
            print(f"\n[!] Ctrl+C — 进度已保存到 {PROGRESS_FILE}")
            print(f"    开机后执行: python batch_runner.py --resume --phases {args.phases}")
            break
        except Exception as e:
            print(f"\n[!] {t['abbr']} 致命错误: {e}")
            continue

        if i < len(targets) - 1:
            print(f"\n  ... {args.delay}s 后进入下一目标 ...")
            time.sleep(args.delay)

    # 最终汇总
    print(f"\n{'='*70}")
    done = sum(1 for t in targets
              if progress.get(t["abbr"], {}).get("vuln_scan"))
    print(f"  扫描完成: {done}/{len(targets)} 目标已深度扫描")
    print(f"  进度文件: {PROGRESS_FILE}")
    print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[!] 已取消 — 进度保存在 {PROGRESS_FILE}")
        print(f"    恢复: python batch_runner.py --resume")
    try:
        input("\n按 Enter 退出...")
    except (EOFError, KeyboardInterrupt):
        pass
