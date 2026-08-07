#!/usr/bin/env python3
# encoding: utf-8
"""
子域名收集脚本
  Linux:   subfinder | httprobe
  Windows: oneforall（天狐工具箱）→ HTTP探活
  回退:    crt.sh + DNS爆破 + HTTP探活

用法:
  python subdomain_collector.py --abbr glut --domain glut.edu.cn
"""

import argparse
import json
import os
import platform
import random
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IS_WINDOWS = platform.system() == "Windows"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

BUILTIN_SUBDOMAINS = [
    "www", "mail", "vpn", "portal", "eip", "my", "sso", "cas", "idp", "auth",
    "login", "passport", "m", "wap", "mobile", "app", "api", "cdn", "static",
    "img", "images", "upload", "down", "download", "file", "files", "bbs", "forum",
    "blog", "wiki", "news", "oa", "webmail", "help", "support",
    "jwc", "yjs", "yjsy", "yzw", "lib", "cs", "ee", "math", "phy", "chem",
    "bio", "law", "med", "art", "pe", "iec", "oia", "xsc", "zzb", "tzb",
    "audit", "gzc", "rsc", "jcc", "hqc", "wzb", "dxs", "tw", "xgc", "xsgzb",
    "xgxt", "jwxt", "zsb", "gk", "cwc", "dw", "gh", "lxy", "smxy", "jdxy",
    "slxy", "wfxy", "jyxy", "ysxy", "tyxy", "gxy", "nxy", "dqxy", "rjxy",
    "admin", "test", "dev", "demo", "old", "new",
    "en", "v6", "ipv6", "lx", "lxzx", "cms",
    "graduate", "alumni", "career", "jobs", "zhaopin", "job",
    "library", "email", "elearning", "lms", "mooc", "metc", "etc",
    "gzw", "zbb", "zzrsb", "pgu", "dx", "gw", "xxgk", "xxzx",
    "wsc", "tm", "net", "host", "cloud", "data", "db", "lab",
]

# 天狐工具箱路径
from config import TIANHU_BASE, TIANHU_GUI_SHOUJI
ONEFORALL_DIR = os.path.join(TIANHU_GUI_SHOUJI, "oneforall")
ONEFORALL_SCRIPT = os.path.join(ONEFORALL_DIR, "oneforall.py")


# ==================== Linux: subfinder | httprobe ====================

def _has_cmd(cmd):
    try:
        subprocess.run(["which", cmd], capture_output=True, timeout=3, check=False)
        return True
    except Exception:
        return False


def linux_collect_and_probe(domain):
    print("[*] subfinder 收集子域名 ...")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "30"],
            capture_output=True, text=True, timeout=60
        )
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not subdomains:
            print("    [-] subfinder 无结果"); return []
        print(f"    [+] subfinder 发现 {len(subdomains)} 个")
    except FileNotFoundError:
        print("    [-] subfinder 未安装"); return []
    except subprocess.TimeoutExpired:
        print("    [-] subfinder 超时"); return []

    if _has_cmd("httprobe"):
        print(f"[*] httprobe 探活（-c 50 -t 3000）...")
        try:
            result = subprocess.run(
                ["httprobe", "-c", "50", "-t", "3000"],
                input="\n".join(subdomains), capture_output=True, text=True, timeout=120
            )
            alive = sorted(set(line.strip() for line in result.stdout.splitlines() if line.strip()))
            print(f"    [+] httprobe 存活: {len(alive)} / {len(subdomains)}")
            return alive
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    print(f"[*] Python HTTP 探活（{len(subdomains)} 个，50 线程）...")
    alive = _python_httprobe(subdomains)
    print(f"    [+] 存活: {len(alive)} / {len(subdomains)}")
    return alive


# ==================== oneforall（天狐）- 直接 import 调用 ====================

def _oneforall_collect(domain):
    """直接导入 oneforall Python API 收集子域名（无需子进程）"""
    # 确保 oneforall 在 sys.path 中
    if ONEFORALL_DIR not in sys.path:
        sys.path.insert(0, ONEFORALL_DIR)

    try:
        from oneforall import OneForAll
    except ImportError as e:
        print(f"    [-] oneforall 导入失败: {e}")
        # 回退到子进程方式
        return _oneforall_collect_subprocess(domain)

    print(f"[*] oneforall 收集子域名（直接 API）...")
    try:
        # 创建 OneForAll 实例并运行
        ofa = OneForAll(
            target=domain,
            brute=True,
            dns=True,
            req=False,   # 跳过 oneforall 自带的 HTTP 请求，用我们的探活
            alive=False, # 导出全部子域名
            port="small",
            fmt="csv",
        )
        # OneForAll.run() 内部会保存结果到 CSV
        # 但我们也需要拿到结果，所以检查生成的 CSV 文件
        ofa.run()

        # 读取结果 CSV
        import csv
        results_dir = os.path.join(ONEFORALL_DIR, "results")
        csv_file = os.path.join(results_dir, f"{domain}.csv")

        subdomains = set()
        if os.path.isfile(csv_file):
            with open(csv_file, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader, [])
                try:
                    sub_idx = header.index("subdomain")
                except ValueError:
                    sub_idx = 5
                for row in reader:
                    if row and len(row) > sub_idx:
                        sub = row[sub_idx].strip().lower()
                        if sub:
                            subdomains.add(sub)

        if subdomains:
            print(f"    [+] oneforall 发现 {len(subdomains)} 个子域名")
            return sorted(subdomains)
        else:
            print("    [-] oneforall 无结果")
            return None

    except Exception as e:
        print(f"    [-] oneforall 出错: {e}")
        return None


def _oneforall_collect_subprocess(domain):
    """回退方案：用子进程调用 oneforall"""
    oneforall_script = os.path.join(ONEFORALL_DIR, "oneforall.py")
    if not os.path.isfile(oneforall_script):
        return None

    print(f"[*] oneforall 子进程调用（{oneforall_script}）...")
    try:
        result = subprocess.run(
            [sys.executable, oneforall_script, "--target", domain,
             "--alive", "False", "--req", "False", "run"],
            capture_output=True, timeout=300,
            cwd=ONEFORALL_DIR,
            encoding="utf-8", errors="replace",
        )
        results_dir = os.path.join(ONEFORALL_DIR, "results")
        csv_file = os.path.join(results_dir, f"{domain}.csv")

        subdomains = set()
        if os.path.isfile(csv_file):
            import csv
            with open(csv_file, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader, [])
                try:
                    sub_idx = header.index("subdomain")
                except ValueError:
                    sub_idx = 5
                for row in reader:
                    if row and len(row) > sub_idx:
                        sub = row[sub_idx].strip().lower()
                        if sub:
                            subdomains.add(sub)
        if subdomains:
            print(f"    [+] oneforall 发现 {len(subdomains)} 个子域名（子进程）")
            return sorted(subdomains)
        else:
            print("    [-] oneforall 无结果")
            return None
    except subprocess.TimeoutExpired:
        print("    [-] oneforall 超时")
        return None
    except Exception as e:
        print(f"    [-] oneforall 出错: {e}")
        return None


# ==================== 回退: crt.sh + DNS ====================

def _check_subdomain(domain, subdomain, timeout=3):
    fqdn = f"{subdomain}.{domain}"
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(fqdn, None)
        return fqdn
    except (socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old)


def _dns_bruteforce(domain, threads=30):
    found = set()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_check_subdomain, domain, sub): sub for sub in BUILTIN_SUBDOMAINS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.add(result)
    return found


def _crtsh_collect(domain):
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                            timeout=15, verify=False)
        if resp.status_code != 200:
            print(f"    [!] crt.sh 返回状态码 {resp.status_code}")
            return subdomains
        for entry in resp.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subdomains.add(name)
    except requests.RequestException as e:
        print(f"    [!] crt.sh 请求失败: {e}")
    except json.JSONDecodeError:
        print("    [!] crt.sh 返回数据解析失败，可能被限速")
    return subdomains


def fallback_collect_and_probe(domain):
    """crt.sh + DNS爆破 + Python HTTP探活"""
    all_subs = set()

    print("[*] crt.sh 证书透明度查询 ...")
    crt = _crtsh_collect(domain)
    if crt:
        print(f"    [+] crt.sh 发现 {len(crt)} 个")
        all_subs.update(crt)

    print(f"[*] DNS 爆破（字典 {len(BUILTIN_SUBDOMAINS)} 个）...")
    dns = _dns_bruteforce(domain)
    if dns:
        print(f"    [+] DNS 爆破发现 {len(dns)} 个")
        all_subs.update(dns)

    if not all_subs:
        return []

    subdomains = sorted(all_subs)
    print(f"[*] HTTP 探活（{len(subdomains)} 个，50 线程）...")
    alive = _python_httprobe(subdomains)
    print(f"    [+] 存活: {len(alive)} / {len(subdomains)}")
    return alive


# ==================== HTTP 探活 ====================

def _probe_one(subdomain, timeout=5):
    for scheme in ("https://", "http://"):
        url = f"{scheme}{subdomain}"
        try:
            resp = requests.head(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                                 timeout=timeout, verify=False, allow_redirects=True)
            if resp.status_code in (200, 301, 302, 307, 308, 401, 403):
                return url
        except requests.RequestException:
            continue
    return None


def _python_httprobe(subdomains, threads=50, timeout=5):
    alive = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_probe_one, sub, timeout): sub for sub in subdomains}
        for future in as_completed(futures):
            url = future.result()
            if url:
                alive.append(url)
    return sorted(alive)


# ==================== 保存 & 主入口 ====================

def save_results(alive_urls, project, domain):
    target_dir = os.path.join(BASE_DIR, project)
    os.makedirs(target_dir, exist_ok=True)

    output_file = os.path.join(target_dir, f"{project}_urls.txt")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"# HTTP 存活子域名 - {domain}\n")
        f.write(f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# 共 {len(alive_urls)} 条\n\n")
        for url in alive_urls:
            f.write(f"{url}\n")
    print(f"\n[√] 已保存 {len(alive_urls)} 条到: {output_file}")
    return output_file


def main():
    parser = argparse.ArgumentParser(description="子域名收集")
    parser.add_argument("--project", "--abbr", dest="project")
    parser.add_argument("--domain", help="主域名")
    parser.add_argument("--offline", action="store_true", help="离线模式: 跳过crt.sh和OneForAll API, 仅DNS爆破")
    args = parser.parse_args()

    project = args.project or input("项目缩写（如 glut）: ").strip()
    domain = args.domain or input("主域名（如 glut.edu.cn）: ").strip()

    if not project or not domain:
        print("[-] 项目和域名不能为空"); sys.exit(1)

    project = project.lower()
    domain = domain.lower()

    print("=" * 60)
    print(f"  子域名收集 - {project} ({domain})")
    print(f"  平台: {'Windows' if IS_WINDOWS else 'Linux'}")
    print("=" * 60)

    start = time.time()
    alive_urls = []

    if args.offline:
        print("[*] 离线模式: 仅DNS爆破")
        alive_urls = dns_bruteforce_and_probe(domain)
    elif IS_WINDOWS:
        # 优先 oneforall
        alive_urls = _oneforall_collect(domain)
        if alive_urls is None:
            # oneforall 失败，回退
            print("[!] oneforall 不可用，回退到 crt.sh + DNS 爆破")
            alive_urls = fallback_collect_and_probe(domain)
        elif alive_urls:
            # oneforall 收集到了，探活
            print(f"[*] HTTP 探活（{len(alive_urls)} 个，50 线程）...")
            before = len(alive_urls)
            alive_urls = _python_httprobe(alive_urls)
            print(f"    [+] 存活: {len(alive_urls)} / {before}")
    else:
        alive_urls = linux_collect_and_probe(domain)

    elapsed = time.time() - start

    if not alive_urls:
        print(f"\n[-] 0 个 HTTP 存活子域名，耗时 {elapsed:.1f}s")
        print("    提示: 检查网络 / DNS / 目标域名是否正确")
        sys.exit(1)

    print(f"\n[+] {len(alive_urls)} 个存活，耗时 {elapsed:.1f}s")
    save_results(alive_urls, project, domain)

    print("\n--- 预览（前 20 条）---")
    for url in alive_urls[:20]:
        print(f"    {url}")
    if len(alive_urls) > 20:
        print(f"    ... 还有 {len(alive_urls) - 20} 条")


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
