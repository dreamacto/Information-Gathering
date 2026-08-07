#!/usr/bin/env python3
# encoding: utf-8
"""
JavaScript / 前端源码分析模块
  功能: JS Source Map 解析、API endpoint 提取、硬编码密钥检测
  集成天狐: PackerFuzzer / Vue Scan / WebCrack
  用法: python js_analyzer.py --project glut
        python js_analyzer.py --url https://target.com
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings()

from config import BASE_DIR, JAVA_CMD, PYTHON_EXE
from pentest_utils import resolve_path, load_targets, safe_request, random_ua
import toolkit_integration as tk

TIMEOUT = 20

# ==================== 密钥/敏感信息正则 ====================
SENSITIVE_PATTERNS = {
    "API Key (通用)":   r"""['"]api[_-]?key['"]\s*[:=]\s*['"]([^'"]{8,})['"]""",
    "AWS Access Key":   r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":   r"""['"]aws[_-]?secret['"]\s*[:=]\s*['"]([^'"]{10,})['"]""",
    "Google API Key":   r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":     r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
    "JWT Token":        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
    "Private Key":      r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "密码硬编码":        r"""['"]passw(or)?d['"]\s*[:=]\s*['"]([^'"]{4,})['"]""",
    "Token硬编码":       r"""['"]token['"]\s*[:=]\s*['"]([^'"]{8,})['"]""",
    "Secret硬编码":      r"""['"]secret['"]\s*[:=]\s*['"]([^'"]{8,})['"]""",
    "数据库连接串":       r"""(?:mysql|postgres|mongodb|redis|jdbc)://[^'"\s]+""",
    "内网IP泄露":         r"""(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}""",
    "OAuth Client Secret": r"""['"]client[_-]?secret['"]\s*[:=]\s*['"]([^'"]{8,})['"]""",
}


def fetch_js_files(base_url):
    """从页面中提取所有 JS 文件 URL"""
    js_files = set()
    try:
        r = requests.get(base_url, timeout=TIMEOUT, verify=False,
                        headers={"User-Agent": random_ua()})
        html = r.text

        # <script src="...js">
        for m in re.finditer(r"""<script[^>]+src=["']([^"']+\.js[^"']*)""",
                             html, re.IGNORECASE):
            js_url = urljoin(base_url, m.group(1))
            js_files.add(js_url)

        # import ... from '...'
        for m in re.finditer(r"""import\s+.*?from\s+["']([^"']+)["']""", html):
            imp = m.group(1)
            if imp.endswith(".js") or "/" in imp:
                js_url = urljoin(base_url, imp)
                if not js_url.endswith(".js"):
                    js_url += ".js"
                js_files.add(js_url)

        # webpack chunks
        for m in re.finditer(r"""["']([^"']*(?:chunk|bundle|app|vendor)[^"']*\.js)["']""",
                             html):
            js_url = urljoin(base_url, m.group(1))
            js_files.add(js_url)

    except Exception as e:
        print(f"  [-] 获取JS文件失败: {e}")

    return list(js_files)


def fetch_js_content(js_url):
    """下载单个 JS 文件"""
    try:
        r = requests.get(js_url, timeout=TIMEOUT, verify=False,
                        headers={"User-Agent": random_ua()})
        if r.status_code == 200 and len(r.text) > 50:
            return r.text
    except Exception:
        pass
    return None


def scan_js_for_secrets(content, source_url=""):
    """扫描 JS 内容中的敏感信息"""
    findings = []
    for name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            # 去重
            unique = list(set(matches if isinstance(matches[0], str)
                            else [m[0] if isinstance(m, tuple) else m for m in matches]))
            for val in unique[:3]:  # 每种最多3个
                # 截断显示
                display = val[:60] + "..." if len(str(val)) > 60 else val
                findings.append({"type": name, "value": str(display),
                               "source": source_url})
    return findings


def find_source_maps(js_content, js_url):
    """查找 JS Source Map"""
    maps = []
    # //# sourceMappingURL=xxx.map
    m = re.search(r"//#\s*sourceMappingURL=(.+\.map)", js_content)
    if m:
        map_url = urljoin(js_url, m.group(1))
        maps.append(map_url)
    # /*# sourceMappingURL=xxx.map */
    m = re.search(r"/\*#\s*sourceMappingURL=(.+\.map)\s*\*/", js_content)
    if m:
        map_url = urljoin(js_url, m.group(1))
        maps.append(map_url)
    return maps


def extract_api_endpoints_from_js(js_content, base_url):
    """从 JS 中提取 API endpoint"""
    endpoints = set()

    # fetch/axios/ajax 调用
    for m in re.finditer(r"""(?:fetch|axios|ajax)\s*\(\s*["']([^"']+)["']""",
                         js_content):
        endpoints.add(m.group(1))

    # baseURL / apiUrl 等配置
    for m in re.finditer(r"""(?:baseURL|apiUrl|apiBase|API_URL|BASE_URL)\s*[:=]\s*["']([^"']+)["']""",
                         js_content, re.IGNORECASE):
        endpoints.add(m.group(1))

    # /api/xxx 路径模式
    for m in re.finditer(r"""["'](/api/v?\d?/[^"'\s]{3,})["']""", js_content):
        endpoints.add(m.group(1))

    return list(endpoints)


def analyze_js_target(url, project=None):
    """全面分析单个目标的 JS"""
    print(f"\n{'='*60}")
    print(f"  JS 前端分析 - {url}")
    print(f"{'='*60}")

    all_secrets = []
    all_endpoints = set()
    all_sourcemaps = []

    # 1. 提取 JS 文件
    js_files = fetch_js_files(url)
    print(f"\n[*] 发现 {len(js_files)} 个 JS 文件")

    # 限制分析数量
    for js_url in js_files[:20]:
        short = js_url.split("/")[-1][:60]
        print(f"  [*] 分析: {short}")

        content = fetch_js_content(js_url)
        if not content:
            continue

        # 2. 密钥扫描
        secrets = scan_js_for_secrets(content, js_url)
        if secrets:
            all_secrets.extend(secrets)
            for s in secrets:
                print(f"  [!] {s['type']}: {s['value']}")

        # 3. Source Map 发现
        maps = find_source_maps(content, js_url)
        if maps:
            all_sourcemaps.extend(maps)
            for m in maps:
                print(f"  [+] SourceMap: {m}")

        # 4. API Endpoint 提取
        endpoints = extract_api_endpoints_from_js(content, url)
        all_endpoints.update(endpoints)

    if all_endpoints:
        print(f"\n[+] 提取 {len(all_endpoints)} 个 API 端点:")
        for ep in sorted(all_endpoints)[:20]:
            print(f"    {ep}")

    if all_sourcemaps:
        print(f"\n[+] 发现 {len(all_sourcemaps)} 个 SourceMap（可还原源码）")

    if all_secrets:
        print(f"\n[!] 发现 {len(all_secrets)} 个敏感信息泄露!")
    else:
        print(f"\n[*] 未发现明显敏感信息")

    # 5. 调用天狐工具: PackerFuzzer
    print(f"\n[*] 调用 PackerFuzzer (Webpack扫描)...")
    tk.run_tool("packerfuzzer", url=url)

    # Vue Scan 是GUI工具，自动化跳过。手动使用: python toolkit_integration.py --tool vuescan --url <url>
    print(f"[*] Vue Scan 需手动操作: python toolkit_integration.py --tool vuescan --url {url}")

    # 保存结果
    if project:
        if all_secrets:
            secrets_path = resolve_path(project, "js_secrets.json")
            with open(secrets_path, "w", encoding="utf-8") as f:
                json.dump(all_secrets, f, ensure_ascii=False, indent=2)
            print(f"[√] 密钥已保存: {secrets_path}")

        if all_endpoints:
            eps_path = resolve_path(project, "js_api_endpoints.txt")
            with open(eps_path, "w", encoding="utf-8") as f:
                for ep in sorted(all_endpoints):
                    f.write(ep + "\n")
            print(f"[√] API端点已保存: {eps_path}")

    return {
        "secrets": all_secrets,
        "endpoints": list(all_endpoints),
        "sourcemaps": all_sourcemaps,
    }


def main():
    parser = argparse.ArgumentParser(description="JS/前端源码分析模块")
    parser.add_argument("--project", default=None, help="项目缩写")
    parser.add_argument("--url", default=None, help="单个URL")
    args = parser.parse_args()

    if args.url:
        analyze_js_target(args.url)
    elif args.project:
        urls = load_targets(args.project)
        # 优先测 login/admin 等页面（JS更多）
        priority = [u for u in urls if any(
            k in u.lower() for k in ["login", "admin", "portal", "main",
                                       "index", "home", "web", "app"])]
        candidates = (priority or urls)[:5]
        print(f"[+] JS 分析目标: {len(candidates)} 个")
        for url in candidates:
            analyze_js_target(url, args.project)
            time.sleep(2)
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 已取消")
    try:
        input("\n按 Enter 退出...")
    except (EOFError, KeyboardInterrupt):
        pass
