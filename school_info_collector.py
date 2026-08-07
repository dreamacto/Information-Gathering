
#!/usr/bin/env python3
# encoding: utf-8
"""
高校网站信息点提取脚本（Windows + Linux 双平台兼容版）
指纹识别：
  - Linux: 优先使用 whatweb
  - Windows: 自动退化为纯 Python 指纹提取（Header / Meta / Cookie）

用法:
  python school_info_collector.py --abbr glut
  python school_info_collector.py --abbr guat
  python school_info_collector.py                    # 不带参数时读取根目录 urls.txt（兼容旧用法）
"""

import argparse
import os
import re
import time
import random
import socket
import subprocess
import platform
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pentest_utils import resolve_path, build_headers, safe_request, BASE_DIR, _extract_root_domain

# ===== 平台检测 =====
IS_WINDOWS = platform.system() == "Windows"

# ===== 配置 =====
THREADS        = 10
METHOD_THREADS = 5
PORT_THREADS   = 10
TIMEOUT        = 20
ALLOWED_STATUS = (200, 301, 302, 307, 308)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]

SKIP_PREFIXES = {
    "www", "mail", "smtp", "pop", "ftp", "dns", "ns1", "ns2",
    "jwc", "lib", "news", "yjs", "cs", "ee", "math", "phy", "chem",
    "bio", "law", "med", "art", "pe", "iec", "oia", "xsc", "zzb", "tzb", "audit",
}

STATIC_EXTS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".mp4", ".avi",
    ".webp", ".bmp", ".tif", ".tiff",
}

HIGH_RISK_PARAMS = {"id", "page", "wbtreeid", "urltype", "classid", "newsid"}
MED_RISK_PARAMS  = {"action", "do", "cmd", "type", "mod", "op", "view", "siteid", "treeid"}
LOW_RISK_PARAMS  = {"search", "keyword", "q", "s", "key"}

UPLOAD_KEYWORDS = {"upload", "file", "上传", "附件", "attach", "down", "import", "export"}
DANGEROUS_METHODS = {"PUT", "DELETE", "MOVE", "PROPFIND", "PATCH"}
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    1433, 1521, 3306, 3389, 5432, 6379, 7001, 8080, 8443,
]


# ---------- 纯 Python 指纹识别（Windows 兜底方案） ----------
def python_fingerprint(resp):
    tech_list = []
    parts = []

    server = resp.headers.get("Server", "")
    powered = resp.headers.get("X-Powered-By", "")
    if server:
        parts.append(f"HTTPServer[{server}]")
        tech_list.append(server)
    if powered:
        parts.append(f"PoweredBy[{powered}]")
        tech_list.append(powered)

    set_cookie = resp.headers.get("Set-Cookie", "")
    if "JSESSIONID" in set_cookie:
        parts.append("Java/JSP")
        tech_list.append("Java/JSP")
    elif "PHPSESSID" in set_cookie:
        parts.append("PHP")
        tech_list.append("PHP")
    elif "ASP.NET_SessionId" in set_cookie:
        parts.append("ASP.NET")
        tech_list.append("ASP.NET")

    resp.encoding = resp.apparent_encoding
    html = resp.text
    match = re.search(
        r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
        html, re.IGNORECASE,
    )
    if match:
        cms = match.group(1)
        parts.append(f"CMS[{cms}]")
        tech_list.append(cms)

    if "/wp-content/" in html:
        parts.append("WordPress")
        tech_list.append("WordPress")
    if "vue.js" in html.lower() or "vue.min.js" in html.lower():
        parts.append("Vue.js")
        tech_list.append("Vue.js")
    if "react" in html.lower() and ("react.js" in html.lower() or "react-dom" in html.lower()):
        parts.append("React")
        tech_list.append("React")

    fingerprint = ", ".join(parts) if parts else "未识别"
    return fingerprint, tech_list


# ---------- 天狐 EHole 路径 ----------
from config import tool_path
EHOLE_EXE = tool_path("ehole") or ""
EHOLE_DIR = os.path.dirname(EHOLE_EXE) if EHOLE_EXE else ""


def _find_ehole():
    if os.path.isfile(EHOLE_EXE):
        return EHOLE_EXE, EHOLE_DIR
    return None, None


def _ehole_batch_finger(urls):
    """用 EHole 批量指纹识别，返回 {url: (fingerprint, tech_list)}"""
    import tempfile

    ehole_exe, ehole_dir = _find_ehole()
    if not ehole_exe:
        return {}

    # 写入临时 URL 文件
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False,
                                      encoding="utf-8")
    for u in urls:
        tmp.write(u + "\n")
    tmp.close()

    # 输出 json
    out_json = tmp.name.replace(".txt", ".json")
    try:
        result = subprocess.run(
            [ehole_exe, "finger", "-l", tmp.name, "-o", out_json, "-t", "50"],
            capture_output=True, text=True, timeout=120,
            cwd=ehole_dir, encoding="utf-8", errors="replace",
        )
        # EHole 会在 stdout 打印结果，同时写 JSON
        if os.path.isfile(out_json):
            import json
            with open(out_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            results = {}
            for item in data if isinstance(data, list) else [data]:
                url = item.get("url", "")
                fps = item.get("fingerprint", item.get("cms", ""))
                if isinstance(fps, list):
                    fps = ", ".join(fps)
                tech_list = [fps] if fps else []
                results[url] = (f"EHole[{fps}]" if fps else "未识别", tech_list)
            # 补充未识别的 URL
            for u in urls:
                if u not in results:
                    results[u] = ("未识别", [])
            return results
    except Exception as e:
        print(f"    [!] EHole 出错: {e}")
    finally:
        for f in [tmp.name, out_json]:
            try:
                os.unlink(f)
            except Exception:
                pass
    return {}


def detect_fingerprint(url):
    """单 URL 指纹识别（兼容旧接口，批量时优先用 _ehole_batch_finger）"""
    if not IS_WINDOWS:
        try:
            result = subprocess.run(
                ["whatweb", "--colour=never", "-q", url],
                capture_output=True, text=True, timeout=8,
            )
            raw = result.stdout.strip()
            if raw:
                parts = raw.split(" ", 1)
                fp = parts[1] if len(parts) > 1 else parts[0]
                tech_list = re.findall(r"\[([^]]+)\]", fp)
                if not tech_list:
                    tech_list = [fp]
                return fp, tech_list
        except Exception:
            pass

    try:
        resp = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                            timeout=5, verify=False)
        return python_fingerprint(resp)
    except requests.RequestException:
        return "未识别", []


def generate_cve_links(tech_list):
    if not tech_list:
        return ""
    links = []
    for tech in tech_list:
        clean = tech.replace("/", " ").strip()
        url = f"https://nvd.nist.gov/vuln/search/results?query={quote(clean)}"
        links.append(
            f'<a href="{url}" target="_blank" style="font-size:0.8em; margin-left:5px;">[{clean} CVE]</a>'
        )
    return " ".join(links)


# ---------- HTTP 方法检测 ----------
def check_methods(url):
    dangerous = []
    try:
        resp = requests.options(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                                timeout=5, verify=False)
        allow = resp.headers.get("Allow", "")
        for method in allow.split(","):
            m = method.strip().upper()
            if m in DANGEROUS_METHODS:
                dangerous.append(m)
    except requests.RequestException:
        pass
    return dangerous


# ---------- 端口扫描 ----------
def check_port(host, port):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        if result == 0:
            return port
    except (socket.error, OSError):
        pass
    finally:
        if sock:
            sock.close()
    return None


def scan_ports(host):
    open_ports = []
    with ThreadPoolExecutor(max_workers=PORT_THREADS) as executor:
        future_map = {executor.submit(check_port, host, port): port for port in COMMON_PORTS}
        for future in as_completed(future_map):
            port = future.result()
            if port:
                open_ports.append(port)
    return sorted(open_ports)


# ---------- 工具函数 ----------
def is_static(url: str) -> bool:
    clean = url.split("?")[0].split("#")[0].lower()
    if clean.startswith(("mailto:", "javascript:", "tel:")):
        return True
    for ext in STATIC_EXTS:
        if clean.endswith(ext):
            return True
    return False


def risk_level(url: str) -> str:
    query = url.split("?", 1)[-1] if "?" in url else ""
    params = set(re.findall(r"([a-zA-Z0-9_]+)=", query))
    if params & HIGH_RISK_PARAMS:
        return "high"
    if params & MED_RISK_PARAMS:
        return "medium"
    if params & LOW_RISK_PARAMS:
        return "low"
    clean = url.split("?")[0].lower()
    if any(clean.endswith(e) for e in (".jsp", ".php", ".asp", ".aspx", ".do", ".action")):
        return "medium"
    return "low"


def is_potential_dynamic(url: str) -> bool:
    if is_static(url):
        return False
    clean = url.split("?")[0].lower()
    if any(clean.endswith(e) for e in (".jsp", ".php", ".asp", ".aspx", ".do", ".action")):
        return True
    if "/upload/" in clean:
        return True
    query = url.split("?", 1)[-1] if "?" in url else ""
    if query and (HIGH_RISK_PARAMS | MED_RISK_PARAMS | LOW_RISK_PARAMS) & set(
        re.findall(r"([a-zA-Z0-9_]+)=", query)
    ):
        return True
    if re.search(r"/(login|signin|logon|auth)", clean, re.IGNORECASE):
        return True
    return False


def check_link_alive(url: str) -> bool:
    try:
        resp = requests.head(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                             timeout=TIMEOUT, verify=False, allow_redirects=True)
        if resp.status_code in ALLOWED_STATUS:
            return True
        resp2 = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                             timeout=TIMEOUT, verify=False, allow_redirects=True)
        return resp2.status_code in ALLOWED_STATUS
    except requests.RequestException:
        return False


def filter_alive_links(links: set, max_workers=10) -> list:
    if not links:
        return []
    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(check_link_alive, url): url for url in links}
        for future in as_completed(future_map):
            url = future_map[future]
            try:
                if future.result():
                    alive.append(url)
            except Exception:
                pass
    return sorted(set(alive))


def get_school_short(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    for i in range(len(parts) - 1):
        if parts[i + 1] == "edu" and i + 2 < len(parts) and parts[i + 2] == "cn":
            school = parts[i]
            if school.lower() in SKIP_PREFIXES and i > 0:
                school = parts[i - 1]
            return school[:4].lower()
    for part in parts:
        if part.lower() not in SKIP_PREFIXES and part not in ("com", "net", "org", "gov", "edu", "cn"):
            return part[:4].lower()
    return parts[0][:4].lower()


VULN_HINTS = {
    "dynamic": "动态参数可能触发：SQL注入、XSS、越权、路径遍历、文件包含",
    "upload":  "上传入口/文件功能可能触发：任意文件上传、任意文件读取、目录浏览",
    "login":   "登录入口可能触发：弱口令、SQL注入、暴力破解、未授权访问、用户枚举",
}


# ---------- Web HTTP 快速探活 ----------
def _check_web_port(url):
    """用 HTTP HEAD 请求检查 Web 服务是否真实可达"""
    try:
        resp = requests.head(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                             timeout=5, verify=False, allow_redirects=True)
        return (url, resp.status_code in ALLOWED_STATUS)
    except requests.RequestException:
        return (url, False)


def prefilter_alive_hosts(urls, max_workers=20):
    """HTTP HEAD 预筛选：只保留 Web 服务器真实响应的 URL，保持原始顺序"""
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_check_web_port, url): url for url in urls}
        for future in as_completed(future_map):
            url, ok = future.result()
            results[url] = ok
    alive = [u for u in urls if results.get(u, False)]
    dead = len(urls) - len(alive)
    return alive, dead


# ---------- 页面分析 ----------
def fetch_and_analyze(url, cached_fingerprint=None):
    result = {
        "url": url,
        "short": get_school_short(url),
        "status": "跳过",
        "fingerprint": "未识别",
        "tech_list": [],
        "cve_links_html": "",
        "dangerous_methods": [],
        "open_ports": [],
        "dynamic_links": [],
        "upload_links": [],
        "login_forms": [],
    }

    print(f"\n{'='*60}\n[*] 正在分析: {url}\n[+] 学校简称: {result['short']}")

    # 先发 HTTP 请求，成功了再做指纹识别
    try:
        resp = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                            timeout=TIMEOUT, verify=False)
        result["status"] = str(resp.status_code)
        if resp.status_code not in ALLOWED_STATUS:
            print(f"[-] 跳过（状态码 {resp.status_code}）")
            return result
        resp.encoding = resp.apparent_encoding
        html = resp.text
    except requests.RequestException as e:
        print(f"[-] 请求失败: {e}")
        return result

    # 指纹：优先用缓存的 EHole 批量结果
    if cached_fingerprint and cached_fingerprint[0] != "未识别":
        result["fingerprint"] = cached_fingerprint[0]
        result["tech_list"] = cached_fingerprint[1]
        print(f"[+] 指纹(EHole): {result['fingerprint']}")
    else:
        print("[*] 识别指纹...")
        fp, tech_list = detect_fingerprint(url)
        result["fingerprint"] = fp
        result["tech_list"] = tech_list
        print(f"[+] 指纹: {fp}")
    result["cve_links_html"] = generate_cve_links(result["tech_list"])

    result["dangerous_methods"] = check_methods(url)
    if result["dangerous_methods"]:
        print(f"[!] 危险方法: {', '.join(result['dangerous_methods'])}")

    hostname = urlparse(url).hostname
    if hostname:
        result["open_ports"] = scan_ports(hostname)
        if result["open_ports"]:
            print(f"[!] 开放端口: {result['open_ports']}")

    # 提取当前目标域名，用于过滤外部链接
    target_root = _extract_root_domain(urlparse(url).hostname or "")

    raw_dynamic = set()
    external_dynamic = 0
    for m in re.finditer(r'href=["\']([^"\']*\?[^"\']*)["\']', html, re.IGNORECASE):
        full = urljoin(url, m.group(1))
        if is_potential_dynamic(full):
            if _is_same_domain(full, target_root):
                raw_dynamic.add(full)
            else:
                external_dynamic += 1
    for u in filter_alive_links(raw_dynamic, 15):
        result["dynamic_links"].append((u, risk_level(u)))
    if external_dynamic:
        print(f"    [过滤] {external_dynamic} 个外部动态链接")

    raw_upload = set()
    external_upload = 0
    kw = "|".join(UPLOAD_KEYWORDS)
    for m in re.finditer(rf'href=["\']([^"\']*(?:{kw})[^"\']*)["\']', html, re.IGNORECASE):
        full = urljoin(url, m.group(1))
        if is_potential_dynamic(full):
            if _is_same_domain(full, target_root):
                raw_upload.add(full)
            else:
                external_upload += 1
    for u in filter_alive_links(raw_upload, 10):
        result["upload_links"].append((u, "file_ref" if is_static(u) else "upload_entry"))

    raw_login = set()
    external_login = 0
    form_pat = r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>(.*?)</form>'
    for m in re.finditer(form_pat, html, re.DOTALL | re.IGNORECASE):
        if 'type="password"' in m.group(2) or "type='password'" in m.group(2):
            login_full = urljoin(url, m.group(1))
            if _is_same_domain(login_full, target_root):
                raw_login.add(login_full)
            else:
                external_login += 1
    for login_url in filter_alive_links(raw_login, 5):
        info = {"action": login_url, "captcha": False, "hidden_fields": [], "login_type": "传统表单"}
        try:
            lr = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                              timeout=TIMEOUT, verify=False)
            lh = lr.text
            if re.search(r"captcha|验证码|vercode", lh, re.IGNORECASE):
                info["captcha"] = True
            hf = re.findall(
                r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']',
                lh, re.IGNORECASE,
            )
            if hf:
                info["hidden_fields"] = hf
            if "cas" in login_url.lower() or "sso" in login_url.lower() or "统一认证" in lh:
                info["login_type"] = "SSO单点登录"
            elif re.search(r"qrcode|二维码|扫码", lh, re.IGNORECASE):
                info["login_type"] = "第三方扫码登录"
        except requests.RequestException:
            pass
        result["login_forms"].append(info)

    print(f"[+] 动态:{len(result['dynamic_links'])} 上传:{len(result['upload_links'])} 登录:{len(result['login_forms'])}")
    return result


# ---------- HTML 报告 ----------
def generate_html(results, project=None):
    def status_order(r):
        return int(r["status"]) if r["status"].isdigit() else 999

    results_sorted = sorted(results, key=status_order)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    success_count = sum(1 for r in results if r["status"] not in ("跳过", "失败"))

    html = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>高校网站信息点报告</title>
<style>
  body {{ font-family: 'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; margin:20px; background:#f5f5f5; }}
  h1 {{ color:#333; }}
  .summary {{ background:#fff; padding:15px; border-radius:8px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.1); }}
  .target {{ background:#fff; padding:15px; margin:20px 0; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.1); }}
  .target h2 {{ margin-top:0; font-size:1.2em; color:#005a9e; }}
  .info {{ font-size:0.9em; color:#666; margin-bottom:10px; }}
  .section {{ margin:10px 0; }}
  .section-title {{ font-weight:bold; color:#444; margin-bottom:5px; }}
  ul {{ list-style:none; padding-left:20px; }}
  li {{ word-break:break-all; margin-bottom:4px; font-size:0.9em; }}
  a {{ text-decoration:none; }} a:hover {{ text-decoration:underline; }}
  .high a {{ color:#d32f2f; font-weight:bold; }}
  .medium a {{ color:#f57c00; }}
  .low a {{ color:#388e3c; }}
  .vuln-hint {{ font-size:0.8em; color:#888; margin-left:10px; }}
  .upload-entry::before {{ content:"上传入口 "; }}
  .file-ref::before {{ content:"文件引用 "; }}
  .captcha-warn {{ color:#d32f2f; font-size:0.8em; font-weight:bold; }}
  .fingerprint {{ background:#e8f5e9; padding:4px 8px; border-radius:4px; font-size:0.85em; }}
  .danger {{ color:#d32f2f; font-weight:bold; }}
  .port-open {{ background:#ffe0b2; padding:2px 6px; border-radius:3px; margin:0 2px; font-size:0.85em; }}
  hr {{ border:none; border-top:1px solid #eee; margin:15px 0; }}
  .footer {{ text-align:center; font-size:0.8em; color:#999; margin-top:30px; }}
</style></head><body>
<h1>高校网站信息点提取报告</h1>
<div class="summary">
  生成时间: {now}<br>目标总数: {len(results)}<br>成功分析: {success_count}
</div>
"""

    for r in results_sorted:
        if r["status"] in ("跳过", "失败"):
            continue
        html += (
            f'<div class="target"><h2>{r["short"]} - {r["url"]} (状态码: {r["status"]})</h2>'
        )
        html += (
            f'<div class="info">指纹: <span class="fingerprint">{r["fingerprint"]}</span> '
            f'{r["cve_links_html"]}</div>'
        )

        if r["dangerous_methods"]:
            html += (
                '<div class="info"><span class="danger">'
                f'危险 HTTP 方法: {", ".join(r["dangerous_methods"])}</span></div>'
            )

        if r["open_ports"]:
            ports_str = "".join(
                f'<span class="port-open">{p}</span>' for p in r["open_ports"]
            )
            html += f'<div class="info">开放端口: {ports_str}</div>'

        # 动态链接
        html += (
            f'<div class="section"><div class="section-title">'
            f'{VULN_HINTS["dynamic"]}</div><ul>'
        )
        if r["dynamic_links"]:
            for u, level in r["dynamic_links"]:
                html += (
                    f'<li class="{level}"><a href="{u}" target="_blank">{u}</a></li>'
                )
        else:
            html += "<li>（无）</li>"
        html += "</ul></div>"

        # upload
        html += (
            f'<div class="section"><div class="section-title">'
            f'{VULN_HINTS["upload"]}</div><ul>'
        )
        if r["upload_links"]:
            for u, etype in r["upload_links"]:
                cls = "upload-entry" if etype == "upload_entry" else "file-ref"
                html += (
                    f'<li class="{cls}"><a href="{u}" target="_blank">{u}</a></li>'
                )
        else:
            html += "<li>（无）</li>"
        html += "</ul></div>"

        # 登录
        html += (
            f'<div class="section"><div class="section-title">'
            f'{VULN_HINTS["login"]}</div><ul>'
        )
        if r["login_forms"]:
            for info in r["login_forms"]:
                html += (
                    f'<li><a href="{info["action"]}" target="_blank">{info["action"]}</a>'
                    f' &nbsp; <span class="vuln-hint">[{info["login_type"]}]</span>'
                )
                if info["captcha"]:
                    html += ' &nbsp; <span class="captcha-warn">[有验证码]</span>'
                if info["hidden_fields"]:
                    html += (
                        ' &nbsp; <span class="vuln-hint">'
                        f'隐藏字段: {", ".join(info["hidden_fields"])}</span>'
                    )
                html += "</li>"
        else:
            html += "<li>（无）</li>"
        html += "</ul></div></div>"

    html += '<div class="footer">自动生成 - 仅供授权演练使用</div></body></html>'

    output_path = resolve_path(project, "report.html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n[√] HTML 报告已保存到 {output_path}")


# ---------- 重点扫描目录 ----------
def generate_priority_targets(results, project=None):
    """
    多维度评分筛选重点目标：
      Tier 1: 认证/教务/门户/邮箱/财务/OA 等核心系统（域名关键词 OR 指纹匹配）
      Tier 2: 有登录入口 OR 动态参数多 OR 识别出CMS/技术栈 OR 有非标端口
      Tier 3: 可访问(200)但无特殊特征 OR 403 OR 有上传入口
      未匹配的 200 站点至少进 Tier 3，确保不漏
    """
    tier1, tier2, tier3 = [], [], []

    # 核心系统关键词
    t1_keywords = [
        "idp", "cas", "sso", "auth", "login", "passport", "oauth", "uis",
        "jwc", "jw.", "jwxt", "xgxt", "yjs", "yjsy", "yzw", "zsb", "gk",
        "eip", "portal", "my", "mail", "webmail", "email",
        "cwc", "caiwu", "cw", "jcc", "oa", "cms",
    ]
    # 重要系统关键词
    t2_keywords = [
        "lib", "library", "vpn", "ftp", "admin", "manage", "api",
        "bi", "data", "cloud", "lab", "ai", "aiagent", "smart",
        "job", "zhaopin", "career", "alumni", "graduate",
        "xsc", "xg", "zzb", "tzb", "gzc", "rsc", "hqc", "wzb",
        "dxs", "tw", "xgc", "xsgzb", "gh", "dw", "audit",
    ]

    for r in results:
        url = r["url"]
        host = urlparse(url).hostname or ""
        tech = r.get("tech_list", [])
        fingerprint = r.get("fingerprint", "未识别")
        login_count = len(r.get("login_forms", []))
        dynamic_count = len(r.get("dynamic_links", []))
        upload_count = len(r.get("upload_links", []))
        status = r.get("status", "0")
        ports = r.get("open_ports", [])
        dangerous = r.get("dangerous_methods", [])

        score = 0

        # 域名关键词评分
        host_lower = host.lower()
        for kw in t1_keywords:
            if kw in host_lower:
                score += 10
                break
        for kw in t2_keywords:
            if kw in host_lower:
                score += 5
                break

        # 指纹/技术栈评分
        if fingerprint != "未识别" and tech:
            score += 3

        # 登录表单评分
        if login_count > 0:
            score += 4
        # 动态参数评分
        if dynamic_count > 10:
            score += 3
        elif dynamic_count > 5:
            score += 2
        # 上传入口
        if upload_count > 0:
            score += 2
        # 危险 HTTP 方法
        if dangerous:
            score += 3
        # 非标端口
        if any(p not in (80, 443) for p in ports):
            score += 2
        # 403 可能有隐藏内容
        if status == "403":
            score += 1

        # 分级
        if score >= 10:
            tier1.append(url)
        elif score >= 4:
            tier2.append(url)
        elif status in ("200", "301", "302", "401", "403"):
            tier3.append(url)

    output_path = resolve_path(project, "priority_targets.txt")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("第一梯队（必扫，极高价值）- 核心业务系统\n")
        for u in tier1:
            f.write(u + "\n")
        f.write("\n第二梯队（重点扫描）- 有认证/登录/动态参数/技术栈\n")
        for u in tier2:
            f.write(u + "\n")
        f.write("\n第三梯队（选择性扫描）- 可访问但特征较少\n")
        for u in tier3:
            f.write(u + "\n")
    print(f"[√] 重点扫描目录已保存到 {output_path}")
    print(f"    Tier1={len(tier1)} Tier2={len(tier2)} Tier3={len(tier3)}")


# ---------- 保存动态URL（供SQL注入等漏洞扫描用）----------
def _target_domain(results):
    """从结果中提取目标主域名（取出现最多的根域名）"""
    from collections import Counter
    roots = Counter()
    for r in results:
        host = urlparse(r["url"]).hostname
        if host:
            roots[_extract_root_domain(host)] += 1
    return roots.most_common(1)[0][0] if roots else None


def _is_same_domain(url, domain):
    """判断 url 是否属于目标域名（用根域名匹配）"""
    host = urlparse(url).hostname
    if not host or not domain:
        return False
    return _extract_root_domain(host) == _extract_root_domain(domain)


def save_dynamic_urls(results, project=None):
    """从分析结果中提取所有带GET参数的动态链接，保存供漏洞扫描器使用"""
    domain = _target_domain(results)
    all_dynamic = set()
    all_login = set()
    external = 0
    for r in results:
        for url, level in r.get("dynamic_links", []):
            if "?" in url:
                if not domain or _is_same_domain(url, domain):
                    all_dynamic.add(url)
                else:
                    external += 1
        for info in r.get("login_forms", []):
            action = info.get("action", "")
            if action and action.startswith("http"):
                if not domain or _is_same_domain(action, domain):
                    all_login.add(action)

    output_path = resolve_path(project, "dynamic_urls.txt")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# 动态URL（带GET参数）— 供SQL注入/目录遍历等漏洞扫描使用\n")
        f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# 共 {len(all_dynamic)} 个动态链接 + {len(all_login)} 个登录入口")
        if external:
            f.write(f"（已过滤 {external} 个外部链接）")
        f.write(f"\n\n")
        for url in sorted(all_dynamic):
            f.write(url + "\n")
        if all_login:
            f.write("\n# --- 登录入口（供POST注入测试）---\n")
            for url in sorted(all_login):
                f.write(url + "\n")
    if all_dynamic or all_login:
        print(f"[√] 动态URL已保存到 {output_path} ({len(all_dynamic)} 动态 + {len(all_login)} 登录，过滤 {external} 外部链接)")


# ---------- 加载 urls ----------
def load_urls(project=None):
    """加载目标 URL 列表"""
    targets_file = resolve_path(project, "urls.txt")

    if not os.path.isfile(targets_file):
        print(f"[-] 找不到 {targets_file}")
        if project:
            print(f"    提示: 请先运行 'python subdomain_collector.py --abbr {project} --domain <域名>'")
        else:
            print("    提示: 请使用 --project 指定学校缩写，或把 urls.txt 放在脚本同目录下")
        sys.exit(1)

    with open(targets_file, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not urls:
        print(f"[-] {targets_file} 中无有效目标")
        sys.exit(1)

    return urls


# ---------- 主函数 ----------
def main():
    parser = argparse.ArgumentParser(description="高校网站信息点提取（Windows + Linux 兼容版）")
    parser.add_argument("--project", "--abbr", default=None, dest="project",
                        help="项目缩写，如 glut、guat，自动匹配 {project}/{project}_urls.txt")
    args = parser.parse_args()

    project = args.project
    # 交互式输入（直接点运行按钮时用）
    if not project:
        print("输入项目缩写则自动匹配 {缩写}/{缩写}_urls.txt，不输入则读取根目录 urls.txt")
        project = input("请输入项目缩写（留空跳过）: ").strip()
        project = project.lower() if project else None

    print("=" * 60)
    title = f"  高校网站信息点提取 - [{project}]" if project else "  高校网站信息点提取"
    print(title)
    print(f"  平台: {'Windows' if IS_WINDOWS else 'Linux'}")
    if project:
        print(f"  目标目录: {project}/")
        print(f"  URL 来源: {project}/{project}_urls.txt")
    print("=" * 60)

    urls = load_urls(project)
    print(f"[+] 共加载 {len(urls)} 个目标URL")

    # HTTP HEAD 预筛选：只保留 Web 服务器真实可响应的
    print(f"[*] 正在 HTTP 探活（{len(urls)} 个目标，{min(len(urls), 20)} 线程并发）...")
    urls, dead = prefilter_alive_hosts(urls)
    print(f"[+] HTTP 存活: {len(urls)} 个 | 无响应/超时: {dead} 个（已跳过）")
    if not urls:
        print("[-] 没有可访问的目标，退出")
        return

    # Windows 下先用 EHole 批量指纹识别
    fp_cache = {}
    if IS_WINDOWS:
        print(f"[*] EHole 批量指纹识别（{len(urls)} 个目标）...")
        fp_cache = _ehole_batch_finger(urls)
        identified = sum(1 for v in fp_cache.values() if v[0] != "未识别")
        print(f"[+] EHole 识别: {identified}/{len(urls)}")

    results = []
    try:
        for i, url in enumerate(urls, 1):
            print(f"\n--- [{i}/{len(urls)}] ---")
            r = fetch_and_analyze(url, cached_fingerprint=fp_cache.get(url))
            results.append(r)
            if i < len(urls):
                delay = random.uniform(1, 2)
                print(f"    ... 等待 {delay:.1f} 秒")
                time.sleep(delay)

        generate_html(results, project)
        generate_priority_targets(results, project)
        save_dynamic_urls(results, project)
        print("\n[√] 全部完成！")
    except KeyboardInterrupt:
        print("\n\n[!] 用户中断，正在保存已完成的结果...")
        if results:
            generate_html(results, project)
            generate_priority_targets(results, project)
            save_dynamic_urls(results, project)
        print("[√] 已保存")
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 已取消")
    except Exception as e:
        print(f"\n[!] 错误: {e}")
    input("\n按 Enter 退出...")
