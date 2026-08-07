#!/usr/bin/env python3
"""
Nuclei 漏洞扫描封装 - 从工具箱调用 nuclei 引擎
支持 500+ YAML POC 模板的批量扫描
"""
import os
import subprocess
import sys
import json
import glob

# ==================== 路径配置 ====================
from config import TIANHU_GUI_SCAN
NUCLEI_DIR = os.path.join(TIANHU_GUI_SCAN, "nuclei")
NUCLEI_EXE = os.path.join(NUCLEI_DIR, "nuclei.exe")
NUCLEI_JAR = os.path.join(NUCLEI_DIR, "nuclei-7.4.8.jar")
POC_DIR = os.path.join(NUCLEI_DIR, "nuclei_pocs")


def _find_nuclei():
    """查找 nuclei 可执行文件"""
    if os.path.isfile(NUCLEI_EXE):
        return NUCLEI_EXE
    if os.path.isfile(NUCLEI_JAR):
        return f"java -jar {NUCLEI_JAR}"
    # 系统 nuclei
    try:
        result = subprocess.run(["which", "nuclei"], capture_output=True,
                               timeout=5, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def list_pocs(tag=None):
    """列出所有 POC 模板"""
    pocs = glob.glob(os.path.join(POC_DIR, "*.yaml"))
    if tag:
        pocs = [p for p in pocs if tag.lower() in os.path.basename(p).lower()]
    return sorted(pocs)


def scan_url(url, templates=None, tags=None, timeout=30):
    """
    对单个 URL 运行 nuclei 扫描。
    templates: 模板文件列表，None=自动选择
    tags: 过滤标签（如 "sqli", "xss", "rce"）
    """
    nuclei = _find_nuclei()
    if not nuclei:
        print("[!] nuclei 不可用")
        return None

    cmd = nuclei.split() if nuclei.startswith("java") else [nuclei]
    cmd.extend(["-u", url, "-silent", "-timeout", str(timeout)])

    if templates:
        for t in templates:
            cmd.extend(["-t", t])
    elif tags:
        cmd.extend(["-tags", tags])
        cmd.extend(["-t", POC_DIR])
    else:
        # 默认用 SQL 注入和通用漏洞模板
        defaults = [
            os.path.join(POC_DIR, "error-based-sql-injection.yaml"),
            os.path.join(POC_DIR, "header_sqli.yaml"),
        ]
        for t in defaults:
            if os.path.isfile(t):
                cmd.extend(["-t", t])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout if result.stdout else result.stderr
    except subprocess.TimeoutExpired:
        return "[!] 扫描超时"
    except Exception as e:
        return f"[!] 错误: {e}"


def scan_batch(urls, output_file=None, templates=None, tags=None):
    """批量扫描多个 URL"""
    nuclei = _find_nuclei()
    if not nuclei:
        print("[!] nuclei 不可用")
        return None

    # 写入临时文件
    tmpfile = "nuclei_targets_tmp.txt"
    with open(tmpfile, "w") as f:
        for u in urls:
            f.write(u + "\n")

    cmd = nuclei.split() if nuclei.startswith("java") else [nuclei]
    cmd.extend(["-l", tmpfile, "-silent"])

    if templates:
        for t in templates:
            cmd.extend(["-t", t])
    elif tags:
        cmd.extend(["-tags", tags, "-t", POC_DIR])
    else:
        cmd.extend(["-t", POC_DIR])

    if output_file:
        cmd.extend(["-o", output_file])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout or result.stderr
        # 清理临时文件
        os.remove(tmpfile)
        return output
    except subprocess.TimeoutExpired:
        return "[!] 批量扫描超时"
    except Exception as e:
        return f"[!] 错误: {e}"


# ==================== 常用模板分类 ====================
SQLI_TEMPLATES = [
    "error-based-sql-injection.yaml",
    "header-blind-sql-injection.yaml",
    "header_sqli.yaml",
    "joomla-sqli-hdwplayer.yaml",
]
XSS_TEMPLATES = [
    "dom-xss.yaml",
    "header_blind_xss.yaml",
]
RCE_TEMPLATES = [
    "hashicorp-consul-rce.yaml",
]
AUTH_TEMPLATES = [
    "host-header-auth-bypass.yaml",
    "common-forbidden-bypass.yaml",
    "huawei-dg8045-auth-bypass.yaml",
]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python nuclei_wrapper.py <URL> [--tags sqli,xss]")
        print("      python nuclei_wrapper.py --list      # 列出所有POC")
        print("      python nuclei_wrapper.py --batch <file> # 批量扫描")
        sys.exit(0)

    if sys.argv[1] == "--list":
        pocs = list_pocs()
        print(f"共 {len(pocs)} 个 POC 模板:")
        for p in pocs:
            print(f"  {os.path.basename(p)}")
    elif sys.argv[1] == "--batch":
        with open(sys.argv[2]) as f:
            urls = [l.strip() for l in f if l.strip()]
        print(f"[*] 扫描 {len(urls)} 个 URL...")
        print(scan_batch(urls) or "无结果")
    else:
        url = sys.argv[1]
        tags = None
        if "--tags" in sys.argv:
            idx = sys.argv.index("--tags")
            tags = sys.argv[idx + 1]
        print(f"[*] 扫描: {url}")
        print(scan_url(url, tags=tags) or "无结果")
