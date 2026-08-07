#!/usr/bin/env python3
"""
目标快速筛选器 - 批量评估补天目标价值
输出: 值得深入扫描的目标列表
"""
import requests
import urllib3
import re
import sys
import time

urllib3.disable_warnings()

# Boda CMS 特征（扫出来的全是假的）
BODA_PATTERN = r'urltype=tree\.TreeTempUrl|wbtreeid=|wbnewsid='
# 有价值的技术栈
GOOD_TECH = ['aspx', 'php', 'asp']


def quick_eval(url, timeout=10):
    """30秒评估一个目标的价值，返回评分 0-10"""
    score = 0
    info = {"url": url, "params": [], "server": "", "cms": "", "issues": []}

    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0'})
        html = r.text
        info["server"] = r.headers.get("Server", "?")
        info["len"] = len(r.content)

        # 太小 = 空壳/跳转页
        if len(r.content) < 1000:
            info["issues"].append("页面太小(可能空壳)")
            score -= 3
        elif len(r.content) > 10000:
            score += 1  # 有内容

        # 找参数
        params = re.findall(r"""(?:href|src|action)=["']([^"']*\?[a-zA-Z]+=[^"']*)""", html)
        info["params"] = params[:10]
        if params:
            score += 2
            # 非Boda CMS 加分
            non_boda = [p for p in params if not re.search(BODA_PATTERN, p)]
            if non_boda:
                score += 2
                info["non_boda_params"] = len(non_boda)
            else:
                info["cms"] = "博达CMS(无视)"
                score -= 5
        else:
            score -= 1

        # 技术栈
        url_lower = url.lower()
        for tech in GOOD_TECH:
            if f'.{tech}' in url_lower or f'.{tech}?' in r.url.lower():
                score += 1
                info["tech"] = tech.upper()

        # 表单
        forms = re.findall(r'<form[^>]*>', html)
        info["forms"] = len(forms)
        if forms:
            score += 1

        # WAF 检测（快速的）
        headers_str = str(r.headers).lower()
        if any(k in headers_str for k in ['aliyun', 'yundun', 'tencent', 'cloudflare', '360']):
            info["waf"] = True
            score -= 2

    except Exception as e:
        info["issues"].append(f"连接失败: {type(e).__name__}")
        score -= 5

    info["score"] = max(-10, min(10, score))
    return info


def batch_eval(targets, delay=2):
    """批量评估"""
    results = []
    for i, url in enumerate(targets):
        url = url.strip()
        if not url.startswith("http"):
            url = "https://" + url
        print(f"[{i+1}/{len(targets)}] {url[:80]}...", end=" ", flush=True)
        info = quick_eval(url)
        score = info["score"]
        star = "***" if score >= 5 else "**" if score >= 2 else "*" if score >= 0 else "-"
        print(f"score={score:>3} {star} params={len(info['params'])} cms={info.get('cms','?')}")
        if score >= 2:  # 有价值
            results.append(info)
        time.sleep(delay)

    results.sort(key=lambda x: -x["score"])
    return results


if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        print(f"[*] 评估 {len(targets)} 个目标\n")
        good = batch_eval(targets)

        print(f"\n{'='*60}")
        print(f"值得深入的目标 ({len(good)} 个):")
        print(f"{'='*60}")
        for g in good:
            print(f"  score={g['score']} {g['url'][:80]}")
            if g.get("non_boda_params"):
                print(f"    非博达参数: {g['non_boda_params']}个")
            print(f"    server={g['server']} len={g['len']} tech={g.get('tech','?')}")
        print()
    else:
        print("用法: python target_scouter.py targets.txt")
        print("targets.txt 一行一个URL")
