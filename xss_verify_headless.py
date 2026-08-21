# -*- coding: utf-8 -*-
"""W12 · XSS 执行确认 xss_verify_headless.py

把"反射候选"推进到"可执行/不可执行"：
  - dalfox 优先（tools/managed/dalfox/dalfox.exe 存在时）
  - playwright 兜底（.venv 安装 playwright + chromium；首次运行检测并提示，不自动下载）

输入 --run-dir：读 xss_reflection_checks.jsonl / xss_candidates.jsonl。
输出 xss_verified.jsonl：{candidate, verdict: executable|not_executable|context_safe, engine, evidence}

安全：只验证 GET 反射候选；marker 唯一化；每请求 ≥3s；403 连续即停。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DALFOX = ROOT / "tools" / "managed" / "dalfox" / "dalfox.exe"
SAFE_CONTEXT_MARKERS = ["<title>", "<textarea"]


def now_iso():
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def make_marker() -> str:
    return "xvw" + hashlib.sha1(str(time.time_ns()).encode()).hexdigest()[:9]


def load_candidates(run_dir: Path) -> list[dict]:
    cands = []
    for fname in ("xss_reflection_checks.jsonl", "xss_candidates.jsonl"):
        p = run_dir / fname
        if not p.is_file():
            continue
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                e = json.loads(ln)
            except json.JSONDecodeError:
                continue
            url = e.get("url") or e.get("final_url")
            if not url or not str(url).startswith(("http://", "https://")):
                continue
            cands.append({
                "url": str(url),
                "param": e.get("param") or e.get("parameter") or "",
                "reflection": e.get("reflection") or e.get("evidence") or "",
            })
    return cands


def mutate_with_marker(url: str, param: str, marker: str) -> str:
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    if param:
        q[param] = [marker]
    else:
        # 无参数名：把 marker 加到所有值后面（保守）
        for k in q:
            q[k] = [v + marker for v in q[k]]
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urllib.parse.urlencode(q, doseq=True), parts.fragment))


def fetch_page(url: str) -> tuple[int, str]:
    try:
        import requests
        r = requests.get(url, timeout=15, allow_redirects=True)
        return r.status_code, r.text or ""
    except Exception as e:
        return 0, str(e)


def verdict_from_dom(marker: str, html: str) -> str:
    """marker 落在哪，决定 context：script 内=可执行，标签文本/属性=可能，title/textarea=安全。"""
    if marker not in html:
        return "not_reflected"
    idx = html.find(marker)
    window = html[max(0, idx - 200): idx + 200]
    low = window.lower()
    # 是否落在危险上下文（script 标签、事件属性、href/src 等）
    if re_search(low, r"<script[^>]*>[^<]*$") or "<script" in low:
        return "executable"
    if re_search(low, r"on[a-z]+\s*=\s*[\"']?[^\"']*$"):
        return "executable"
    if any(m in low for m in SAFE_CONTEXT_MARKERS):
        return "context_safe"
    if "href=" in low or "src=" in low:
        return "executable"  # 属性上下文（javascript: 前缀另议，交由人工）
    return "not_executable"


def re_search(text, pattern):
    import re
    return re.search(pattern, text) is not None


def run_dalfox(cand: dict, marker: str) -> dict | None:
    if not DALFOX.is_file():
        return None
    url = mutate_with_marker(cand["url"], cand["param"], marker)
    try:
        r = subprocess.run(
            [str(DALFOX), url, "--silence", "--no-color", "--skip-bav", "--delay", "3000"],
            capture_output=True, text=True, timeout=90, encoding="utf-8", errors="replace")
        found = "poc" in (r.stdout or "").lower() or marker in (r.stdout or "")
        verdict = "executable" if found else "not_executable"
        return {"verdict": verdict, "engine": "dalfox", "evidence": (r.stdout or r.stderr)[:400]}
    except Exception as e:
        return {"verdict": "inconclusive", "engine": "dalfox", "evidence": f"dalfox 失败: {str(e)[:200]}"}


def run_playwright(cand: dict, marker: str) -> dict | None:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError:
        return None
    from playwright.sync_api import sync_playwright
    url = mutate_with_marker(cand["url"], cand["param"], marker)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=20000, wait_until="domcontentloaded")
            html = page.content()
            browser.close()
        verdict = verdict_from_dom(marker, html)
        return {"verdict": verdict, "engine": "playwright",
                "evidence": f"marker 出现在 DOM，判定 {verdict}"}
    except Exception as e:
        return {"verdict": "inconclusive", "engine": "playwright",
                "evidence": f"playwright 失败: {str(e)[:200]}"}


def main():
    ap = argparse.ArgumentParser(description="XSS 执行确认（W12）")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--engine", default="auto", choices=["auto", "dalfox", "playwright"])
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    run_dir = Path(a.run_dir)
    out_jsonl = run_dir / "xss_verified.jsonl"
    if out_jsonl.exists() and not a.force:
        print(f"[=] 已存在 {out_jsonl}（--force 重跑）")
        return

    cands = load_candidates(run_dir)
    print(f"[*] 反射候选 {len(cands)}；engine={a.engine}（dalfox 存在: {DALFOX.is_file()}）")

    results = []
    waf_strikes = 0
    for c in cands:
        marker = make_marker()
        time.sleep(a.delay)
        if a.engine in ("auto", "dalfox") and DALFOX.is_file():
            rec = run_dalfox(c, marker)
        elif a.engine in ("auto", "playwright"):
            rec = run_playwright(c, marker)
        else:
            rec = None
        if rec is None:
            rec = run_playwright(c, marker)
        if rec is None or rec.get("verdict") == "inconclusive":
            # 兜底：内置 requests 抓取 + DOM 上下文判定（无任何引擎依赖）
            url = mutate_with_marker(c["url"], c.get("param", ""), marker)
            st, html = fetch_page(url)
            if st == 200:
                rec = {"verdict": verdict_from_dom(marker, html), "engine": "stdlib-fetch",
                       "evidence": f"HTTP {st}，marker DOM 判定"}
            else:
                rec = rec or {"verdict": "inconclusive", "engine": "none",
                              "evidence": f"HTTP {st}，无可用引擎"}
        # 403 连续 5 次 → WAF 停
        st, body = fetch_page(c["url"])
        if st == 403:
            waf_strikes += 1
            if waf_strikes >= 5:
                print("[!] 连续 403，疑似 WAF，停止验证")
                break
        else:
            waf_strikes = 0
        rec.update({"candidate": c["url"], "param": c.get("param"), "ts": now_iso()})
        results.append(rec)
        print(f"  [{rec['verdict']}] {c['url'][:90]} ({rec['engine']})")

    with out_jsonl.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    n_exec = sum(1 for r in results if r.get("verdict") == "executable")
    print(f"[+] {out_jsonl}（{len(results)} 候选，{n_exec} executable）")


if __name__ == "__main__":
    main()
