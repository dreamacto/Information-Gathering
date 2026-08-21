# -*- coding: utf-8 -*-
"""W7 · IDOR 水平越权差分引擎 idor_triage.py

输入（全部现成资产）：
  --run-dir    <dir>   输出写到该 run 目录
  --sessions   <file>  sessions.jsonl 或 auth_sessions.local.json（host→凭证≥1；≥2 可做水平差分）
  --requests   <file>  replay_requests.local.jsonl 或 api_confirmed.jsonl（只取 GET/HEAD 只读端点）

每端点最多 4 个请求：基线A / B重放 / 匿名 / 可选复验。
机器判据（全部确定性，无 LLM 参与）：
  anon==200 且 结构指纹==基线        → unauth_access（高置信）
  B==200 且 token Jaccard>0.85 且非通用错误页 → idor_horizontal_candidate
  200-with-error（状态200但正文含错误词）     → noise

安全约束：delay≥3s；并发1；每host≤5端点；凭证失效(401/302跳登录)即停该host；
A 的 Cookie 绝不发往 B 的 host（host_of 严格匹配）；UA 沿用会话文件原值。

输出：idor_candidates.jsonl + idor_manual_review.md
运行时：.venv（requests 可用即可）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from authenticated_session_review import host_of  # noqa: E402

ERR_WORDS = ("error", "失败", "未登录", "权限", "deny", "denied", "forbidden",
             "unauthorized", "登录", "过期", "重新登录")
AUTH_HEADERS = ("cookie", "authorization", "x-auth-token", "x-token", "token", "api-key", "apikey")


def now_iso():
    from datetime import datetime, timezone, timedelta
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def fetch_wait(url, headers=None, method="GET", timeout=15, delay=3.0, session=None, **kw):
    """限速请求：请求前强制等待 delay 秒（沿用 sqli_triage 的 fetch_wait 风格）。"""
    time.sleep(delay)
    if session is not None:
        return session.request(method, url, headers=headers, timeout=timeout,
                               allow_redirects=False, **kw)
    if HAS_REQUESTS:
        return requests.request(method, url, headers=headers, timeout=timeout,
                                allow_redirects=False, **kw)
    raise RuntimeError("无 requests：请用 .venv 运行")


def token_set(body: str) -> set:
    """正文 token 集合（连续非空白片段），用于结构相似度。"""
    return set(re.findall(r"\S{2,}", body[:20000]))


def struct_hash(body: str) -> str:
    """结构指纹：JSON 键路径集合 / HTML 标签序列的哈希（对值不敏感、对结构敏感）。"""
    try:
        data = json.loads(body)
        keys = set()

        def walk(o, prefix=""):
            if isinstance(o, dict):
                for k, v in o.items():
                    keys.add(f"{prefix}.{k}")
                    walk(v, f"{prefix}.{k}")
            elif isinstance(o, list):
                for v in o[:3]:
                    walk(v, prefix + "[]")

        walk(data)
        if keys:
            return hashlib.sha256("|".join(sorted(keys)).encode()).hexdigest()[:16]
    except (json.JSONDecodeError, ValueError):
        pass
    tags = re.findall(r"<[a-zA-Z][a-zA-Z0-9-]*", body[:20000])
    return hashlib.sha256("|".join(tags[:400]).encode()).hexdigest()[:16]


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def body_is_errorish(status: int, body: str) -> bool:
    """200-with-error 排除：状态 200 但正文含错误词 → 降级 noise。"""
    if status != 200:
        return False
    low = body[:4000].lower()
    return any(w.lower() in low for w in ERR_WORDS)


def load_sessions(path: Path) -> dict:
    """host → [凭证dict...]。兼容 sessions.jsonl 与 auth_sessions.local.json。"""
    by_host: dict[str, list[dict]] = {}
    text = path.read_text(encoding="utf-8", errors="replace")
    entries = []
    if path.suffix == ".jsonl":
        for ln in text.splitlines():
            ln = ln.strip()
            if ln:
                try:
                    entries.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
    else:
        try:
            data = json.loads(text)
            entries = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            pass
    for e in entries:
        host = e.get("host") or (urlparse(e.get("url", "")).hostname if e.get("url") else None)
        if not host:
            continue
        headers = dict(e.get("headers") or {})
        if e.get("cookie") and "cookie" not in {k.lower() for k in headers}:
            headers["Cookie"] = e["cookie"]
        if e.get("ua"):
            headers.setdefault("User-Agent", e["ua"])
        by_host.setdefault(host, []).append({
            "headers": headers,
            "label": e.get("label") or e.get("user") or "session",
        })
    return by_host


def load_endpoints(path: Path) -> list[dict]:
    """只取 GET/HEAD 只读端点。兼容 replay_requests.local.jsonl 与 api_confirmed.jsonl。"""
    out = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
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
        method = (e.get("method") or "GET").upper()
        if method not in ("GET", "HEAD"):
            continue
        out.append({"url": url, "method": method, "headers": e.get("headers") or {}})
    seen, dedup = set(), []
    for e in out:
        if e["url"] not in seen:
            seen.add(e["url"])
            dedup.append(e)
    return dedup


def strip_auth(headers: dict) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in AUTH_HEADERS}


def swap_auth(base_headers: dict, cred_headers: dict) -> dict:
    """保留业务头（UA/Referer/Accept 等），凭证头换成目标凭证的。"""
    merged = strip_auth(base_headers)
    for k, v in cred_headers.items():
        if k.lower() == "user-agent":
            continue
        merged[k] = v
    return merged


def main():
    ap = argparse.ArgumentParser(description="IDOR 水平越权差分引擎（W7）")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--sessions", required=True, help="sessions.jsonl 或 auth_sessions.local.json")
    ap.add_argument("--requests", required=True, help="replay_requests.local.jsonl 或 api_confirmed.jsonl")
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--max-per-host", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    run_dir = Path(a.run_dir)
    if not run_dir.is_dir():
        sys.exit(f"[!] run 目录不存在: {run_dir}")
    out_jsonl = run_dir / "idor_candidates.jsonl"
    if out_jsonl.exists() and not a.force:
        print(f"[=] 已存在 {out_jsonl}（--force 重跑）")
        return

    sessions = load_sessions(Path(a.sessions))
    endpoints = load_endpoints(Path(a.requests))
    print(f"[*] 会话 host 数={len(sessions)}；只读端点数={len(endpoints)}；delay={a.delay}s")

    per_host: dict[str, int] = {}
    hosts_dead = set()
    results = []
    sess_http = requests.Session() if HAS_REQUESTS else None

    for ep in endpoints:
        url = ep["url"]
        host = host_of(url) or urlparse(url).hostname
        if not host:
            continue
        if host in hosts_dead:
            continue
        if per_host.get(host, 0) >= a.max_per_host:
            continue
        creds = sessions.get(host)
        if not creds:
            continue  # 无凭证不做差分（避免把匿名可读误判）
        try:
            base_headers = dict(ep.get("headers") or {})
            if not base_headers:
                base_headers = {"User-Agent": "Mozilla/5.0 (compatible; authorized-review/1.0)"}

            # 1) 基线 A
            h_a = swap_auth(base_headers, creds[0]["headers"])
            r_a = fetch_wait(url, headers=h_a, method=ep["method"], timeout=a.timeout,
                             delay=a.delay, session=sess_http)
            if r_a.status_code in (401, 302) or "login" in (r_a.headers.get("Location", "") or "").lower():
                hosts_dead.add(host)
                print(f"[!] {host} 凭证疑似失效（{r_a.status_code}），本 host 停测")
                continue
            per_host[host] = per_host.get(host, 0) + 1
            body_a = r_a.text or ""
            tokens_a = token_set(body_a)
            rec = {
                "endpoint": url, "method": ep["method"], "host": host,
                "a": {"status": r_a.status_code, "len": len(body_a), "struct_hash": struct_hash(body_a)},
                "ts": now_iso(),
            }

            # 2) 匿名
            r_anon = fetch_wait(url, headers=strip_auth(base_headers), method=ep["method"],
                                timeout=a.timeout, delay=a.delay, session=sess_http)
            body_anon = r_anon.text or ""
            rec["anon"] = {"status": r_anon.status_code, "len": len(body_anon),
                           "struct_hash": struct_hash(body_anon)}

            # 3) B 重放（≥2 凭证才做）
            rec["b"] = None
            rec["similarity"] = None
            body_b = ""
            if len(creds) >= 2:
                h_b = swap_auth(base_headers, creds[1]["headers"])
                r_b = fetch_wait(url, headers=h_b, method=ep["method"], timeout=a.timeout,
                                 delay=a.delay, session=sess_http)
                body_b = r_b.text or ""
                rec["b"] = {"status": r_b.status_code, "len": len(body_b),
                            "struct_hash": struct_hash(body_b)}
                rec["similarity"] = round(jaccard(tokens_a, token_set(body_b)), 4)

            # 判定（纯机器）
            verdict = "inconclusive"
            if (rec["anon"]["status"] == 200
                    and rec["anon"]["struct_hash"] == rec["a"]["struct_hash"]
                    and not body_is_errorish(200, body_anon)):
                verdict = "unauth_access"
            elif (rec.get("b") and rec["b"]["status"] == 200
                    and (rec["similarity"] or 0) > 0.85
                    and not body_is_errorish(200, body_b)):
                verdict = "idor_horizontal_candidate"
            elif body_is_errorish(200, body_anon) or body_is_errorish(200, body_b):
                verdict = "noise"

            rec["verdict"] = verdict
            rec["evidence_ref"] = "响应摘要内联本文件；原始请求/响应不入对话"
            results.append(rec)
            b_status = rec["b"]["status"] if rec["b"] else "-"
            print(f"  [{verdict}] {url[:100]} anon={rec['anon']['status']} b={b_status} sim={rec['similarity']}")
        except Exception as e:
            results.append({"endpoint": url, "host": host, "verdict": "inconclusive",
                            "error": str(e)[:200], "ts": now_iso()})
            continue

    with out_jsonl.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    cand = [r for r in results if r.get("verdict") in ("unauth_access", "idor_horizontal_candidate")]
    md = run_dir / "idor_manual_review.md"
    lines = [
        "# IDOR 越权差分 · 人工复核队列",
        "",
        f"- 生成：idor_triage.py · {now_iso()} · 端点 {len(results)} · 候选 {len(cand)}",
        "- 判据为纯机器判定（结构指纹/Jaccard）；候选 ≠ 漏洞，需人工最小化验证。",
        "",
        "| # | verdict | host | endpoint | anon | B | similarity |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(cand, 1):
        b_status = r["b"]["status"] if r.get("b") else "-"
        lines.append(f"| {i} | {r['verdict']} | {r.get('host', '')} | {r['endpoint'][:90]} "
                     f"| {r['anon']['status']} | {b_status} | {r.get('similarity', '-')} |")
    md.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] {out_jsonl}（{len(results)} 端点，{len(cand)} 候选）；{md}")


if __name__ == "__main__":
    main()
