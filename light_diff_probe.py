#!/usr/bin/env python3
"""light_diff_probe.py —— 标准化"ad-hoc 只读差分"工具（20260822 复盘 P2）。

把 AI 会话手搓 requests 探测脚本这件事收编：给 URL+参数做小差分/连通性检查，
统一限速、统一证据落盘、统一"只记元数据"纪律。

用法（.venv 运行时，唯一有 h2 的环境）：
  .venv/Scripts/python.exe light_diff_probe.py --url "https://x/api?q=1" --probes baseline,quote,boolean --out runs/<ts>/light_diff.jsonl
  .venv/Scripts/python.exe light_diff_probe.py --url "https://x.net" --probes baseline --label H9-https

内置探针（全部只读 GET，绝不发 payload 语义外的请求）：
  baseline   原样 GET
  baseline2  再来一次（测响应稳定性）
  quote      参数值加单引号
  dquote     参数值加双引号
  boolean    参数值拼 ' AND '1'='1（仅用于观察是否被拦截层吞掉，不做注入判定）
  empty      参数值置空

纪律：并发 1；请求间隔 >= delay（默认 3s）；每 URL 探针数受 --budget 限制（默认 8）；
只落 status/len/sha256/content-type/server/elapsed 元数据，正文不落盘不进对话。
403/429/5xx 连续出现时提前停止并提示 WAF/拦截可能。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

CST = timezone(timedelta(hours=8))
UA = "Mozilla/5.0 (authorized-readonly-differential-probe)"


def now_iso() -> str:
    return datetime.now(CST).isoformat(timespec="seconds")


def set_param(url: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not pairs:
        return url
    new_pairs = [(pairs[0][0], value)] + pairs[1:]
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def build_probe_urls(url: str, probes: list[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name in probes:
        if name == "baseline" or name == "baseline2":
            out.append((name, url))
        elif name in ("quote", "dquote", "boolean", "empty"):
            pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
            if not pairs:
                continue
            k, v = pairs[0]
            new_v = {"quote": v + "'", "dquote": v + '"',
                     "boolean": v + "' AND '1'='1", "empty": ""}[name]
            out.append((name, set_param(url, new_v)))
    return out


def main() -> int:
    import requests

    ap = argparse.ArgumentParser(description="标准化只读差分探针（限速/落元数据/WAF 提示）")
    ap.add_argument("--url", required=True)
    ap.add_argument("--probes", default="baseline,quote",
                    help="逗号分隔：baseline,baseline2,quote,dquote,boolean,empty")
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--budget", type=int, default=8, help="单 URL 最大请求数")
    ap.add_argument("--out", type=Path, default=None, help="结果 jsonl 追加路径")
    ap.add_argument("--label", default="", help="证据标签（如 H6/H9）")
    a = ap.parse_args()

    probes = [p.strip() for p in a.probes.split(",") if p.strip()]
    plan = build_probe_urls(a.url, probes)[: a.budget]
    if not plan:
        print("[!] 无有效探针（参数化探针需要 URL 带 query）")
        return 2

    results = []
    consecutive_blocks = 0
    for name, purl in plan:
        try:
            r = requests.get(purl, timeout=a.timeout, headers={"User-Agent": UA})
            rec = {
                "ts": now_iso(), "label": a.label, "probe": name, "url": purl[:200],
                "status": r.status_code, "len": len(r.content),
                "sha256_12": hashlib.sha256(r.content).hexdigest()[:12],
                "content_type": r.headers.get("Content-Type", ""),
                "server": r.headers.get("Server", ""),
                "elapsed": round(r.elapsed.total_seconds(), 3),
            }
            if r.status_code in (403, 429) or r.status_code >= 500:
                consecutive_blocks += 1
            else:
                consecutive_blocks = 0
        except Exception as e:  # noqa: BLE001
            rec = {"ts": now_iso(), "label": a.label, "probe": name, "url": purl[:200], "error": str(e)[:120]}
        results.append(rec)
        print(json.dumps(rec, ensure_ascii=False)[:200])
        if consecutive_blocks >= 2:
            print("[!] 连续 2 次拦截类响应（403/429/5xx）→ 疑似 WAF/网关拦截，提前停止；差异判据先按 waf_blocked 处理")
            break
        if len(plan) > 1 and name != plan[-1][0]:
            time.sleep(max(a.delay, 0.5))

    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        with a.out.open("a", encoding="utf-8") as f:
            for rec in results:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"[+] {len(results)} 条元数据 → {a.out}")
    print("[i] 判读提示：各探针 sha/len 完全一致=参数被忽略；仅含引号/布尔的探针变 4xx=拦截层行为；本工具不做漏洞判定。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
