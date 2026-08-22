#!/usr/bin/env python3
"""waf_profile.py —— WAF/拦截画像合成器（20260822 首跑复盘 P1，零网络请求）。

把散落在多份产物里的拦截证据合并成每 host 一份"拦截画像"，
防止下游把 WAF/网关 403 误读成业务信号（本 run 的 SQLi 误报正是此因）。

输入（全部只读盘上文件）：
  candidate_exposures.jsonl   status>=400 行：body_sample_sha256 / server / path
  sqli_candidates.jsonl       boolean_diffs 里非 2xx 的 true/false_text 头 60 字符与 server 线索
  second_pass_results.jsonl   status>=400 行
  light_verify_final.jsonl    本目录存在的轻量验证记录（H6 类）

输出：
  waf_profile.jsonl   每 host 一行：拦截层/触发模式/统一性哈希/证据引用
  reports/waf_profile.md   人读版 + 对下游判据的建议

判据（保守）：
  unified_block     ≥2 个不同路径返回同一响应体哈希 → 统一拦截页
  single_block      仅 1 个 4xx 样本 → 记录待证
  layer_guess       从响应正文头 60 字符提取网关/服务器名（AppGateway/Tengine/nginx/cloudflare…）
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

CST = timezone(timedelta(hours=8))


def now_iso() -> str:
    return datetime.now(CST).isoformat(timespec="seconds")


def read_jsonl(p: Path) -> list[dict]:
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


LAYER_PATTERNS = [
    (re.compile(r"Microsoft-Azure-Application-Gateway", re.I), "Azure Application Gateway"),
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"Tengine", re.I), "Tengine"),
    (re.compile(r"nginx", re.I), "nginx"),
    (re.compile(r"AlibabaSLB|aliyun", re.I), "Alibaba SLB/WAF"),
    (re.compile(r"SafeDog|safedog", re.I), "SafeDog WAF"),
    (re.compile(r"<title>403 Forbidden</title>", re.I), "generic-403-page"),
]


def guess_layer(text: str, server_header: str = "") -> str:
    for source in (server_header or "", (text or "")[:200]):
        for pat, name in LAYER_PATTERNS:
            if pat.search(source):
                return name
    return "unknown"


def host_of(url: str) -> str:
    s = str(url or "")
    if "://" in s:
        return s.split("://", 1)[1].split("/", 1)[0]
    return s.split("/", 1)[0]


def build(run_dir: Path) -> list[dict]:
    evidence: dict[str, list[dict]] = defaultdict(list)

    for row in read_jsonl(run_dir / "candidate_exposures.jsonl"):
        st = row.get("status")
        if isinstance(st, int) and st >= 400:
            host = row.get("host") or host_of(row.get("url"))
            if host:
                evidence[host].append({
                    "source": "candidate_exposures.jsonl",
                    "path": row.get("path"),
                    "status": st,
                    "body_sha": row.get("body_sample_sha256"),
                    "server": row.get("server") or "",
                    "text_head": "",
                })

    for row in read_jsonl(run_dir / "sqli_candidates.jsonl"):
        host = row.get("host") or host_of(row.get("url"))
        diffs = row.get("boolean_diffs") or {}
        for _param, d in diffs.items():
            st = d.get("true_status") or d.get("false_status")
            if isinstance(st, int) and st >= 400:
                text = (d.get("true_text") or d.get("false_text") or "")[:200]
                if host:
                    evidence[host].append({
                        "source": f"sqli_candidates.jsonl#{_param}",
                        "path": (row.get("url") or "")[:120],
                        "status": st,
                        "body_sha": None,
                        "server": "",
                        "text_head": text,
                    })
                break

    for row in read_jsonl(run_dir / "second_pass_results.jsonl"):
        st = row.get("status")
        if isinstance(st, int) and st >= 400 and row.get("host"):
            evidence[row["host"]].append({
                "source": "second_pass_results.jsonl",
                "path": (row.get("url") or "")[:120],
                "status": st,
                "body_sha": row.get("sample_sha256"),
                "server": "",
                "text_head": "",
            })

    for row in read_jsonl(run_dir / "light_verify_final.jsonl"):
        st = row.get("status")
        if isinstance(st, int) and st >= 400:
            host = host_of(row.get("url"))
            if host:
                evidence[host].append({
                    "source": "light_verify_final.jsonl",
                    "path": (row.get("url") or "")[:120],
                    "status": st,
                    "body_sha": None,
                    "server": row.get("server") or "",
                    "text_head": "",
                })

    profiles = []
    for host, evs in sorted(evidence.items()):
        statuses = Counter(e["status"] for e in evs)
        shas = [e["body_sha"] for e in evs if e["body_sha"]]
        unified = len(set(shas)) == 1 and len(shas) >= 2 if shas else False
        layers = Counter(guess_layer(e["text_head"], e["server"]) for e in evs)
        layer = layers.most_common(1)[0][0] if layers else "unknown"
        profiles.append({
            "checked_at": now_iso(),
            "host": host,
            "block_samples": len(evs),
            "status_distribution": dict(statuses),
            "unified_block_page": unified,
            "layer_guess": layer,
            "distinct_body_hashes": len(set(shas)),
            "evidence": [{k: e[k] for k in ("source", "path", "status")} for e in evs[:10]],
            "guidance": (
                "统一拦截页：该 host 的 4xx 差异大概率是 WAF/网关行为，参数级判据需先排除拦截因素，候选建议打 waf_blocked 标注"
                if unified else
                "拦截证据存在但未证明统一拦截页：复核 4xx 候选时人工确认响应体是否一致"
            ),
        })
    return profiles


def main() -> int:
    ap = argparse.ArgumentParser(description="WAF/拦截画像合成（零网络请求，纯盘上聚合）")
    ap.add_argument("--run-dir", type=Path, required=True)
    a = ap.parse_args()
    run_dir = a.run_dir if a.run_dir.is_absolute() else Path.cwd() / a.run_dir

    profiles = build(run_dir)
    out = run_dir / "waf_profile.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for p in profiles:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    rep = run_dir / "reports" / "waf_profile.md"
    rep.parent.mkdir(exist_ok=True)
    lines = [
        "# WAF/拦截画像（零请求盘上合成）",
        "",
        f"- 生成：{now_iso()} · 输入：candidate_exposures / sqli_candidates / second_pass_results / light_verify_final",
        f"- host 数：{len(profiles)}",
        "",
        "| host | 4xx样本 | 状态分布 | 统一拦截页 | 拦截层猜测 | 建议 |",
        "|---|---|---|---|---|---|",
    ]
    for p in profiles:
        lines.append(f"| {p['host']} | {p['block_samples']} | {p['status_distribution']} | {'是' if p['unified_block_page'] else '未证明'} | {p['layer_guess']} | {p['guidance'][:60]} |")
    lines += ["", "## 对下游判据的指令", "",
              "- 复核/规划会话读到本文件后：凡 status_distribution 里的 4xx 差异候选，先按 `waf_blocked` 假设处理，再谈参数语义。"]
    rep.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] {len(profiles)} 个 host 画像 → {out}")
    print(f"[+] 人读版 → {rep}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
