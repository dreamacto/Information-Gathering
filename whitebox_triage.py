# -*- coding: utf-8 -*-
"""W13 · 白盒 sink 流水线 whitebox_triage.py

--source-dir unpacked/wxXXX（或 --run-dir 自动发现）→ 扫 .js/.wxml/.json
→ sink_lib 命中行 ±3 行上下文 → sink_findings.jsonl + whitebox_review.md

不做全自动污点追踪；AI（配方F）基于输出做带证据研判。
纯离线、零网络。.min.js 先跳过（另 beautify 后再扫，避免行号错位）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SINK_LIB = ROOT / "knowledge_base" / "sink_lib.jsonl"


def now_iso():
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def load_sinks() -> list[dict]:
    sinks = []
    if not SINK_LIB.is_file():
        sys.exit(f"[!] sink 库不存在：{SINK_LIB}（先跑 scripts/gen_sink_lib.py）")
    for ln in SINK_LIB.read_text(encoding="utf-8").splitlines():
        if ln.strip():
            try:
                sinks.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    return sinks


def find_source_dir(source_dir: Path | None, run_dir: Path | None) -> Path:
    if source_dir and source_dir.is_dir():
        return source_dir
    if run_dir and run_dir.is_dir():
        # run 目录下常见 unpacked/ 或 miniapp 源码
        for sub in ("unpacked", "miniapp", "wxapp"):
            p = run_dir / sub
            if p.is_dir():
                return p
        # run 目录本身就是源码树（含 app.js）
        if (run_dir / "app.js").exists():
            return run_dir
    sys.exit("[!] 需要有效的 --source-dir 或含源码的 --run-dir")


def scan_file(fp: Path, sinks: list[dict], max_per_file: int = 10) -> list[dict]:
    findings = []
    try:
        text = fp.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    if fp.name.endswith(".min.js"):
        return findings  # 压缩文件跳过（行号无意义）
    lines = text.splitlines()
    per_cat_file: dict[str, int] = defaultdict(int)
    for i, line in enumerate(lines, 1):
        for s in sinks:
            cat = s["category"]
            if per_cat_file[cat] >= max_per_file:
                continue
            try:
                if re.search(s["pattern"], line):
                    ctx = "\n".join(lines[max(0, i - 4):i + 3])
                    findings.append({
                        "file": str(fp), "line": i, "category": cat,
                        "snippet": line.strip()[:120],
                        "severity": s.get("severity", "medium"),
                        "confidence": 0.5 if s.get("severity") == "low" else 0.7,
                        "context": ctx[:400],
                    })
                    per_cat_file[cat] += 1
            except re.error:
                continue  # 坏模式跳过，不中断整文件扫描
    return findings


def main():
    ap = argparse.ArgumentParser(description="白盒 sink 流水线（W13）")
    ap.add_argument("--source-dir", default=None)
    ap.add_argument("--run-dir", default=None, help="输出目录（也用于自动发现源码）")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--scan", action="store_true")
    ap.add_argument("--out-dir", default=None)
    a = ap.parse_args()

    source = find_source_dir(Path(a.source_dir) if a.source_dir else None,
                             Path(a.run_dir) if a.run_dir else None)
    out_dir = Path(a.out_dir) if a.out_dir else (Path(a.run_dir) if a.run_dir else ROOT)
    out_dir.mkdir(parents=True, exist_ok=True)
    sinks = load_sinks()
    print(f"[*] 源码树 {source} · sink 模式 {len(sinks)} 条")

    all_findings = []
    files = [p for p in source.rglob("*") if p.suffix in (".js", ".wxml", ".json") and p.is_file()]
    for fp in files:
        all_findings.extend(scan_file(fp, sinks))

    # 去重：同文件同类只留首次 + 计数
    seen = {}
    dedup = []
    for f in all_findings:
        key = (f["file"], f["category"])
        if key in seen:
            seen[key]["count"] += 1
        else:
            f["count"] = 1
            seen[key] = f
            dedup.append(f)

    out_jsonl = out_dir / "sink_findings.jsonl"
    with out_jsonl.open("w", encoding="utf-8") as f:
        for r in dedup:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # 聚合 review md（按文件分组，前10条/文件）
    by_file = defaultdict(list)
    for r in dedup:
        by_file[r["file"]].append(r)
    md = out_dir / "whitebox_review.md"
    lines = [
        "# 白盒 sink 复核清单（供配方F 研判）",
        "",
        f"- 源码树：{source} · 文件 {len(files)} · 命中 {len(dedup)}（含重复共 {len(all_findings)}）· {now_iso()}",
        "- 只标候选：入口可控性/链路完整性需配方F + 人工确认，绝不直接标 confirmed。",
        "",
    ]
    for fpath, items in sorted(by_file.items()):
        lines.append(f"## {fpath}")
        lines.append("")
        for r in items[:10]:
            lines.append(f"- **[{r['severity']}] {r['category']}** L{r['line']} ×{r['count']}")
            lines.append(f"  `{r['snippet']}`")
        if len(items) > 10:
            lines.append(f"- …另有 {len(items) - 10} 类")
        lines.append("")
    md.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] {out_jsonl}（{len(dedup)} 条）+ {md}")


if __name__ == "__main__":
    main()
