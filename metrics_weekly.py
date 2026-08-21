# -*- coding: utf-8 -*-
"""W10 · 周度度量 metrics_weekly.py

扫描 runs/*/（近 N 天）→ 聚合五指标 → reports/metrics_YYYYMMDD.md + reports/metrics_history.jsonl。
纯离线、零网络。缺数据的指标显示 N/A 不报错。

五指标：
 1 每run候选数      = Σ(各 *_candidates.jsonl 行数) / run 数
 2 确认率          = findings_ledger confirmed / (confirmed+rejected)
 3 人工小时/确认    = N/A（当前无复核时长数据源；接口预留）
 4 各队列FP率       = fp_memory 条数 / 对应候选总量（按 host 前缀聚类的近似）
 5 假设命中率       = hypothesis_ledger tested_confirmed / (tested_confirmed+tested_falsified)

用法：
  python metrics_weekly.py [--days 7] [--runs-root runs]
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path

CST = timezone(timedelta(hours=8))
ROOT = Path(__file__).resolve().parent


def now_iso() -> str:
    return datetime.now(CST).isoformat(timespec="seconds")


def _mtime_within(p: Path, days: int, now: datetime) -> bool:
    if days >= 99999:
        return True
    try:
        return (now - datetime.fromtimestamp(p.stat().st_mtime, CST)).days <= days
    except OSError:
        return False


def count_lines(p: Path) -> int:
    try:
        with p.open(encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def read_jsonl(p: Path) -> list[dict]:
    out = []
    if not p.is_file():
        return out
    with p.open(encoding="utf-8", errors="replace") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                try:
                    out.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
    return out


def scan_runs(runs_root: Path, days: int, now: datetime) -> tuple[list[dict], list[str]]:
    runs, incomplete = [], []
    if not runs_root.is_dir():
        return runs, incomplete
    for d in sorted(runs_root.iterdir()):
        if not d.is_dir() or not _mtime_within(d, days, now):
            continue
        cand_total = 0
        cand_files = []
        for f in d.glob("*_candidates.jsonl"):
            n = count_lines(f)
            cand_total += n
            cand_files.append((f.name, n))
        has_summary = (d / "run_summary.json").is_file()
        runs.append({"dir": d.name, "candidates": cand_total, "cand_files": cand_files,
                     "has_summary": has_summary})
        if not has_summary:
            incomplete.append(d.name)
    return runs, incomplete


def collect_findings(runs_root: Path, days: int, now: datetime) -> Counter:
    c = Counter()
    for d in sorted(runs_root.iterdir() if runs_root.is_dir() else []):
        if not d.is_dir() or not _mtime_within(d, days, now):
            continue
        ws = d / "postrun_review"
        fl = ws / "findings_ledger.csv" if ws.is_dir() else None
        q = ws / "target_review_queue.csv" if ws.is_dir() else None
        if fl is not None and fl.is_file():
            import csv
            with fl.open(encoding="utf-8-sig", newline="") as f:
                for row in csv.DictReader(f):
                    st = (row.get("status") or "").strip().lower()
                    if st:
                        c[f"findings_{st}"] += 1
        if q is not None and q.is_file():
            import csv
            with q.open(encoding="utf-8-sig", newline="") as f:
                for row in csv.DictReader(f):
                    st = (row.get("disposition") or "pending").strip().lower()
                    c[f"disp_{st}"] += 1
    return c


def main() -> None:
    ap = argparse.ArgumentParser(description="周度度量聚合（W10）")
    ap.add_argument("--days", type=int, default=7, help="扫描近 N 天（99999=全量）")
    ap.add_argument("--runs-root", default="runs")
    ap.add_argument("--kb", default="knowledge_base")
    a = ap.parse_args()

    now = datetime.now(CST)
    runs_root = ROOT / a.runs_root
    kb_root = ROOT / a.kb
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)

    runs, incomplete = scan_runs(runs_root, a.days, now)
    n_runs = len(runs)
    cand_sum = sum(r["candidates"] for r in runs)

    # 指标1
    m1 = (cand_sum / n_runs) if n_runs else None

    # 指标2 确认率（queue disposition 近似 + findings_ledger 双口径）
    cnt = collect_findings(runs_root, a.days, now)
    confirmed = cnt.get("findings_confirmed", 0)
    rejected = cnt.get("disp_rejected", 0)
    denom = confirmed + rejected
    m2 = (confirmed / denom) if denom else None
    disp_confirmed = cnt.get("disp_confirmed", 0)

    # 指标3 人工小时/确认：当前无数据源
    m3 = "N/A（无复核时长数据源；在 postrun_review 记录人工起止时间后启用）"

    # 指标4 FP 率（fp_memory 条数 / 候选总量）
    fp_entries = read_jsonl(kb_root / "fp_memory.jsonl")
    m4 = (len(fp_entries) / cand_sum) if cand_sum else None

    # 指标5 假设命中率
    ledger = read_jsonl(kb_root / "hypothesis_ledger.jsonl")
    tested_c = sum(1 for h in ledger if h.get("status") == "tested_confirmed")
    tested_f = sum(1 for h in ledger if h.get("status") == "tested_falsified")
    m5 = (tested_c / (tested_c + tested_f)) if (tested_c + tested_f) else None

    def fmt(x, pct=False):
        if x is None:
            return "N/A"
        return f"{x*100:.1f}%" if pct else f"{x:.2f}"

    # 最吵队列：候选最多的 run 文件
    noisy = Counter()
    for r in runs:
        for fname, n in r["cand_files"]:
            noisy[fname] += n
    noisy_top = noisy.most_common(3)

    date = now.strftime("%Y%m%d")
    md = reports / f"metrics_{date}.md"
    lines = [
        f"# 周度度量 · {date}",
        "",
        f"- 扫描窗口：近 {a.days} 天 · run 目录 {n_runs} 个 · 生成 {now_iso()}",
        "",
        "## 五指标",
        "",
        "| # | 指标 | 值 | 说明 |",
        "|---|---|---|---|",
        f"| 1 | 每 run 候选数 | {fmt(m1)} | Σ candidates jsonl / run 数（共 {cand_sum} 条候选） |",
        f"| 2 | 确认率 | {fmt(m2, pct=True)} | findings confirmed={confirmed} / (confirmed+rejected={denom})；queue 侧 confirmed={disp_confirmed} |",
        f"| 3 | 人工小时/确认 | {m3} | |",
        f"| 4 | FP 记忆率 | {fmt(m4, pct=True)} | fp_memory {len(fp_entries)} 条 / 候选 {cand_sum} |",
        f"| 5 | 假设命中率 | {fmt(m5, pct=True)} | ledger tested {tested_c}+{tested_f} |",
        "",
        "## 最吵队列（候选最多的来源文件）",
        "",
    ]
    if noisy_top:
        lines += [f"- `{name}`：{n} 条" for name, n in noisy_top]
    else:
        lines.append("- 无候选文件")
    if incomplete:
        lines += ["", "## 数据不全的 run（缺 run_summary.json）", ""]
        lines += [f"- {n}" for n in incomplete[:20]]
    md.write_text("\n".join(lines), encoding="utf-8")

    hist = reports / "metrics_history.jsonl"
    with hist.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "date": date, "generated": now_iso(), "runs_scanned": n_runs,
            "candidates_total": cand_sum,
            "candidates_per_run": round(m1, 3) if m1 is not None else None,
            "confirm_rate": round(m2, 4) if m2 is not None else None,
            "fp_memory_entries": len(fp_entries),
            "hypothesis_hit_rate": round(m5, 4) if m5 is not None else None,
            "findings_confirmed": confirmed, "queue_confirmed": disp_confirmed,
            "incomplete_runs": len(incomplete),
        }, ensure_ascii=False) + "\n")

    print(f"[+] 报告 → {md}")
    print(f"[+] history 追加一行 → {hist}")
    print(f"[*] runs={n_runs} 候选={cand_sum} 每run候选={fmt(m1)} 确认率={fmt(m2, pct=True)} FP率={fmt(m4, pct=True)} 假设命中率={fmt(m5, pct=True)}")


if __name__ == "__main__":
    main()
