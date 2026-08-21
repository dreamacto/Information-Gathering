# -*- coding: utf-8 -*-
"""W6 · fh 复核子代理编排器 fh_review_dispatch.py

把 init_postrun_review.py 生成的逐目标复核工作区，变成子代理可执行的批次文件，
并把 verdict 聚合回 findings_ledger.csv / review_ledger.csv / target_review_queue.csv。

设计要点（W5 已统一的契约，勿改）：
- 状态词 9 值枚举（与 fh skill / 配方A 完全一致）：
  pending|confirmed|rejected|duplicate|out_of_scope|needs_login|approval_required|blocked|accepted_risk
- 工作区 = <run_dir>/postrun_review/（target_review_queue.csv + target_reviews/ + review_ledger.csv + findings_ledger.csv）
- 批次文件自包含：子代理不需要读 fh/SKILL.md 也能干活
- 全程零网络请求，纯本地文件操作

用法：
  python tools/fh_review_dispatch.py --run-dir runs/20260820_114704_one_click_full_weak --prepare [--batch-size 8]
  python tools/fh_review_dispatch.py --run-dir runs/20260820_114704_one_click_full_weak --aggregate
  python tools/fh_review_dispatch.py --run-dir runs/20260820_114704_one_click_full_weak --status
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

CST = timezone(timedelta(hours=8))

VERDICT_ENUM = [
    "pending", "confirmed", "rejected", "duplicate", "out_of_scope",
    "needs_login", "approval_required", "blocked", "accepted_risk",
]
# verdict JSON 必备字段（batch 指令里也写了一份，双端对齐）
VERDICT_FIELDS = {
    "review_order": int,
    "target_id": str,
    "host": str,
    "disposition": VERDICT_ENUM,
    "confidence": float,          # 0.0-1.0
    "basis": str,                 # 卷宗内证据 "文件路径:行号" 或明确描述
    "next_action": str,           # 空串或建议动作
    "fp_pattern": str,            # rejected 时可空：误报特征，进 fp_memory
    "source_status": dict,        # 可选：{源文件名: status} 回填 review_ledger
}
VERDICT_REQUIRED = ["review_order", "host", "disposition", "confidence", "basis"]

QUEUE_COLS = [
    "target_id", "review_order", "priority", "value_score", "host", "base_url",
    "representative_url", "run_dirs", "categories", "signals", "source_files",
    "safe_readonly_plan", "approval_gates", "rate_limit", "status", "disposition",
    "evidence_paths", "notes",
]
FINDINGS_COLS = [
    "finding_id", "status", "run_dir", "source_item_id", "target", "url_or_path",
    "category", "title", "impact", "permission_level", "evidence_paths", "video_time",
    "cleanup", "retest", "notes",
]
FINDINGS_HEADER = ",".join(FINDINGS_COLS)

PRIORITY_WEIGHT = {"P0": 100, "P1": 60, "P2": 25, "P3": 10}


def now_iso() -> str:
    return datetime.now(CST).isoformat(timespec="seconds")


def load_queue(run_dir: Path) -> list[dict]:
    q = run_dir / "postrun_review" / "target_review_queue.csv"
    if not q.is_file():
        sys.exit(f"[!] 未找到复核工作区 {q}；先运行 scripts/init_postrun_review.py 或 fh skill 的同名脚本")
    with q.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def save_queue(run_dir: Path, rows: list[dict]) -> None:
    q = run_dir / "postrun_review" / "target_review_queue.csv"
    with q.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=QUEUE_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def find_dossier(ws: Path, order: str, host: str) -> Path | None:
    """卷宗定位：兼容 {order}_{host}.md 与零填充 {order:04d}_{host}.md，再 glob 兜底。"""
    tdir = ws / "target_reviews"
    cands = [tdir / f"{order}_{host}.md", tdir / f"{int(order):04d}_{host}.md"]
    for c in cands:
        if c.is_file():
            return c
    for p in sorted(tdir.glob(f"*_{host}.md")) if tdir.is_dir() else []:
        if p.stem.split("_", 1)[0].lstrip("0") == order.lstrip("0"):
            return p
    return None


def batch_instruction(dossier: Path | None, order: str, host: str) -> str:
    """批次文件里每个目标的指令块（自包含：verdict schema 原文 + 输出路径）。"""
    dossier_line = (f"- 卷宗：{dossier}（先完整读它，不要发任何网络请求）" if dossier
                    else "- 卷宗：缺失 → disposition 直接 blocked，basis 写“卷宗缺失，无法复核”")
    return f"""### 目标 {order} · {host}
{dossier_line}
- 完成卷宗 checklist：scope / 源文件 / 类别信号 / 安全只读计划 / 审批门 / 证据 / disposition / cleanup / retest
- 把判定写入 verdicts/{order}.json，schema 如下（UTF-8，一字段不缺）：

```json
{{
  "review_order": {order},
  "target_id": "<卷宗内 target_id>",
  "host": "{host}",
  "disposition": "pending|confirmed|rejected|duplicate|out_of_scope|needs_login|approval_required|blocked|accepted_risk 九值之一",
  "confidence": 0.0,
  "basis": "卷宗内证据（文件路径:行号 或 明确描述），confirmed 必须有确定性证据，证据不足降级 rejected/blocked/needs_login",
  "next_action": "",
  "fp_pattern": "仅 rejected 时可填：误报特征一句话（进 fp_memory 供下轮排重），其余留空",
  "source_status": {{"<源文件名>": "reviewed|skipped"}}
}}
```
"""


def cmd_prepare(run_dir: Path, batch_size: int) -> None:
    rows = load_queue(run_dir)
    ws = run_dir / "postrun_review"
    verdicts_dir = ws / "verdicts"
    verdicts_dir.mkdir(exist_ok=True)
    batches_dir = ws / "review_batches"
    batches_dir.mkdir(exist_ok=True)

    pending_rows = [r for r in rows if (r.get("disposition") or "pending") == "pending"]
    already = {p.stem for p in verdicts_dir.glob("*.json")}
    todo = [r for r in pending_rows if r["review_order"] not in already]

    total = len(rows)
    done = total - len(todo)
    print(f"[*] 队列 {total} 目标；已有 disposition 或已有 verdict {done}；待出批次 {len(todo)}")

    if not todo:
        nxt = _next_pending_order(rows)
        print(f"[=] 无待办。下一个未审 review_order={nxt}")
        return

    n_batches = 0
    for bi in range(0, len(todo), batch_size):
        chunk = todo[bi:bi + batch_size]
        idx = bi // batch_size + 1
        bno = f"batch_{idx:03d}"
        bpath = batches_dir / f"{bno}.md"
        if bpath.exists():
            print(f"[=] {bno}.md 已存在，跳过（幂等）")
            continue
        n_batches += 1
        lines = [
            f"# 复核批次 {bno}",
            "",
            f"- 生成：fh_review_dispatch.py --prepare · {now_iso()}",
            f"- 本批 {len(chunk)} 个目标。**一个会话只做这一批**；上下文到 70% 立即收尾，剩余目标留给下个会话。",
            "- 全程零网络请求：判断只依据卷宗与盘上文件；原始响应只引 \"文件路径:行号\"。",
            "- confirmed 必须有卷宗内确定性证据；证据不足一律降级，不硬凑。",
            "",
            "## 目标清单",
            "",
        ]
        for r in chunk:
            order = r["review_order"]
            host = r.get("host", "")
            dossier = find_dossier(ws, order, host)
            lines.append(f"- {order} · {host} · 优先级 {r.get('priority','')} · 卷宗 {'存在' if dossier else '缺失(跳过并在 verdict notes 说明)'}")
        lines.append("")
        lines.append("## 逐目标指令")
        lines.append("")
        for r in chunk:
            order = r["review_order"]
            host = r.get("host", "")
            dossier = find_dossier(ws, order, host)
            lines.append(batch_instruction(dossier, order, host))
        lines.append("## 完成后")
        lines.append("")
        lines.append(f"本批全部 verdict 写入 `{verdicts_dir}` 后，运行：")
        lines.append(f"`python tools/fh_review_dispatch.py --run-dir {run_dir} --aggregate`")
        (batches_dir / f"{bno}.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"[+] 已生成 {n_batches} 个批次文件 → {batches_dir}")
    print(f"[+] verdict 输出目录：{verdicts_dir}")
    nxt = todo[0]["review_order"] if todo else _next_pending_order(rows)
    print(f"[*] 下一个未审 review_order={nxt}")


def _next_pending_order(rows: list[dict]) -> str:
    for r in rows:
        if (r.get("disposition") or "pending") == "pending":
            return r["review_order"]
    return "-（全部已有 disposition）"


def _validate_verdict(data: dict, queue_by_order: dict) -> tuple[bool, str]:
    try:
        order = str(int(data.get("review_order")))
    except (TypeError, ValueError):
        return False, "review_order 缺失或非整数"
    if order not in queue_by_order:
        return False, f"review_order={order} 不在队列"
    disp = data.get("disposition")
    if disp not in VERDICT_ENUM:
        return False, f"disposition={disp!r} 不在 9 值枚举"
    if disp != "pending":
        for fld in ("confidence", "basis"):
            if not data.get(fld) and data.get(fld) != 0:
                return False, f"缺少 {fld}"
        try:
            if not (0.0 <= float(data["confidence"]) <= 1.0):
                return False, "confidence 超出 [0,1]"
        except (TypeError, ValueError):
            return False, "confidence 非数值"
        if disp == "confirmed" and len(str(data.get("basis", "")).strip()) < 10:
            return False, "confirmed 的 basis 过短（需确定性证据描述）"
    return True, ""


def cmd_aggregate(run_dir: Path) -> None:
    rows = load_queue(run_dir)
    ws = run_dir / "postrun_review"
    verdicts_dir = ws / "verdicts"
    queue_by_order = {r["review_order"]: r for r in rows}
    row_by_order = {r["review_order"]: r for r in rows}

    findings_path = ws / "findings_ledger.csv"
    if not findings_path.is_file():
        findings_path.write_text(FINDINGS_HEADER + "\n", encoding="utf-8-sig")

    fp_path = Path("knowledge_base/fp_memory.jsonl")
    if not fp_path.parent.is_dir():
        fp_path = ws / "fp_memory.jsonl"

    verdict_files = sorted(verdicts_dir.glob("*.json")) if verdicts_dir.is_dir() else []
    if not verdict_files:
        print("[=] verdicts/ 无文件；先让子代理按批次文件复核")
        _print_progress(rows)
        return

    invalid_path = ws / "invalid_verdicts.csv"
    applied = skipped = invalid = 0
    fp_added = findings_added = 0
    new_fp_lines: list[str] = []

    existing_orders = set()
    for v in verdict_files:
        try:
            data = json.loads(v.read_text(encoding="utf-8"))
        except Exception as e:
            invalid += 1
            _append_csv(invalid_path, [v.name, f"JSON解析失败: {e}"])
            continue
        ok, err = _validate_verdict(data, queue_by_order)
        if not ok:
            invalid += 1
            _append_csv(invalid_path, [v.name, err])
            continue
        order = str(int(data["review_order"]))
        if order in existing_orders:
            skipped += 1
            continue
        if (row_by_order[order].get("disposition") or "pending") != "pending":
            skipped += 1
            continue
        existing_orders.add(order)

        disp = data["disposition"]
        row = row_by_order[order]
        row["disposition"] = disp
        row["evidence_paths"] = data.get("basis", "") or row.get("evidence_paths", "")
        row["notes"] = (row.get("notes", "") + f" | verdict@{now_iso()} conf={data.get('confidence')}").strip(" |")
        applied += 1

        # review_ledger 回填 source_status
        src_status = data.get("source_status") or {}
        if src_status:
            _update_review_ledger(ws, order, src_status)

        # confirmed → findings_ledger
        if disp == "confirmed":
            fnum = sum(1 for _ in findings_path.open(encoding="utf-8-sig")) - 1
            fid = f"F-{datetime.now(CST).strftime('%Y%m%d')}-{fnum + 1:03d}"
            _append_csv_findings(findings_path, [
                fid, "confirmed", str(run_dir), row.get("target_id", order),
                row.get("host", ""), row.get("representative_url", ""),
                ";".join(filter(None, [row.get("categories", "")])) or "uncategorized",
                f"[AI初判] {row.get('host','')} 候选确认(待人工终审)",
                "待人工评估", "authenticated" if disp == "confirmed" else "unknown",
                data.get("basis", ""), "", "", "", f"confidence={data.get('confidence')} 由 fh_review_dispatch 聚合",
            ])
            findings_added += 1

        # rejected + fp_pattern → fp_memory
        if disp == "rejected" and data.get("fp_pattern"):
            new_fp_lines.append(json.dumps({
                "ts": now_iso(),
                "host": data.get("host") or row.get("host", ""),
                "fp_pattern": str(data["fp_pattern"]),
                "verdict_basis": f"verdicts/{order}.json basis={data.get('basis','')[:120]}",
            }, ensure_ascii=False))
            fp_added += 1

    save_queue(run_dir, rows)
    if new_fp_lines:
        with fp_path.open("a", encoding="utf-8") as f:
            for ln in new_fp_lines:
                f.write(ln + "\n")

    _write_top_file(ws, rows)
    print(f"[+] 聚合完成：应用 {applied} 条 verdict（跳过 {skipped}，无效 {invalid}→invalid_verdicts.csv）")
    print(f"[+] findings_ledger 新增 {findings_added} 行；fp_memory 新增 {fp_added} 行（→ {fp_path}）")
    _print_progress(rows)


def _print_progress(rows: list[dict]) -> None:
    total = len(rows)
    done = sum(1 for r in rows if (r.get("disposition") or "pending") != "pending")
    nxt = _next_pending_order(rows)
    print(f"[*] 进度：已审 {done}/总数 {total}，下一个未审 review_order={nxt}")


def _append_csv(path: Path, vals: list) -> None:
    new = not path.exists()
    with path.open("a", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["file", "reason"])
        w.writerow(vals)


def _append_csv_findings(path: Path, vals: list) -> None:
    with path.open("a", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerow(vals)


def _update_review_ledger(ws: Path, order: str, src_status: dict) -> None:
    p = ws / "review_ledger.csv"
    if not p.is_file():
        return
    with p.open(encoding="utf-8-sig", newline="") as f:
        rrows = list(csv.DictReader(f))
    if not rrows:
        return
    cols = list(rrows[0].keys())
    changed = False
    for rr in rrows:
        if rr.get("order") == order and rr.get("source_file") in src_status:
            st = src_status[rr["source_file"]]
            if st in ("reviewed", "skipped"):
                rr["status"] = st
                changed = True
    if changed:
        with p.open("w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rrows)


def _write_top_file(ws: Path, rows: list[dict]) -> None:
    done = [r for r in rows if r.get("disposition") not in (None, "", "pending")]
    scored = []
    for r in done:
        w_ = PRIORITY_WEIGHT.get(r.get("priority", ""), 0)
        try:
            w_ += float(r.get("value_score") or 0) / 100.0
        except ValueError:
            pass
        scored.append((w_, r))
    scored.sort(key=lambda t: t[0], reverse=True)
    top = scored[:10]
    lines = [
        "# TOP 人工复核（影响 × 置信度）",
        "",
        f"生成：fh_review_dispatch.py --aggregate · {now_iso()} · 已审 {len(done)}/{len(rows)}",
        "",
        "| review_order | host | disposition | priority | 依据/notes |",
        "|---|---|---|---|---|",
    ]
    for w_, r in top:
        lines.append(f"| {r.get('review_order')} | {r.get('host')} | {r.get('disposition')} | {r.get('priority')} | {(r.get('notes') or r.get('evidence_paths') or '')[:80]} |")
    (ws / "review_batches" / "TOP_人工复核.md").parent.mkdir(exist_ok=True)
    (ws / "review_batches" / "TOP_人工复核.md").write_text("\n".join(lines), encoding="utf-8")


def cmd_status(run_dir: Path) -> None:
    rows = load_queue(run_dir)
    from collections import Counter
    c = Counter((r.get("disposition") or "pending") for r in rows)
    print(f"[*] 队列 {len(rows)} 目标")
    for k in VERDICT_ENUM:
        if c.get(k):
            print(f"    {k:18s} {c[k]}")
    _print_progress(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description="fh 复核子代理编排器（W6）")
    ap.add_argument("--run-dir", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--prepare", action="store_true")
    g.add_argument("--aggregate", action="store_true")
    g.add_argument("--status", action="store_true")
    ap.add_argument("--batch-size", type=int, default=8)
    a = ap.parse_args()
    run_dir = Path(a.run_dir)
    if a.prepare:
        cmd_prepare(run_dir, a.batch_size)
    elif a.aggregate:
        cmd_aggregate(run_dir)
    else:
        cmd_status(run_dir)


if __name__ == "__main__":
    main()
