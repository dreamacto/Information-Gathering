#!/usr/bin/env python3
"""run_lifecycle.py —— run 完成态查询器（20260822 首跑复盘 P1）。

回答"这个 run 跑完了吗 / 下一步是什么"，让完成态从 AI 自由裁量变成查文件。
零网络请求：全部状态从盘上产物推导 + 可选的人工显式标记。

用法：
  python run_lifecycle.py runs/<ts>              # 查询并写 run_lifecycle.json
  python run_lifecycle.py runs/<ts> --mark planned/light_exhausted/report_accepted ...

状态推导规则（证据 → 状态）：
  scan_done           run_summary.json 存在
  review_workspace    postrun_review/target_review_queue.csv 存在
  review_in_progress  verdicts/ 有部分 json 且队列有 pending
  review_aggregated   队列全部非 pending（--aggregate 已跑）
  planned             postrun_review/hypothesis_plan.jsonl 存在
  light_exhausted     phase_status.json 里 light_phases_exhausted=true
  swept               knowledge_base/last_sweep.json 的 runs_covered 含本 run
  awaiting_approval   游标指向审批门阶段（phase_status.json cursor 或 stop_reason 含审批门）
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import artifact_manifest  # noqa: F401  (shim inserts src/ on sys.path)
from artifact_manifest import verify_manifest

from authorized_assessment.quality.run_quality_gate import validate_quality_report

CST = timezone(timedelta(hours=8))
ROOT = Path(__file__).resolve().parent

MANUAL_STATES = {
    "planned",
    "light_exhausted",
    "swept",
    # 报告生命周期五态（实施规格 684-694 行）：孤立的 accepted_report 不再是完整闭环
    "report_generated",
    "report_reviewed",
    "report_accepted",
    "report_delivered",
    "report_superseded",
}
REPORT_LIFECYCLE_STATES = (
    "report_generated",
    "report_reviewed",
    "report_accepted",
    "report_delivered",
    "report_superseded",
)

# review_aggregated 七项验证（实施规格 674-682 行）；verdict 枚举与 fh_review_dispatch 双端对齐
VERDICT_REQUIRED = ("review_order", "host", "disposition", "confidence", "basis")
VERDICT_DISPOSITIONS = {
    "pending",
    "confirmed",
    "rejected",
    "duplicate",
    "out_of_scope",
    "needs_login",
    "approval_required",
    "blocked",
    "accepted_risk",
}
TERMINAL_LEDGER_STATUSES = {"reviewed", "skipped"}
BLOCKING_COUNTED_DISPOSITIONS = ("blocked", "needs_login", "approval_required")
EVIDENCED_DISPOSITIONS = ("confirmed", "accepted_risk")
CONCLUSION_ALLOWED_QUALITY = {"VALID", "PARTIAL"}
RUN_QUALITY_FILENAME = "run_quality.json"


def _split_sources(raw: object) -> set[str]:
    return {s.strip() for s in str(raw or "").replace("|", ";").split(";") if s.strip()}


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


def read_csv_rows(p: Path) -> list[dict]:
    if not p.is_file():
        return []
    with p.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def evaluate_review_aggregation(run_dir: Path, queue_rows: list[dict]) -> dict:
    """review_aggregated 七项验证（实施规格 674-682 行）；任一不过即 fail-closed。

    返回 {"allowed": bool, "checks": {...}, "reasons": [...], "counts": {...}}。
    """
    checks: dict[str, bool] = {}
    reasons: list[str] = []
    counts: dict[str, int] = {"queue_total": len(queue_rows)}
    for d in BLOCKING_COUNTED_DISPOSITIONS:
        counts[d] = 0

    verdicts_dir = run_dir / "postrun_review" / "verdicts"
    verdict_by_order: dict[str, dict] = {}
    if verdicts_dir.is_dir():
        for p in sorted(verdicts_dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                reasons.append(f"verdict_parse_error: {p.name}")
                continue
            if isinstance(data, dict):
                verdict_by_order[p.stem] = data

    unaggregated: list[str] = []
    invalid_verdicts: list[str] = []
    blocking_unreasoned: list[str] = []
    missing_evidence: list[str] = []
    pending_rows: list[str] = []

    for row in queue_rows:
        disp = (row.get("disposition") or "pending").strip() or "pending"
        order = str(row.get("review_order") or "").strip() or "<no_order>"
        verdict = verdict_by_order.get(order) if order != "<no_order>" else None
        if disp == "pending":
            pending_rows.append(order)
            if verdict is None:
                unaggregated.append(order)
            else:
                for field in VERDICT_REQUIRED:
                    if field not in verdict:
                        invalid_verdicts.append(f"{order}:missing:{field}")
                vdisp = str(verdict.get("disposition") or "pending")
                if vdisp not in VERDICT_DISPOSITIONS:
                    invalid_verdicts.append(f"{order}:bad_disposition:{vdisp}")
                elif vdisp == "pending":
                    unaggregated.append(order)
        if disp in BLOCKING_COUNTED_DISPOSITIONS:
            counts[disp] += 1
            if not str(row.get("notes") or "").strip() and not str(
                (verdict or {}).get("basis") or ""
            ).strip():
                blocking_unreasoned.append(order)
        if disp in EVIDENCED_DISPOSITIONS and not str(row.get("evidence_paths") or "").strip():
            if not str((verdict or {}).get("basis") or "").strip():
                missing_evidence.append(order)

    checks["batch_verdicts_aggregated"] = not unaggregated and not invalid_verdicts
    if unaggregated:
        reasons.append("batch_verdicts_missing_or_pending: " + ",".join(unaggregated[:5]))
    if invalid_verdicts:
        reasons.append("verdicts_invalid: " + "; ".join(invalid_verdicts[:5]))

    checks["no_pending_left"] = not pending_rows
    if pending_rows:
        reasons.append(f"pending_rows_left: {len(pending_rows)}")

    ledger_path = run_dir / "postrun_review" / "review_ledger.csv"
    ledger_sources: set[str] = set()
    bad_ledger_status: list[str] = []
    duplicate_ledger_rows: list[str] = []
    for row in read_csv_rows(ledger_path):
        src = str(row.get("source_file") or "").strip()
        status = str(row.get("status") or "").strip().lower()
        if src:
            if src in ledger_sources:
                duplicate_ledger_rows.append(src)
            ledger_sources.add(src)
        if status not in TERMINAL_LEDGER_STATUSES:
            bad_ledger_status.append(f"{src or '<blank>'}:{status or 'empty'}")

    queue_sources: set[str] = set()
    for row in queue_rows:
        queue_sources |= _split_sources(row.get("source_files"))
    unmapped = sorted(queue_sources - ledger_sources)
    checks["candidate_sources_mapped"] = not unmapped
    if unmapped:
        reasons.append("sources_not_in_ledger: " + ",".join(unmapped[:5]))

    checks["ledger_queue_counts_consistent"] = not bad_ledger_status and not duplicate_ledger_rows
    if bad_ledger_status:
        reasons.append("ledger_rows_not_terminal: " + "; ".join(bad_ledger_status[:5]))
    if duplicate_ledger_rows:
        reasons.append("ledger_duplicate_source_rows: " + ",".join(sorted(set(duplicate_ledger_rows))[:5]))

    checks["blocking_dispositions_counted"] = not blocking_unreasoned
    if blocking_unreasoned:
        reasons.append("blocking_rows_without_reason: " + ",".join(blocking_unreasoned[:5]))

    checks["confirmed_evidence_valid"] = not missing_evidence
    if missing_evidence:
        reasons.append("evidenced_rows_without_evidence: " + ",".join(missing_evidence[:5]))

    quality_path = run_dir / RUN_QUALITY_FILENAME
    if not quality_path.is_file():
        checks["run_quality_gate_allows_conclusions"] = False
        reasons.append(f"run_quality_report_missing: {RUN_QUALITY_FILENAME}")
    else:
        try:
            report = json.loads(quality_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            report = None
        if not isinstance(report, dict):
            checks["run_quality_gate_allows_conclusions"] = False
            reasons.append("run_quality_report_unparseable")
        else:
            errors = validate_quality_report(report)
            if errors:
                checks["run_quality_gate_allows_conclusions"] = False
                reasons.append("run_quality_report_invalid: " + "; ".join(errors[:3]))
            elif report.get("quality_status") not in CONCLUSION_ALLOWED_QUALITY:
                checks["run_quality_gate_allows_conclusions"] = False
                reasons.append(
                    f"run_quality_status_blocks_conclusions: {report.get('quality_status')}"
                )
            else:
                checks["run_quality_gate_allows_conclusions"] = True

    allowed = all(checks.values())
    if not allowed:
        reasons.insert(0, "review_aggregated_denied")
    return {"allowed": allowed, "checks": checks, "reasons": reasons, "counts": counts}


def derive(run_dir: Path) -> dict:
    q = run_dir / "postrun_review" / "target_review_queue.csv"
    verdicts = sorted((run_dir / "postrun_review" / "verdicts").glob("*.json")) if (run_dir / "postrun_review" / "verdicts").is_dir() else []
    queue_rows = read_csv_rows(q)
    pending = sum(1 for r in queue_rows if (r.get("disposition") or "pending") == "pending")

    phase_status = {}
    ps = run_dir / "phase_status.json"
    if ps.is_file():
        try:
            phase_status = json.loads(ps.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            phase_status = {}

    states = []
    if (run_dir / "run_summary.json").is_file():
        states.append("scan_done")
    if q.is_file():
        states.append("review_workspace")
    if verdicts and pending > 0:
        states.append("review_in_progress")
    aggregation = evaluate_review_aggregation(run_dir, queue_rows) if queue_rows else None
    if queue_rows and aggregation and aggregation["allowed"]:
        states.append("review_aggregated")
    if (run_dir / "postrun_review" / "hypothesis_plan.jsonl").is_file():
        states.append("planned")
    if phase_status.get("light_phases_exhausted"):
        states.append("light_exhausted")
    # swept 推导：配方E 沉淀游标覆盖本 run（也可 --mark swept 手动标记）
    sweep_cur = ROOT / "knowledge_base" / "last_sweep.json"
    if sweep_cur.is_file():
        try:
            if any(str(run_dir.name) in str(c) for c in json.loads(sweep_cur.read_text(encoding="utf-8")).get("runs_covered", [])):
                states.append("swept")
        except json.JSONDecodeError:
            pass
    cursor = str(phase_status.get("cursor") or "")
    stop_reason = str(phase_status.get("stop_reason") or "")
    if cursor in ("weak_credential_review", "credential_testing", "exploitability", "approval_gate") or "审批门" in stop_reason:
        states.append("awaiting_approval")

    # 显式人工标记（--mark）持久化在 run_lifecycle.manual.json，与推导合并
    manual_path = run_dir / "run_lifecycle.manual.json"
    manual = []
    if manual_path.is_file():
        try:
            manual = json.loads(manual_path.read_text(encoding="utf-8")).get("states", [])
        except json.JSONDecodeError:
            manual = []

    all_states = list(dict.fromkeys(states + [m for m in manual if m in MANUAL_STATES]))

    steps = [
        ("scan_done", "一键流程/编排器跑完 L0"),
        ("review_workspace", "fh_review_dispatch --prepare 或 init_postrun_review 已建工作区"),
        ("review_aggregated", "批次复核 verdicts 全部落盘并 --aggregate"),
        ("planned", "配方B 产出 hypothesis_plan.jsonl 并经人工批准"),
        ("light_exhausted", "配方C 轻量阶段穷尽（游标停在审批门/重量级/预算）"),
        ("swept", "配方E 周度沉淀已覆盖本 run"),
    ]
    next_step = next((name + " · " + desc for name, desc in steps if name not in all_states), "全部阶段闭环（或进入周期性下一轮）")

    integrity = verify_manifest(run_dir)

    return {
        "run_dir": str(run_dir),
        "generated_at": now_iso(),
        "states": all_states,
        "derived_from": {
            "queue_total": len(queue_rows),
            "queue_pending": pending,
            "verdict_files": len(verdicts),
            "cursor": cursor or None,
            "stop_reason": stop_reason or None,
            "review_aggregation": aggregation,
        },
        "complete_cycle": all(s in all_states for s, _ in steps),
        "integrity": integrity,
        "cleanup_audit": "recorded" if (run_dir / "deletion_audit.jsonl").is_file() else "legacy_unknown",
        "next_step": next_step,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="run 完成态查询器：回答'跑完了吗/下一步是什么'")
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--mark", metavar="STATE", choices=sorted(MANUAL_STATES), help="人工显式标记状态（planned/light_exhausted/swept/报告生命周期五态）")
    a = ap.parse_args()

    run_dir = a.run_dir if a.run_dir.is_absolute() else ROOT / a.run_dir
    if not run_dir.is_dir():
        print(f"[!] 目录不存在: {run_dir}")
        return 2

    if a.mark:
        manual_path = run_dir / "run_lifecycle.manual.json"
        cur = {"states": []}
        if manual_path.is_file():
            try:
                cur = json.loads(manual_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                cur = {"states": []}
        if a.mark not in cur["states"]:
            cur["states"].append(a.mark)
        manual_path.write_text(json.dumps(cur, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"[+] 已标记 {a.mark} → {manual_path}")

    info = derive(run_dir)
    out = run_dir / "run_lifecycle.json"
    out.write_text(json.dumps(info, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[*] {run_dir}")
    print(f"    状态: {' + '.join(info['states']) or '（空 run，无产物）'}")
    print(f"    完整闭环: {'是' if info['complete_cycle'] else '否'}")
    print(f"    下一步: {info['next_step']}")
    print(f"    明细: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
