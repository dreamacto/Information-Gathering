#!/usr/bin/env python3
"""run_lifecycle.py —— run 完成态查询器（20260822 首跑复盘 P1）。

回答"这个 run 跑完了吗 / 下一步是什么"，让完成态从 AI 自由裁量变成查文件。
零网络请求：全部状态从盘上产物推导 + 可选的人工显式标记。

用法：
  python run_lifecycle.py runs/<ts>              # 查询并写 run_lifecycle.json
  python run_lifecycle.py runs/<ts> --mark planned/light_exhausted/accepted_report ...

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
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

CST = timezone(timedelta(hours=8))
ROOT = Path(__file__).resolve().parent

MANUAL_STATES = {"planned", "light_exhausted", "accepted_report", "swept"}


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


def derive(run_dir: Path) -> dict:
    q = run_dir / "postrun_review" / "target_review_queue.csv"
    verdicts = sorted((run_dir / "postrun_review" / "verdicts").glob("*.json")) if (run_dir / "postrun_review" / "verdicts").is_dir() else []
    queue_rows = []
    if q.is_file():
        import csv
        with q.open(encoding="utf-8-sig", newline="") as f:
            queue_rows = list(csv.DictReader(f))
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
    if queue_rows and pending == 0:
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
        },
        "complete_cycle": all(s in all_states for s, _ in steps),
        "next_step": next_step,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="run 完成态查询器：回答'跑完了吗/下一步是什么'")
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--mark", metavar="STATE", choices=sorted(MANUAL_STATES), help="人工显式标记状态（planned/light_exhausted/accepted_report/swept）")
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
