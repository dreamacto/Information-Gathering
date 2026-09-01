"""Offline run duplicate gate; does not execute or resume runs."""
from __future__ import annotations

from datetime import datetime
from typing import Mapping

from .run_identity import dedup_key


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def find_reuse(current: Mapping, existing: list[Mapping], *, now: str, cooldown_seconds: int = 3600) -> dict:
    key = dedup_key(
        engagement_id=str(current["engagement_id"]), canonical_target=str(current["canonical_target"]),
        phase=str(current["phase"]), config_hash=str(current["config_hash"]), input_hash=str(current["input_hash"]),
    )
    now_dt = _time(now)
    matches = []
    for row in existing:
        if row.get("dedup_key") != key or not row.get("run_id"):
            continue
        finished = row.get("finished_at") or row.get("started_at")
        if not finished:
            continue
        age = (now_dt - _time(str(finished))).total_seconds()
        if 0 <= age <= cooldown_seconds and row.get("terminal_state") in {"complete", "scan_done", "success"}:
            matches.append((age, str(row["run_id"])))
    if not matches:
        return {"duplicate": False, "action": "full_run", "matched_run_id": None, "reason": "no reusable run in cooldown"}
    _, run_id = min(matches, key=lambda item: (item[0], item[1]))
    return {"duplicate": True, "action": "resume_delta", "matched_run_id": run_id, "reason": "same input key within cooldown"}
