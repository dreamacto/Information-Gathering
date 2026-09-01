"""Deterministic offline run lineage and input identity helpers."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

REQUIRED_FIELDS = (
    "parent_run_id", "attempt_no", "retry_of", "engagement_id", "phase",
    "config_hash", "input_hash", "started_at", "finished_at", "terminal_state",
)


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def dedup_key(*, engagement_id: str, canonical_target: str, phase: str, config_hash: str, input_hash: str) -> str:
    return "|".join((engagement_id, canonical_target, phase, config_hash, input_hash))


def build_run_metadata(*, engagement_id: str, canonical_target: str, phase: str, config: Any, input_data: Any,
                       parent_run_id: str | None = None, attempt_no: int = 1, retry_of: str | None = None,
                       started_at: str | None = None, finished_at: str | None = None,
                       terminal_state: str = "in_progress") -> dict[str, Any]:
    if not engagement_id or not canonical_target or not phase:
        raise ValueError("engagement_id, canonical_target and phase are required")
    if attempt_no < 1:
        raise ValueError("attempt_no must be >= 1")
    return {
        "parent_run_id": parent_run_id,
        "attempt_no": attempt_no,
        "retry_of": retry_of,
        "engagement_id": engagement_id,
        "canonical_target": canonical_target,
        "phase": phase,
        "config_hash": canonical_hash(config),
        "input_hash": canonical_hash(input_data),
        "started_at": started_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "finished_at": finished_at,
        "terminal_state": terminal_state,
        "dedup_key": dedup_key(engagement_id=engagement_id, canonical_target=canonical_target,
                               phase=phase, config_hash=canonical_hash(config), input_hash=canonical_hash(input_data)),
    }
