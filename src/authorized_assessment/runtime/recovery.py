"""Fail-closed, offline recovery planning.

Inputs are already-validated local control-plane records.  This module only
checks integrity and returns a plan; it never performs requests, writes, or
replays operations.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

WORKFLOWS = {"wz", "xcx"}
CURSORS = {"wz": "phase_status.json", "xcx": "phase_status.miniapp.json"}
FAIL_CLOSED = {"blocked", "timeout", "timed_out", "cancelled", "permission_denied", "failed"}


def canonical_hash(value: Any) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _hash_check(label: str, value: Any, expected: Any, errors: list[str]) -> None:
    if not isinstance(expected, str) or not expected:
        errors.append(f"missing_{label}_hash")
    elif canonical_hash(value) != expected:
        errors.append(f"{label}_hash_drift")


def _sequences(records: Sequence[Any], key: str) -> list[int]:
    values = []
    for item in records:
        if isinstance(item, Mapping) and isinstance(item.get(key), int) and not isinstance(item.get(key), bool):
            values.append(item[key])
    return values


def _validate_cursor(cursor: Any, workflow: str, errors: list[str]) -> None:
    if not isinstance(cursor, Mapping):
        errors.append("missing_cursor")
        return
    if cursor.get("workflow") != workflow:
        errors.append("cursor_workflow_mismatch")
    expected = CURSORS.get(workflow)
    if cursor.get("status_file") != expected:
        errors.append("cursor_stream_mismatch")
    seq = cursor.get("sequence")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        errors.append("invalid_cursor_sequence")


def _check_sequence_gap(records: Sequence[Any], key: str, errors: list[str], label: str) -> None:
    values = _sequences(records, key)
    if len(values) != len(records):
        errors.append(f"invalid_{label}_sequence")
        return
    if len(set(values)) != len(values):
        errors.append(f"duplicate_{label}_sequence")
    if values and values != list(range(min(values), max(values) + 1)):
        errors.append(f"{label}_sequence_gap")


def plan_recovery(state: Mapping[str, Any]) -> dict[str, Any]:
    """Return only ``resume``, ``blocked`` or ``manual-validation``."""
    errors: list[str] = []
    if not isinstance(state, Mapping):
        return {"status": "blocked", "reason": "invalid_state", "errors": ["state must be an object"], "actions": []}
    workflow = state.get("workflow")
    if workflow not in WORKFLOWS:
        errors.append("invalid_workflow")
    policy = state.get("policy")
    scope = state.get("scope")
    context = state.get("context")
    _hash_check("policy", policy, state.get("policy_hash"), errors)
    _hash_check("scope", scope, state.get("scope_hash"), errors)
    _hash_check("context", context, state.get("context_hash"), errors)
    _validate_cursor(state.get("cursor"), workflow, errors) if workflow in WORKFLOWS else errors.append("invalid_workflow")
    events = state.get("events", [])
    if not isinstance(events, list):
        errors.append("invalid_events")
    else:
        _check_sequence_gap(events, "aggregate_sequence", errors, "event")
    lineage = state.get("lineage", [])
    if not isinstance(lineage, list):
        errors.append("invalid_lineage")
    else:
        _check_sequence_gap(lineage, "attempt_no", errors, "attempt")
    idempotency = state.get("idempotency", [])
    if not isinstance(idempotency, list):
        errors.append("invalid_idempotency")
    statuses = {
        str(item.get("status", item.get("result_status", ""))).lower()
        for item in [*events, *lineage, *idempotency]
        if isinstance(item, Mapping)
    }
    if statuses & FAIL_CLOSED:
        errors.append("terminal_fail_closed_status")
    if state.get("cancel_requested") is True:
        errors.append("cancel_requested")
    if errors:
        return {"status": "blocked", "reason": "fail_closed", "errors": sorted(set(errors)), "actions": []}
    return {"status": "resume", "reason": "validated", "errors": [],
            "actions": ["resume_from_cursor"], "workflow": workflow,
            "cursor": state["cursor"].get("status_file")}


# Explicit aliases for compatibility with likely callers.
recover = plan_recovery
build_recovery_plan = plan_recovery
