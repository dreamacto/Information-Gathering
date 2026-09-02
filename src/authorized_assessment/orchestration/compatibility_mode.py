"""Offline compatibility policy and run-ownership gates.

All decisions are local and fail closed. This module never reads credentials,
responses, HAR files, runs, or policy files.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from authorized_assessment.runtime.lease import LocalLeaseStore
from .approval_interrupt import check_approval
from .feature_flags import OrchestrationMode, FeatureFlagSnapshot, mode_snapshot, parse_mode

_READONLY_ACTIONS = frozenset({"offline", "read_only", "metadata", "plan", "inspect", "validate", "shadow"})
_ACTION_ALIASES = {"readonly": "read_only", "read-only": "read_only", "read only": "read_only"}


def resolve_mode(value: Any = None, *, explicit: bool = False, legacy_mode: Any = None) -> dict[str, Any]:
    try:
        mode = parse_mode(value)
    except ValueError as exc:
        return {"ok": False, "status": "rejected", "reason": "invalid_mode", "detail": str(exc)}
    snapshot = mode_snapshot(mode, legacy_mode=legacy_mode) if legacy_mode is not None else mode_snapshot(mode)
    return {"ok": True, "status": "resolved", "mode": mode.value,
            "explicit": bool(explicit or value is not None), "snapshot": snapshot.to_dict(),
            "snapshot_hash": snapshot.snapshot_hash}


def _result(ok: bool, status: str, reason: str | None = None, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": ok, "status": status}
    if reason:
        result["reason"] = reason
    result.update(extra)
    return result


def _normalize_action(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip().lower().replace("-", "_")
    return _ACTION_ALIASES.get(value, value)


def normalize_blocked_actions(value: Any) -> frozenset[str] | None:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, (list, tuple, set, frozenset)):
        return None
    return frozenset(a for item in value if (a := _normalize_action(item)) is not None)


def gate_graph_execution(mode: Any = None, context: Mapping[str, Any] | None = None, *, action: str | None = None, approval: Any = None, **kwargs: Any) -> dict[str, Any]:
    """Evaluate graph execution. Every malformed or missing prerequisite fails closed."""
    try:
        parsed = parse_mode(mode)
    except ValueError:
        return _result(False, "rejected", "invalid_mode")
    data = dict(context or {})
    data.update(kwargs)
    requested = _normalize_action(action if action is not None else data.get("action", data.get("requested_action")))
    blocked = normalize_blocked_actions(data.get("blocked_actions", ()))
    if blocked is None:
        return _result(False, "blocked", "invalid_blocked_actions", mode=parsed.value)
    if parsed is not OrchestrationMode.LEGACY and requested is None:
        return _result(False, "blocked", "action_required", mode=parsed.value)
    if requested in blocked:
        return _result(False, "blocked", "blocked_action", mode=parsed.value, action=requested)
    if parsed is OrchestrationMode.LEGACY:
        return _result(True, "allowed", "legacy_mode", mode=parsed.value)
    if parsed is OrchestrationMode.GRAPH_SHADOW:
        return _result(True, "shadow", "graph_not_dispatched", mode=parsed.value, dispatch=False, plan=True)
    for field in ("assessment_id", "phase", "target_ref", "policy_ref", "scope_ref"):
        if field not in data or (field.endswith("_ref") and not isinstance(data[field], Mapping)):
            return _result(False, "blocked", "context_missing", mode=parsed.value, field=field)
    if data.get("scope_confirmed") is not True or data.get("policy_valid") is not True or data.get("cursor_valid") is not True:
        return _result(False, "blocked", "readonly_prerequisite_missing" if parsed is OrchestrationMode.GRAPH_READONLY else "active_prerequisite_missing", mode=parsed.value)
    if data.get("stop_active", False) or data.get("cancelled", False):
        return _result(False, "blocked", "execution_stopped", mode=parsed.value)
    if data.get("permission_denied", False):
        return _result(False, "permission_denied", "permission_denied", mode=parsed.value)
    if parsed is OrchestrationMode.GRAPH_READONLY:
        if requested not in _READONLY_ACTIONS:
            return _result(False, "blocked", "readonly_action_required", mode=parsed.value, action=requested)
        return _result(True, "allowed", "readonly_gate_passed", mode=parsed.value, dispatch=True)
    if not isinstance(approval, Mapping):
        return _result(False, "approval_required", "approval_missing", mode=parsed.value)
    try:
        decision = check_approval(
            approval=approval, policy_snapshot=data.get("policy_snapshot", data.get("policy_ref")),
            required=True, assessment_id=data["assessment_id"], phase=data["phase"],
            target_ref=data["target_ref"], scope_confirmed=True,
            stop_active=bool(data.get("stop_active", False)),
        )
    except Exception:
        return _result(False, "approval_required", "approval_required", mode=parsed.value)
    if not decision.approved:
        return _result(False, "approval_required", "approval_required", mode=parsed.value)
    return _result(True, "allowed", "active_gate_passed", mode=parsed.value, dispatch=True)


readonly_gate = gate_graph_execution
active_gate = gate_graph_execution


def _identity(assessment_id: Any, run_id: Any, owner: Any, token: Any) -> bool:
    return all(isinstance(x, str) and bool(x.strip()) for x in (assessment_id, owner, token)) and (run_id is None or isinstance(run_id, str))


def acquire_run_ownership(path: str | Path, assessment_id: str, run_id: str, owner: str, ttl_seconds: float, *, token: str, now: float | None = None) -> dict[str, Any]:
    """Use the same assessment_id resource key as OrchestrationRuntime; run_id is metadata only."""
    if not _identity(assessment_id, run_id, owner, token):
        return _result(False, "rejected", "invalid_identity")
    resource = assessment_id
    try:
        result = LocalLeaseStore(Path(path)).acquire(resource, owner, ttl_seconds, token=token, now=now)
    except Exception as exc:
        return _result(False, "error", "lease_store_error", resource=resource, detail=type(exc).__name__)
    return {**result, "resource": resource, "assessment_id": assessment_id, "run_id": run_id, "owner": owner}


def release_run_ownership(path: str | Path, assessment_id: str, run_id: str, owner: str, *, token: str, now: float | None = None) -> dict[str, Any]:
    if not _identity(assessment_id, run_id, owner, token):
        return _result(False, "rejected", "invalid_identity")
    resource = assessment_id
    try:
        result = LocalLeaseStore(Path(path)).release(resource, owner, token=token, now=now)
    except Exception as exc:
        return _result(False, "error", "lease_store_error", resource=resource, detail=type(exc).__name__)
    return {**result, "resource": resource, "assessment_id": assessment_id, "run_id": run_id, "owner": owner}


__all__ = ["resolve_mode", "normalize_blocked_actions", "gate_graph_execution", "readonly_gate", "active_gate", "acquire_run_ownership", "release_run_ownership"]
