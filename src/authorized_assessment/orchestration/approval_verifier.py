"""Offline, fail-closed verification of two-key approval records."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from authorized_assessment.runtime.policy_snapshot import (
    validate_policy_snapshot,
)

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "contracts" / "approval_schema.json"
APPROVAL_ACTIONS = ("credential_testing", "sqlmap_single_candidate", "shiro_single_candidate", "write_endpoint", "upload", "delete", "import_export", "transaction", "race_write", "other_gated")
DECISIONS = ("deny", "approved", "expired", "revoked", "blocked")


def _err(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def validate_approval(approval: Any) -> list[dict[str, str]]:
    """Validate shape and invariants, returning path-level safe errors."""
    errors: list[dict[str, str]] = []
    if not isinstance(approval, dict):
        return [_err("approval_not_object", "approval must be an object")]
    required = ("approval_id", "requested_action", "assessment_id", "phase", "target_ref", "roe_ref", "script_gate", "human_confirmation", "decision", "created_at")
    for field in required:
        if field not in approval:
            errors.append(_err("missing_field", f"missing required field: {field}"))
    if errors:
        return errors
    if not isinstance(approval["approval_id"], str) or not approval["approval_id"].startswith("approval_"):
        errors.append(_err("invalid_approval_id", "approval_id has invalid format"))
    if approval["requested_action"] not in APPROVAL_ACTIONS:
        errors.append(_err("invalid_action", "requested_action is not in approval schema enum"))
    if approval["decision"] not in DECISIONS:
        errors.append(_err("invalid_decision", "decision is not in approval schema enum"))
    for field in ("assessment_id", "phase", "created_at"):
        if not isinstance(approval[field], str) or not approval[field].strip():
            errors.append(_err("invalid_field", f"{field} must be a non-empty string"))
    for field in ("target_ref", "roe_ref"):
        value = approval[field]
        if not isinstance(value, dict) or not isinstance(value.get("path"), str) or not isinstance(value.get("sha256"), str) or len(value["sha256"]) != 64:
            errors.append(_err("invalid_reference", f"{field} must contain path and sha256"))
    for field, child in (("script_gate", ("passed", "checked_at")), ("human_confirmation", ("confirmed", "confirmed_at"))):
        value = approval[field]
        if not isinstance(value, dict):
            errors.append(_err("invalid_gate", f"{field} must be an object"))
            continue
        for name in child:
            if name not in value:
                errors.append(_err("missing_field", f"missing required field: {field}.{name}"))
        if "passed" in value and field == "script_gate" and not isinstance(value["passed"], bool):
            errors.append(_err("invalid_gate", "script_gate.passed must be boolean"))
        if "confirmed" in value and field == "human_confirmation" and not isinstance(value["confirmed"], bool):
            errors.append(_err("invalid_gate", "human_confirmation.confirmed must be boolean"))
        if any(name in value and _parse_time(value[name]) is None for name in child if name.endswith("_at")):
            errors.append(_err("invalid_timestamp", f"{field} timestamp must be ISO-8601"))
    if _parse_time(approval["created_at"]) is None:
        errors.append(_err("invalid_timestamp", "created_at must be ISO-8601"))
    if approval.get("expires_at") is not None and _parse_time(approval["expires_at"]) is None:
        errors.append(_err("invalid_timestamp", "expires_at must be ISO-8601 or null"))
    return errors


def verify_approval(
    approval: Mapping[str, Any] | None,
    policy_snapshot: Mapping[str, Any] | None,
    *,
    assessment_id: str | None = None,
    phase: str | None = None,
    target_ref: Mapping[str, Any] | None = None,
    now: datetime | None = None,
    seen_approval_ids: set[str] | frozenset[str] | None = None,
    scope_confirmed: bool = True,
    stop_active: bool = False,
) -> dict[str, Any]:
    """Return a safe decision; only an exact, live two-key approval can pass."""
    errors = validate_approval(approval)
    violations = list(errors)
    policy_errors = validate_policy_snapshot(policy_snapshot)
    if policy_errors:
        violations.append(_err("policy_invalid", "policy snapshot failed validation"))
    p = dict(policy_snapshot or {})
    a = dict(approval or {})
    action = a.get("requested_action")
    if action in set(p.get("blocked_actions") or []):
        violations.append(_err("blocked_action", "requested action is blocked by policy"))
    if assessment_id is not None and a.get("assessment_id") != assessment_id:
        violations.append(_err("assessment_mismatch", "approval assessment binding mismatch"))
    if phase is not None and a.get("phase") != phase:
        violations.append(_err("phase_mismatch", "approval phase binding mismatch"))
    if target_ref is not None and a.get("target_ref") != dict(target_ref):
        violations.append(_err("target_mismatch", "approval target binding mismatch"))
    if seen_approval_ids and a.get("approval_id") in seen_approval_ids:
        violations.append(_err("duplicate_approval", "approval_id was already used"))
    if scope_confirmed is not True or p.get("authorization_status") != "confirmed":
        violations.append(_err("scope_unconfirmed", "approval cannot confirm or expand scope"))
    if stop_active or bool(p.get("stop_active", False)):
        violations.append(_err("stop_active", "approval cannot解除 active stop state"))
    if a.get("decision") == "approved":
        if a.get("script_gate", {}).get("passed") is not True:
            violations.append(_err("script_gate_failed", "approved requires script gate"))
        if a.get("human_confirmation", {}).get("confirmed") is not True:
            violations.append(_err("human_confirmation_missing", "approved requires human confirmation"))
        expires = _parse_time(a.get("expires_at"))
        current = now or datetime.now(timezone.utc)
        if expires is not None and expires <= current:
            violations.append(_err("approval_expired", "approval has expired"))
    if a.get("decision") != "approved":
        violations.append(_err("not_approved", "approval decision is not approved"))
    return {"decision": "approved" if not violations else "blocked", "valid": not violations, "violations": violations}


def evaluate_approval(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return verify_approval(*args, **kwargs)

__all__ = ["validate_approval", "verify_approval", "evaluate_approval"]
