from __future__ import annotations

import json
from pathlib import Path

import pytest

from authorized_assessment.orchestration.compatibility_mode import (
    acquire_run_ownership,
    gate_graph_execution,
    normalize_blocked_actions,
    release_run_ownership,
)
from authorized_assessment.orchestration.feature_flags import (
    OrchestrationMode,
    can_transition,
    deserialize_snapshot,
    mode_snapshot,
    parse_mode,
)


def _context() -> dict:
    ref = {"kind": "local", "path": "fixture", "sha256": "0" * 64}
    return {
        "assessment_id": "assessment-test",
        "phase": "offline",
        "target_ref": ref,
        "policy_ref": ref,
        "scope_ref": ref,
        "scope_confirmed": True,
        "policy_valid": True,
        "cursor_valid": True,
    }


def test_modes_default_and_snapshot_round_trip():
    assert parse_mode() is OrchestrationMode.LEGACY
    snapshot = mode_snapshot("graph_readonly", metadata={"legacy_mode": "full"})
    restored = deserialize_snapshot(snapshot.to_json())
    assert restored.to_dict() == snapshot.to_dict()
    assert snapshot.snapshot_hash == restored.snapshot_hash


def test_transition_is_single_step_only():
    assert can_transition("legacy", "graph_shadow")
    assert can_transition("graph_shadow", "graph_readonly")
    assert not can_transition("legacy", "graph_readonly")
    assert can_transition("graph_readonly", "graph_active_approved")
    assert not can_transition("graph_active_approved", "legacy")


def test_sensitive_snapshot_fields_rejected():
    with pytest.raises(ValueError):
        mode_snapshot("legacy", metadata={"cookie": "never"})
    with pytest.raises(ValueError):
        mode_snapshot("legacy", metadata={"nested": {"raw_response": "never"}})


def test_blocked_actions_normalize_and_take_precedence():
    assert normalize_blocked_actions([" password-spray ", "READONLY"]) == frozenset({"password_spray", "read_only"})
    result = gate_graph_execution("legacy", _context(), action=" password-spray ", blocked_actions=["PASSWORD-SPRAY"])
    assert result["ok"] is False
    assert result["reason"] == "blocked_action"


def test_nonlegacy_requires_action_and_context():
    assert gate_graph_execution("graph_shadow", {}, action=None)["status"] == "blocked"
    result = gate_graph_execution("graph_readonly", {"action": "offline"})
    assert result["status"] == "blocked"
    assert gate_graph_execution("graph_readonly", {**_context(), "action": "probe"})["status"] == "blocked"
    assert gate_graph_execution("graph_readonly", {**_context(), "action": "offline"})["ok"]


def test_active_requires_two_key_bound_approval():
    context = {**_context(), "action": "offline"}
    missing = gate_graph_execution("graph_active_approved", context)
    assert missing["status"] == "approval_required"
    malformed = gate_graph_execution("graph_active_approved", context, approval={"decision": "approved"})
    assert malformed["status"] == "approval_required"


def test_ownership_conflict_and_release_are_fail_closed(tmp_path: Path):
    lease = tmp_path / "leases.json"
    first = acquire_run_ownership(lease, "assessment-x", "run-a", "owner-a", 30, token="token-a", now=100)
    assert first["ok"]
    second = acquire_run_ownership(lease, "assessment-x", "run-b", "owner-b", 30, token="token-b", now=101)
    assert second["status"] == "conflict"
    wrong = release_run_ownership(lease, "assessment-x", "run-a", "owner-b", token="token-a", now=101)
    assert wrong["status"] == "forbidden"
    released = release_run_ownership(lease, "assessment-x", "run-a", "owner-a", token="token-a", now=101)
    assert released["ok"]


def test_ownership_invalid_and_expired(tmp_path: Path):
    lease = tmp_path / "leases.json"
    assert acquire_run_ownership(lease, "", "run", "owner", 30, token="x")["status"] == "rejected"
    acquired = acquire_run_ownership(lease, "assessment-y", "run", "owner", 1, token="x", now=10)
    assert acquired["ok"]
    expired = acquire_run_ownership(lease, "assessment-y", "run2", "owner2", 30, token="y", now=12)
    assert expired["ok"]


def test_no_sensitive_values_in_serialized_snapshot():
    payload = json.dumps(mode_snapshot("graph_shadow", legacy_mode="subdomains").to_dict())
    assert all(word not in payload.lower() for word in ("cookie", "token", "password", "session", "har", "raw_response"))
