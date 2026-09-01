from __future__ import annotations

from datetime import datetime, timezone

from authorized_assessment.orchestration.approval_verifier import verify_approval
from authorized_assessment.orchestration.context_verifier import verify_context


def _policy(**overrides):
    p = {
        "schema_version": "1.0", "engagement_id": None, "workflow": "wz", "phase": "p",
        "authorization_status": "confirmed", "active_testing_authorized": True,
        "allowed_actions": ["offline_analysis", "readonly_get"], "blocked_actions": ["webshell"],
        "approval_required": [], "rate_policy": {"same_host_delay_seconds": 2, "same_host_concurrency": 1, "cross_host_worker_limit": 3},
        "stop_conditions": ["operator_stop_request"], "source_hashes": {"x": "a"}, "generated_at": "2026-09-02T00:00:00+00:00",
    }
    p.update(overrides)
    return p


def _approval(**overrides):
    a = {
        "approval_id": "approval_test1", "requested_action": "race_write", "assessment_id": "a1", "phase": "p1",
        "target_ref": {"path": "target.json", "sha256": "a" * 64}, "roe_ref": {"path": "ROE.md", "sha256": "b" * 64},
        "script_gate": {"passed": True, "checked_at": "2026-09-01T00:00:00+00:00"},
        "human_confirmation": {"confirmed": True, "confirmed_at": "2026-09-01T00:00:00+00:00"},
        "decision": "approved", "expires_at": "2026-12-01T00:00:00+00:00", "created_at": "2026-09-01T00:00:00+00:00",
    }
    a.update(overrides)
    return a


def test_approval_requires_both_keys_and_bindings():
    result = verify_approval(_approval(), _policy(), assessment_id="a1", phase="p1", target_ref=_approval()["target_ref"], now=datetime(2026, 9, 2, tzinfo=timezone.utc))
    assert result["valid"]
    denied = verify_approval(_approval(script_gate={"passed": False, "checked_at": "2026-09-01T00:00:00+00:00"}), _policy())
    assert not denied["valid"]
    assert "script_gate_failed" in {v["code"] for v in denied["violations"]}


def test_approval_blocked_action_and_expiry_fail_closed():
    blocked = verify_approval(_approval(requested_action="webshell"), _policy(blocked_actions=["webshell"]))
    assert blocked["decision"] == "blocked"
    expired = verify_approval(_approval(expires_at="2026-09-01T00:00:00+00:00"), _policy(), now=datetime(2026, 9, 2, tzinfo=timezone.utc))
    assert "approval_expired" in {v["code"] for v in expired["violations"]}


def test_context_conflict_and_cursor_isolation_fail_closed():
    snapshot = {
        "task_type": "review", "workflow": "wz", "phase": None, "engagement_id": None,
        "loaded_sources": [], "source_hashes": {}, "policy_digest": _policy(), "current_facts": [],
        "historical_inputs": [], "excluded_sources": [], "context_conflicts": ["scope_not_confirmed:x"], "created_at": "2026-09-02T00:00:00+00:00",
    }
    result = verify_context(snapshot, _policy(), cursor={"filename": "phase_status.miniapp.json"})
    codes = {v["code"] for v in result["violations"]}
    assert "context_conflict" in codes
    assert "cursor_isolation" in codes


def test_context_rejects_sensitive_keys_without_echoing_value():
    secret = "DO_NOT_ECHO"
    snapshot = {"cookie": secret}
    result = verify_context(snapshot)
    assert all(secret not in v["detail"] for v in result["violations"])
