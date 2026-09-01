from __future__ import annotations

import pytest

from authorized_assessment.runtime.recovery import (
    CURSORS,
    canonical_hash,
    plan_recovery,
)
from authorized_assessment.runtime.state_version import (
    SCHEMA_VERSION,
    StateVersion,
    bump_state_version,
    check_optimistic_version,
    compare_versions,
    validate_state_record,
)


def valid_state(**overrides):
    state = {
        "workflow": "wz",
        "policy": {"allowed": ["offline_analysis"], "blocked": ["webshell"]},
        "scope": {"targets": ["example.invalid"]},
        "context": {"phase": "fingerprint"},
        "cursor": {"workflow": "wz", "status_file": "phase_status.json", "sequence": 1},
        "events": [{"aggregate_sequence": 0}, {"aggregate_sequence": 1}],
        "lineage": [{"attempt_no": 1}],
        "idempotency": [{"status": "accepted"}],
    }
    for key in ("policy", "scope", "context"):
        state[f"{key}_hash"] = canonical_hash(state[key])
    state.update(overrides)
    return state


def test_complete_wz_recovery_is_resume_only():
    result = plan_recovery(valid_state())
    assert result["status"] == "resume"
    assert result["actions"] == ["resume_from_cursor"]
    assert result["cursor"] == CURSORS["wz"]


def test_xcx_requires_miniapp_cursor():
    state = valid_state(workflow="xcx")
    state["cursor"] = {"workflow": "xcx", "status_file": "phase_status.miniapp.json", "sequence": 0}
    assert plan_recovery(state)["status"] == "resume"


def test_cross_workflow_cursor_blocks():
    state = valid_state(cursor={"workflow": "xcx", "status_file": "phase_status.miniapp.json", "sequence": 1})
    result = plan_recovery(state)
    assert result["status"] == "blocked"
    assert "cursor_workflow_mismatch" in result["errors"]


@pytest.mark.parametrize("field", ["policy_hash", "scope_hash", "context_hash"])
def test_missing_prior_hash_blocks(field):
    state = valid_state()
    state.pop(field)
    result = plan_recovery(state)
    assert result["status"] == "blocked"
    assert any(error.startswith("missing_") for error in result["errors"])


def test_hash_drift_blocks():
    state = valid_state()
    state["context"]["phase"] = "changed"
    assert "context_hash_drift" in plan_recovery(state)["errors"]


def test_event_sequence_gap_blocks():
    state = valid_state(events=[{"aggregate_sequence": 0}, {"aggregate_sequence": 2}])
    assert "event_sequence_gap" in plan_recovery(state)["errors"]


def test_cancel_timeout_and_blocked_are_fail_closed():
    for item in ({"status": "cancelled"}, {"status": "timeout"}, {"status": "blocked"}):
        state = valid_state(idempotency=[item])
        result = plan_recovery(state)
        assert result["status"] == "blocked"
        assert result["actions"] == []


def test_cancel_requested_blocks_without_execution():
    result = plan_recovery(valid_state(cancel_requested=True))
    assert result["status"] == "blocked"
    assert result["actions"] == []


def test_invalid_and_missing_control_plane_data_blocks():
    result = plan_recovery({"workflow": "wz"})
    assert result["status"] == "blocked"
    assert result["actions"] == []


def test_recovery_does_not_call_or_write():
    state = valid_state()
    result = plan_recovery(state)
    assert set(result) >= {"status", "reason", "errors", "actions"}
    assert all("request" not in action and "write" not in action for action in result["actions"])


def test_state_version_is_distinct_from_schema_version():
    value = StateVersion("task_1", 3)
    assert value.schema_version == SCHEMA_VERSION
    assert value.state_version == 3
    assert value.to_dict() == {"entity_id": "task_1", "schema_version": "1.0", "state_version": 3}


def test_compare_versions_and_monotonic_bump():
    assert compare_versions(2, 1) == 1
    assert compare_versions(1, 2) == -1
    assert compare_versions(2, 2) == 0
    result = bump_state_version(entity_id="task_1", current_version=2, expected_version=2)
    assert result["status"] == "updated"
    assert result["state_version"] == 3


def test_stale_expected_version_is_conflict_and_never_decrements():
    result = bump_state_version(entity_id="task_1", current_version=4, expected_version=3)
    assert result["status"] == "conflict"
    assert result["reason"] == "version_conflict"
    assert "state_version" not in result


def test_cross_entity_version_reuse_is_conflict():
    result = check_optimistic_version(entity_id="task_1", requested_entity_id="task_2",
                                      current_version=1, expected_version=1)
    assert result == {"status": "conflict", "reason": "entity_mismatch", "entity_id": "task_1"}


@pytest.mark.parametrize("bad", [-1, True, 1.2, "1"])
def test_versions_must_be_nonnegative_integers(bad):
    with pytest.raises(ValueError):
        compare_versions(bad, 0)


def test_state_record_validation_separates_schema_and_state_errors():
    assert validate_state_record({"schema_version": "1.0", "entity_id": "x", "state_version": 0}) == []
    errors = validate_state_record({"schema_version": "9.0", "entity_id": "x", "state_version": -1})
    assert "schema_version must be '1.0'" in errors
    assert "state_version must be a non-negative integer" in errors
