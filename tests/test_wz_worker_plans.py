import pytest
from authorized_assessment.analysis.wz_worker_plans import build_wz_worker_plan


def snapshot():
    return {
        "workflow": "wz", "status_file": "phase_status.json",
        "cursor": {"current_phase": "application_mapping"},
        "target_model": {"current_facts": ["structured fingerprint"]},
        "coverage": {"application_mapping": {"substatuses": {"graphql_mapping": "pending"}}},
        "candidate_index": [], "ledger_index": [], "phase_summary": {},
        "artifact_refs": [], "not_tested": ["authenticated review"],
        "historical_inputs": [{"classification": "historical_lead", "ref": "lead-1"}],
    }


def test_plan_contains_five_branches_and_full_analyst_fields():
    result = build_wz_worker_plan(snapshot())
    assert [row["phase"] for row in result["fan_out"]] == [
        "graphql_mapping", "websocket_mapping", "file_surface_mapping", "auth_surface_mapping", "webhook_mapping"
    ]
    for field in ("facts_used", "reasoning_summary", "alternative_explanations", "hypotheses", "unknowns", "coverage", "not_tested", "next_hints"):
        assert field in result
    assert result["current_coverage_from_history"] is False


def test_plan_rejects_incomplete_or_cross_workflow_context():
    with pytest.raises(ValueError):
        build_wz_worker_plan({})
    bad = snapshot(); bad["workflow"] = "fh"
    with pytest.raises(ValueError):
        build_wz_worker_plan(bad)
    bad = snapshot(); bad["historical_inputs"] = [{"classification": "current_facts"}]
    with pytest.raises(ValueError):
        build_wz_worker_plan(bad)


def test_plan_rejects_sensitive_snapshot():
    bad = snapshot(); bad["phase_summary"] = {"token": "redacted"}
    with pytest.raises(ValueError):
        build_wz_worker_plan(bad)
