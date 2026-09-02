from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from authorized_assessment.orchestration.xcx_graph import XCX_CURSOR_FILE, XCX_PHASE_WORKERS, XCX_PHASES

ROOT = Path(__file__).resolve().parents[1]


def schema():
    return json.loads((ROOT / "contracts" / "xcx_worker_result_schema.json").read_text(encoding="utf-8"))


def base(worker_type="code"):
    value = {"result_id": "result_demo", "task_id": "task_demo", "worker_id": f"worker_xcx_identity_{worker_type}", "worker_type": worker_type, "status": "ok", "created_at": "2026-09-01T00:00:00+00:00", "workflow": "xcx", "cursor_file": XCX_CURSOR_FILE, "phase": "identity", "facts": [], "artifact_refs": [], "coverage": {}, "not_tested": [], "lineage": {"assessment_id": "assessment_xcx", "correlation_id": "corr_identity", "parent_id": None}, "gate": {"code_result_id": None, "analyst_result_id": None, "verifier_result_id": None, "dual_result_satisfied": False}}
    if worker_type == "analyst":
        value.update({"facts_used": [], "reasoning_summary": "offline", "alternative_explanations": [], "hypotheses": [], "unknowns": [], "next_hints": []})
    return value


def test_schema_accepts_code_analyst_and_verifier_shapes():
    validator = Draft202012Validator(schema())
    for kind in ("code", "analyst", "verifier"):
        value = base(kind)
        if kind == "verifier":
            value["gate"] = {"code_result_id": "result_code", "analyst_result_id": "result_analyst", "verifier_result_id": "result_demo", "dual_result_satisfied": True}
            value["disposition"] = "verified"
        assert list(validator.iter_errors(value)) == []


@pytest.mark.parametrize("field", ["workflow", "cursor_file", "worker_id", "phase", "lineage", "gate"])
def test_result_rejects_invalid_required_fields(field):
    value = base()
    value.pop(field)
    assert list(Draft202012Validator(schema()).iter_errors(value))


def test_analyst_requires_structured_analysis_and_dual_gate_is_explicit():
    value = base("analyst")
    value.pop("hypotheses")
    assert list(Draft202012Validator(schema()).iter_errors(value))
    verifier = base("verifier")
    verifier["disposition"] = "verified"
    assert verifier["gate"]["dual_result_satisfied"] is False


def test_worker_bindings_cover_every_xcx_phase_with_three_roles():
    assert tuple(XCX_PHASE_WORKERS) == XCX_PHASES
    assert all(len(roles) == 3 and all(worker.startswith("worker_xcx_") for worker in roles) for roles in XCX_PHASE_WORKERS.values())
