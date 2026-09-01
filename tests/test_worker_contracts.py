from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    return json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))


def validate_result(result: dict) -> list[str]:
    errors = []
    if result.get("worker_type") in {"code", "analyst"} and result.get("finding_status") in {"proven", "confirmed"}:
        errors.append("non-verifier cannot confirm")
    gate = result.get("gate") or {}
    if result.get("disposition") == "verified" and not gate.get("dual_result_satisfied"):
        errors.append("dual result gate unsatisfied")
    if result.get("worker_type") == "analyst":
        required = ("facts_used", "reasoning_summary", "alternative_explanations", "hypotheses", "unknowns", "coverage", "not_tested", "next_hints")
        errors.extend(f"missing analyst field: {key}" for key in required if key not in result)
    return errors


def base_result(worker_type="code"):
    result = {"result_id": "result_demo", "task_id": "task_demo", "worker_id": f"worker_{worker_type}", "worker_type": worker_type, "status": "ok", "created_at": "2026-09-01T00:00:00+00:00", "lineage": {"assessment_id": "asmt_demo", "correlation_id": "corr_demo", "parent_id": None}, "gate": {"code_result_id": "result_demo", "analyst_result_id": "result_analyst", "verifier_result_id": "result_verifier", "dual_result_satisfied": worker_type == "verifier"}}
    if worker_type == "analyst":
        result.update({"facts_used": [], "reasoning_summary": "summary", "alternative_explanations": [], "hypotheses": [], "unknowns": [], "coverage": {}, "not_tested": [], "next_hints": []})
    return result


def test_manifest_and_task_contracts_have_control_refs():
    manifest = load("worker_manifest_schema.json")
    task = load("task_envelope_schema.json")
    assert "permissions" in manifest["required"]
    assert "idempotency_key" in task["required"]
    assert task["properties"]["action"]["enum"] == ["offline", "read_only", "metadata"]


def test_code_result_is_not_confirmation():
    result = base_result("code")
    result["finding_status"] = "proven"
    assert "non-verifier cannot confirm" in validate_result(result)


def test_analyst_requires_complete_structured_analysis():
    result = base_result("analyst")
    del result["hypotheses"]
    assert "missing analyst field: hypotheses" in validate_result(result)


def test_verifier_requires_dual_result_gate():
    result = base_result("verifier")
    result["disposition"] = "verified"
    result["gate"]["dual_result_satisfied"] = False
    assert "dual result gate unsatisfied" in validate_result(result)

@pytest.mark.parametrize("error_class", ["timeout", "cancelled", "permission_denied", "blocked", "scope_conflict"])
def test_error_and_checkpoint_states_are_explicit(error_class):
    assert error_class in load("worker_error_schema.json")["properties"]["error_class"]["enum"]
    assert "cancelled" in load("checkpoint_schema.json")["properties"]["status"]["enum"]


def test_checkpoint_cursor_files_are_explicitly_separate():
    values = load("checkpoint_schema.json")["properties"]["status_file"]["enum"]
    assert values[:2] == ["phase_status.json", "phase_status.miniapp.json"]


def test_worker_error_has_safe_fields_only():
    properties = load("worker_error_schema.json")["properties"]
    assert "safe_reason" in properties
    assert "traceback" not in properties
    assert "raw_response" not in properties
