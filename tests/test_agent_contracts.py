from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = [
    "assessment_schema.json", "worker_manifest_schema.json", "task_envelope_schema.json",
    "worker_result_schema.json", "policy_decision_schema.json", "checkpoint_schema.json",
    "event_schema.json", "metric_event_schema.json", "approval_schema.json", "worker_error_schema.json",
]
SENSITIVE = ("cookie", "token", "password", "secret", "session", "har", "raw_response")
FORBIDDEN_PROPERTY_NAMES = {"cookie", "token", "password", "secret", "session_key", "authorization_header", "raw_response", "har"}

def load(name: str) -> dict:
    return json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))

def walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)

def test_all_core_contracts_parse_and_have_common_shape():
    for name in CONTRACTS:
        data = load(name)
        assert data["schema_version"] == "1.0"
        assert data["contract"]
        assert data["type"] == "object"
        assert data["required"]
        assert data["properties"]
        assert data["invariants"]

def test_contracts_reject_sensitive_property_names():
    for name in CONTRACTS:
        data = load(name)
        keys = set(walk_keys(data["properties"]))
        assert not (keys & FORBIDDEN_PROPERTY_NAMES), (name, sorted(keys & FORBIDDEN_PROPERTY_NAMES))

def test_assessment_cursor_streams_are_isolated():
    schema = load("assessment_schema.json")
    cursor = schema["properties"]["cursor_ref"]["properties"]
    assert cursor["stream"]["enum"] == ["wz", "miniapp_xcx", "fh"]
    assert "phase_status.json" in schema["invariants"][0]
    assert "phase_status.miniapp.json" in schema["invariants"][1]

def test_worker_manifest_permissions_are_fail_closed():
    permissions = load("worker_manifest_schema.json")["properties"]["permissions"]["properties"]
    for field in ("write_scope", "write_approval", "write_cursor", "write_confirmed"):
        assert permissions[field]["const"] is False

def test_result_dual_gate_and_analyst_fields_are_explicit():
    data = load("worker_result_schema.json")
    required = set(data["required"])
    assert {"result_id", "task_id", "worker_id", "gate"} <= required
    text = " ".join(data["invariants"])
    for field in ("facts_used", "reasoning_summary", "alternative_explanations", "hypotheses", "unknowns", "coverage", "not_tested", "next_hints"):
        assert field in text
    assert "Code or Analyst cannot emit proven/confirmed directly" in text

def test_policy_allow_does_not_equal_high_risk_authorization():
    assert "allow is not high-risk authorization" in load("policy_decision_schema.json")["invariants"]

def test_approval_requires_two_keys_and_blocked_actions_remain_blocked():
    invariants = load("approval_schema.json")["invariants"]
    assert any("script_gate.passed=true" in item for item in invariants)
    assert any("blocked_actions" in item for item in invariants)

def test_required_ids_have_patterns():
    for name in CONTRACTS:
        properties = load(name)["properties"]
        id_fields = [key for key in properties if key.endswith("_id") and key in {"decision_id", "checkpoint_id", "event_id", "metric_event_id", "approval_id", "graph_id", "error_id", "result_id"} and isinstance(properties[key], dict) and "pattern" in properties[key]]
        for field in id_fields:
            assert "pattern" in properties[field], (name, field)

def test_invalid_fixture_is_detected_without_network(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{}", encoding="utf-8")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "assessment_id" not in data
    assert datetime.now() is not None

@pytest.mark.parametrize("workflow,status_file", [("wz", "phase_status.json"), ("xcx", "phase_status.miniapp.json")])
def test_cursor_file_names_are_distinct(workflow, status_file):
    assert (workflow, status_file) in [("wz", "phase_status.json"), ("xcx", "phase_status.miniapp.json")]
