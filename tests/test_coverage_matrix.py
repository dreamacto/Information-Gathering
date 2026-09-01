"""tests/test_coverage_matrix.py —— 测试维度/覆盖子状态契约测试（Batch 5 / 规格 10.x + 5.2 + 13.2）。

覆盖：
  - 契约 ↔ 实现常量无漂移（16 字段、六状态、5.2 七字段）；
  - 正例行通过；聚合覆盖率钳制 [0,1]；
  - 13.2 负例：not_applicable 无 reason、非法子状态、coverage>1（行数矛盾拒绝）、
    哈希字段明文凭证、未知字段、缺 evidence_ref、未做适用性判定宣称不适用。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from authorized_assessment.analysis import coverage_matrix as cm

ROOT = Path(__file__).resolve().parents[1]
DIMENSIONS_CONTRACT = ROOT / "contracts" / "test_dimensions_schema.json"
SUBSTATUS_CONTRACT = ROOT / "contracts" / "coverage_substatus_schema.json"

SPEC_101_FIELDS = [
    "role",
    "account_ref_hash",
    "tenant",
    "object_ref_hash",
    "api_version",
    "client_version",
    "device",
    "workflow_state",
    "http_method",
    "content_type",
    "feature_flag",
    "authentication_state",
    "branch",
    "status",
    "reason",
    "evidence_ref",
]

SPEC_102_SUBSTATUSES = [
    "tested",
    "not_applicable",
    "blocked",
    "approval_required",
    "needs_manual_validation",
    "inconclusive",
]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _dimension_row(**overrides: object) -> dict:
    base = {
        "role": "anonymous",
        "account_ref_hash": cm.ref_hash("user-1"),
        "tenant": "",
        "object_ref_hash": "",
        "api_version": "v1",
        "client_version": "",
        "device": "desktop",
        "workflow_state": "",
        "http_method": "GET",
        "content_type": "application/json",
        "feature_flag": "",
        "authentication_state": "unauthenticated",
        "branch": "main",
        "status": "tested",
        "reason": "",
        "evidence_ref": "runs/x/probe_results.jsonl",
    }
    base.update(overrides)
    return base


def _map_row(**overrides: object) -> dict:
    base = {
        "applicable": "applicable",
        "status": "tested",
        "source": "run:runs/x/api_confirmed.jsonl",
        "asset": "https://example.gov.cn",
        "endpoint_or_surface": "/api/graphql",
        "reason": "",
        "evidence_ref": "runs/x/api_confirmed.jsonl",
    }
    base.update(overrides)
    return base


# ---------- 契约 ↔ 实现无漂移 ----------


def test_dimensions_contract_matches_module_constants():
    contract = _load(DIMENSIONS_CONTRACT)
    assert contract["required_fields"] == SPEC_101_FIELDS
    assert list(cm.TEST_DIMENSION_FIELDS) == SPEC_101_FIELDS
    assert contract["status_values"] == SPEC_102_SUBSTATUSES


def test_substatus_contract_matches_module_constants():
    contract = _load(SUBSTATUS_CONTRACT)
    assert contract["status_values"] == SPEC_102_SUBSTATUSES
    assert list(cm.COVERAGE_SUBSTATUSES) == SPEC_102_SUBSTATUSES
    assert contract["application_map_row_required_fields"] == list(cm.APPLICATION_MAP_ROW_FIELDS)
    assert contract["aggregate_example"]["substatuses"] == {
        "api_schema_versions": "tested",
        "object_authorization": "tested",
        "field_authorization": "needs_manual_validation",
        "graphql": "not_applicable",
        "websocket": "blocked",
        "pagination": "tested",
        "third_party_api": "inconclusive",
    }


def test_two_contracts_share_status_enum():
    assert _load(DIMENSIONS_CONTRACT)["status_values"] == _load(SUBSTATUS_CONTRACT)["status_values"]


# ---------- 正例 ----------


def test_valid_dimension_row_passes():
    assert cm.validate_test_dimensions_row(_dimension_row()) == []


def test_valid_application_map_row_passes():
    assert cm.validate_application_map_row(_map_row()) == []


def test_coverage_ratio_clamped_to_one():
    assert cm.coverage_ratio(2, 2) == 1.0
    assert cm.coverage_ratio(1, 3) == pytest.approx(1 / 3, abs=1e-4)
    assert cm.coverage_ratio(0, 0) == 0.0


def test_aggregate_substatuses_example_from_spec_passes():
    normalized, violations = cm.aggregate_substatuses(
        _load(SUBSTATUS_CONTRACT)["aggregate_example"]["substatuses"]
    )
    assert violations == []
    assert normalized["graphql"] == "not_applicable"
    assert normalized["third_party_api"] == "inconclusive"


def test_ref_hash_is_irreversible_sha256():
    digest = cm.ref_hash("user-42@example.gov.cn")
    assert len(digest) == 64
    int(digest, 16)  # 纯十六进制
    assert "user-42" not in digest


# ---------- 负例（13.2） ----------


def test_not_applicable_without_reason_flagged():
    row = _dimension_row(status="not_applicable")
    violations = cm.validate_test_dimensions_row(row)
    assert any("reason 为空" in v for v in violations)
    row_map = _map_row(applicable="not_applicable", status="not_applicable", evidence_ref="")
    assert any("reason 为空" in v for v in cm.validate_application_map_row(row_map))


def test_invalid_substatus_flagged():
    violations = cm.validate_test_dimensions_row(_dimension_row(status="done"))
    assert any("status 非法" in v and "done" in v for v in violations)


def test_coverage_greater_than_one_rejected():
    """13.2 负例：coverage > 1（tested 超过总数）必须拒绝而非静默钳制。"""
    with pytest.raises(ValueError) as excinfo:
        cm.coverage_ratio(3, 2)
    assert "tested(3) > total(2)" in str(excinfo.value)
    with pytest.raises(ValueError):
        cm.coverage_ratio(-1, 5)


def test_plaintext_in_hash_field_flagged():
    row = _dimension_row(account_ref_hash="cookie: session=abcdef123456")
    violations = cm.validate_test_dimensions_row(row)
    assert any("sha256" in v for v in violations)
    row2 = _dimension_row(object_ref_hash="password=SuperSecret123")
    assert any("sha256" in v or "明文" in v for v in cm.validate_test_dimensions_row(row2))


def test_unknown_field_flagged():
    row = _dimension_row(extra_dimension="x")
    assert any("未知字段" in v and "extra_dimension" in v for v in cm.validate_test_dimensions_row(row))


def test_missing_required_field_flagged():
    row = _dimension_row()
    del row["authentication_state"]
    assert any("authentication_state" in v for v in cm.validate_test_dimensions_row(row))


def test_tested_without_evidence_ref_flagged():
    row = _dimension_row(evidence_ref="")
    violations = cm.validate_test_dimensions_row(row)
    assert any("evidence_ref 为空" in v for v in violations)


def test_map_row_not_applicable_without_applicability_flagged():
    """10.3：未做适用性判定（applicable 仍为 applicable）不得宣称 status=not_applicable。"""
    row = _map_row(status="not_applicable", reason="GraphQL 端点未发现")
    violations = cm.validate_application_map_row(row)
    assert any("适用性判定" in v for v in violations)


def test_map_row_missing_min_field_flagged():
    row = _map_row()
    del row["endpoint_or_surface"]
    assert any("endpoint_or_surface" in v for v in cm.validate_application_map_row(row))


def test_blocked_without_next_step_reason_flagged():
    row = _dimension_row(status="blocked", evidence_ref="")
    assert any("reason" in v for v in cm.validate_test_dimensions_row(row))


def test_aggregate_rejects_bad_status():
    _, violations = cm.aggregate_substatuses({"graphql": "skipped"})
    assert any("子状态非法" in v and "skipped" in v for v in violations)


# ---------- 纯度 ----------


def test_validators_are_readonly_and_deterministic(tmp_path):
    row = _dimension_row()
    map_row = _map_row()
    first = (
        cm.validate_test_dimensions_row(row),
        cm.validate_application_map_row(map_row),
        cm.aggregate_substatuses({"graphql": "not_applicable"}),
    )
    second = (
        cm.validate_test_dimensions_row(row),
        cm.validate_application_map_row(map_row),
        cm.aggregate_substatuses({"graphql": "not_applicable"}),
    )
    assert first == second
    assert first[0] == [] and first[1] == []
    assert not (tmp_path / "anything").exists()
