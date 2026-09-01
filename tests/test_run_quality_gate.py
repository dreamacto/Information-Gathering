"""run_quality_gate 契约与判定器测试（实施规格 3.2 / 13.1 / 13.2）。

覆盖：规格示例、六项强制门控逐项触发、五态各自可达、[0,1] 钳制与重复计数负例、
校验器正负例、阈值可配置、判定确定性。
"""
from __future__ import annotations

import copy

import pytest

from authorized_assessment.quality import (
    GATE_REASONS,
    QUALITY_STATUS_STATES,
    GateThresholds,
    evaluate_run_quality,
    load_schema,
    load_thresholds_overrides,
    validate_quality_report,
)


def _targets(n: int) -> list[str]:
    return [f"target-{i}" for i in range(n)]


def _ok_rows(targets: list[str]) -> list[dict]:
    return [{"target": t, "ok": True, "error_class": None} for t in targets]


# ---------------------------------------------------------------- 正例：规格示例形态


def test_spec_example_low_coverage_and_rate_limit_skips():
    targets = _targets(10)
    rows = _ok_rows(targets[:4])
    rows += [
        {"target": targets[4], "ok": False, "error_class": "timeout"},
        {"target": targets[5], "ok": False, "error_class": "connection"},
        {"target": targets[6], "ok": False, "error_class": "connection"},
        {"target": targets[7], "ok": False, "error_class": "waf"},
        {"target": targets[8], "ok": False, "error_class": "waf"},
        {"target": targets[9], "ok": False, "error_class": "rate_limit"},
    ]
    # rate_limit 行再补 2 条（不同探测尝试），使 rate_limit_skips=3/10=0.3 > 0.20
    rows.append({"target": targets[9], "ok": False, "error_class": "rate_limit"})
    rows.append({"target": targets[9], "ok": False, "error_class": "rate_limit"})

    report = evaluate_run_quality(targets, rows)
    assert report["quality_status"] == "INCONCLUSIVE"
    assert report["negative_conclusion_allowed"] is False
    assert report["unique_in_scope_targets"] == 10
    assert report["unique_targets_with_successful_probe"] == 4
    assert report["probe_coverage"] == pytest.approx(0.4)
    # 规格示例数值为示意（ok_ratio 0.4 与 3 传输错误/1 超时等计数在单一行集下互斥）；
    # 本行集 4 ok / 12 行 → 0.3333（实现按 4 位小数舍入），关键形态与门控原因和示例一致。
    assert report["probe_ok_ratio"] == pytest.approx(0.3333)
    assert report["transport_errors"] == 3
    assert report["dns_errors"] == 0
    assert report["timeouts"] == 1
    assert report["waf_blocks"] == 2
    assert report["rate_limit_skips"] == 3
    assert "probe_coverage_below_threshold" in report["quality_gate_reasons"]
    assert "rate_limit_skip_ratio_high" in report["quality_gate_reasons"]
    assert validate_quality_report(report) == []


def test_valid_run_allows_negative_conclusion():
    targets = _targets(10)
    report = evaluate_run_quality(targets, _ok_rows(targets))
    assert report["quality_status"] == "VALID"
    assert report["negative_conclusion_allowed"] is True
    assert report["probe_coverage"] == 1.0
    assert report["probe_ok_ratio"] == 1.0
    assert report["quality_gate_reasons"] == []


# ---------------------------------------------------------------- 六门逐项触发


def test_gate_probe_coverage_below_threshold():
    targets = _targets(10)
    report = evaluate_run_quality(targets, _ok_rows(targets[:8]))
    assert "probe_coverage_below_threshold" in report["quality_gate_reasons"]
    assert report["quality_status"] == "INCONCLUSIVE"
    assert report["negative_conclusion_allowed"] is False


def test_gate_probe_ok_ratio_below_threshold():
    targets = _targets(10)
    rows = _ok_rows(targets)
    rows += [{"target": targets[0], "ok": False, "error_class": "connection"} for _ in range(15)]
    # coverage = 10/10（每个目标至少一次成功），ok_rows = 10/25 = 0.4 < 0.5
    report = evaluate_run_quality(targets, rows)
    assert report["probe_coverage"] == pytest.approx(1.0)
    assert "probe_ok_ratio_below_threshold" in report["quality_gate_reasons"]
    assert "probe_coverage_below_threshold" not in report["quality_gate_reasons"]


def test_gate_rate_limit_skip_ratio_high():
    targets = _targets(10)
    rows = _ok_rows(targets)
    rows += [{"target": t, "ok": False, "error_class": "rate_limit"} for t in targets[:3]]
    report = evaluate_run_quality(targets, rows)
    assert report["probe_coverage"] == 1.0
    assert "rate_limit_skip_ratio_high" in report["quality_gate_reasons"]


def test_gate_transport_error_ratio_high():
    targets = _targets(10)
    rows = _ok_rows(targets[:6])
    rows += [{"target": t, "ok": False, "error_class": "connection"} for t in targets[6:]]
    report = evaluate_run_quality(targets, rows)
    assert "transport_error_ratio_high" in report["quality_gate_reasons"]
    assert report["transport_errors"] == 4


def test_gate_no_successful_probe_yields_failed():
    targets = _targets(10)
    rows = [{"target": t, "ok": False, "error_class": "timeout"} for t in targets]
    report = evaluate_run_quality(targets, rows)
    assert report["quality_status"] == "FAILED"
    assert "no_successful_probe" in report["quality_gate_reasons"]
    assert report["negative_conclusion_allowed"] is False


def test_gate_waf_block_ratio_exceeded():
    targets = _targets(10)
    rows = _ok_rows(targets[:9])
    rows += [{"target": targets[9], "ok": False, "error_class": "waf"}]
    rows += [{"target": targets[9], "ok": False, "error_class": "waf"}]
    # 2 条 waf / 11 行 ≈ 0.18 > 0.10 默认阈值；coverage = 9/10 = 0.90 恰好不触发 coverage 门
    report = evaluate_run_quality(targets, rows)
    assert "waf_block_ratio_exceeded" in report["quality_gate_reasons"]
    assert "probe_coverage_below_threshold" not in report["quality_gate_reasons"]
    assert report["waf_blocks"] == 2


# ---------------------------------------------------------------- 五态与边界


def test_blocked_run_is_blocked():
    targets = _targets(5)
    report = evaluate_run_quality(targets, _ok_rows(targets), blocked=True)
    assert report["quality_status"] == "BLOCKED"
    assert "run_blocked" in report["quality_gate_reasons"]
    assert report["negative_conclusion_allowed"] is False


def test_partial_run_below_threshold_degradation():
    # 门控全部未触发，但存在低于阈值的退化信号（1/10 transport 错误）
    targets = _targets(10)
    rows = _ok_rows(targets)
    rows.append({"target": targets[0], "ok": False, "error_class": "connection"})
    report = evaluate_run_quality(targets, rows)
    assert report["quality_status"] == "PARTIAL"
    assert report["quality_gate_reasons"] == []
    assert report["negative_conclusion_allowed"] is False


def test_no_in_scope_targets_is_not_valid():
    report = evaluate_run_quality([], [])
    assert report["quality_status"] != "VALID"
    assert "no_in_scope_targets" in report["quality_gate_reasons"]
    assert report["negative_conclusion_allowed"] is False


def test_coverage_clamped_to_unit_interval_duplicate_counting_forbidden():
    # 1 个 in-scope 目标 + 100 个范围外目标的成功探测 → 覆盖率恒为 1.0，不允许 2.0/101 类重复计数
    targets = ["in-scope-1"]
    rows = [{"target": "in-scope-1", "ok": True, "error_class": None}]
    rows += [{"target": f"out-{i}", "ok": True, "error_class": None} for i in range(100)]
    report = evaluate_run_quality(targets, rows)
    assert report["probe_coverage"] == 1.0
    assert report["unique_targets_with_successful_probe"] == 1
    assert validate_quality_report(report) == []


def test_out_of_scope_targets_do_not_count():
    targets = ["a", "b"]
    rows = [
        {"target": "a", "ok": True, "error_class": None},
        {"target": "out-x", "ok": True, "error_class": None},
    ]
    report = evaluate_run_quality(targets, rows)
    assert report["unique_in_scope_targets"] == 2
    assert report["unique_targets_with_successful_probe"] == 1
    assert report["probe_coverage"] == pytest.approx(0.5)


def test_evaluate_is_deterministic():
    targets = _targets(4)
    rows = _ok_rows(targets[:2]) + [
        {"target": targets[2], "ok": False, "error_class": "dns"},
    ]
    first = evaluate_run_quality(targets, rows)
    second = evaluate_run_quality(list(targets), copy.deepcopy(rows))
    assert first == second


def test_thresholds_can_be_overridden():
    targets = _targets(10)
    rows = _ok_rows(targets[:8])
    default = evaluate_run_quality(targets, rows)
    assert default["quality_status"] == "INCONCLUSIVE"
    relaxed = evaluate_run_quality(
        targets, rows, thresholds=GateThresholds(probe_coverage_min=0.5)
    )
    assert relaxed["quality_status"] == "VALID"
    assert relaxed["negative_conclusion_allowed"] is True


# ---------------------------------------------------------------- 校验器正负例


def _base_report() -> dict:
    targets = _targets(2)
    return evaluate_run_quality(targets, _ok_rows(targets))


def test_validator_accepts_evaluated_report():
    assert validate_quality_report(_base_report()) == []


def test_validator_rejects_coverage_above_one():
    report = _base_report()
    report["probe_coverage"] = 2.0
    errors = validate_quality_report(report)
    assert any("probe_coverage" in e and "[0,1]" in e for e in errors)


def test_validator_rejects_missing_required_field():
    report = _base_report()
    del report["probe_ok_ratio"]
    errors = validate_quality_report(report)
    assert any("missing required field: probe_ok_ratio" in e for e in errors)


def test_validator_rejects_non_dict():
    assert validate_quality_report(["not", "a", "dict"]) == ["quality report must be a dict"]


def test_validator_rejects_unknown_status():
    report = _base_report()
    report["quality_status"] = "GREAT"
    errors = validate_quality_report(report)
    assert any("quality_status" in e for e in errors)


def test_validator_rejects_unknown_reason():
    report = _base_report()
    report["quality_status"] = "INCONCLUSIVE"
    report["negative_conclusion_allowed"] = False
    report["quality_gate_reasons"] = ["made_up_reason"]
    errors = validate_quality_report(report)
    assert any("made_up_reason" in e for e in errors)


def test_validator_rejects_inconsistent_negative_conclusion_flag():
    report = _base_report()
    report["negative_conclusion_allowed"] = False
    errors = validate_quality_report(report)
    assert any("if and only if" in e for e in errors)


def test_validator_rejects_non_valid_without_reasons():
    report = _base_report()
    report["quality_status"] = "INCONCLUSIVE"
    report["negative_conclusion_allowed"] = False
    report["quality_gate_reasons"] = []
    errors = validate_quality_report(report)
    assert any("at least one gate reason" in e for e in errors)


def test_validator_rejects_valid_with_reasons():
    report = _base_report()
    report["quality_gate_reasons"] = ["run_blocked"]
    errors = validate_quality_report(report)
    assert any("must not carry gate reasons" in e for e in errors)


def test_validator_rejects_duplicate_reasons():
    report = _base_report()
    report["quality_status"] = "INCONCLUSIVE"
    report["negative_conclusion_allowed"] = False
    report["quality_gate_reasons"] = ["run_blocked", "run_blocked"]
    errors = validate_quality_report(report)
    assert any("duplicates" in e for e in errors)


def test_validator_rejects_success_count_above_target_count():
    report = _base_report()
    report["unique_in_scope_targets"] = 1
    errors = validate_quality_report(report)
    assert any("exceeds unique_in_scope_targets" in e for e in errors)


def test_validator_rejects_credential_like_key():
    report = _base_report()
    report["operator_session_token"] = " leaked "
    errors = validate_quality_report(report)
    assert any("credential-like key" in e for e in errors)


# ---------------------------------------------------------------- 契约防漂移


def test_states_and_reasons_match_schema_contract():
    schema = load_schema()
    assert schema, "contracts/run_quality_schema.json must exist and parse"
    assert list(schema["quality_status_states"]) == list(QUALITY_STATUS_STATES)
    assert list(schema["gate_reasons"]) == list(GATE_REASONS)
    assert set(schema["required"]) <= set(schema["properties"])


def test_thresholds_loaded_from_schema_match_defaults():
    assert load_thresholds_overrides() == GateThresholds()
    schema = load_schema()
    gate = schema["gate_thresholds"]
    defaults = GateThresholds()
    assert gate["probe_coverage_min"] == defaults.probe_coverage_min
    assert gate["probe_ok_ratio_min"] == defaults.probe_ok_ratio_min
    assert gate["rate_limit_skip_ratio_max"] == defaults.rate_limit_skip_ratio_max
    assert gate["transport_error_ratio_max"] == defaults.transport_error_ratio_max
    assert gate["waf_block_ratio_max"] == defaults.waf_block_ratio_max
