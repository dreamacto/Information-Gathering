"""Tests for finding_quality_gate (spec 2.1-2.2, 13.1, 13.2; B1 8-state superset)."""
from __future__ import annotations

import pytest

from authorized_assessment.quality.finding_quality_gate import (
    EVIDENCE_REQUIRED_FIELDS,
    FINDING_SCHEMA_PATH,
    FINDING_STATUS_STATES,
    FIVE_GATES,
    GATE_REASON_ENUMS,
    IMPACT_CATEGORIES,
    STATUS_RULE_IDS,
    evaluate_finding_quality,
    load_finding_schema,
    validate_finding_quality_report,
)


def base_confirmed_finding(**overrides):
    """一个满足全部五门且人工已验证的 finding 分类输入。"""
    finding = {
        "finding_id": "F-0001",
        "source_run": "runs/20260829_120000",
        "engagement_id": "eng-demo-20260829",
        "target": "https://target.example.com",
        "asset_identity": "target.example.com (approved target)",
        "vulnerability_family": "authorization_bypass",
        "precondition": "low-privilege account",
        "minimal_reproduction": "GET /api/admin/users with low-privilege session -> 200 with other-tenant records",
        "observed_result": "cross-tenant records returned",
        "impact_statement": "unauthorized read of other tenants' objects",
        "evidence_ref": "runs/20260829_120000/evidence/F-0001/",
        "validation_result": "verified",
        "reviewer": "operator-a",
        "reviewed_at": "2026-08-29T12:00:00+08:00",
        "manual_validation_status": "verified",
        "authorization": {
            "in_scope": True,
            "scope_confirmed": True,
            "credentials_authorized": True,
            "approval_required": False,
        },
        "reachability": {"evidence_type": "authenticated_response"},
        "reproducibility": {
            "baseline_recorded": True,
            "anomalous_response_recorded": True,
            "repeatable": True,
            "one_time_anomaly": False,
            "minimal_steps_recorded": True,
        },
        "impact": {"category": "unauthorized_object_access", "hypothesis": "cross-tenant read"},
    }
    finding.update(overrides)
    return finding


def test_confirmed_requires_all_five_gates_and_manual_verification():
    report = evaluate_finding_quality(base_confirmed_finding())
    assert report["finding_status"] == "confirmed"
    assert report["status_rule_applied"] == "five_gates_confirmed"
    assert report["confirmed_allowed"] is True
    assert report["gates_passed"] == 5
    assert report["gates_failed"] == []
    assert report["blockers"] == []
    assert validate_finding_quality_report(report) == []


def test_each_gate_failure_downgrades_confirmed():
    expectations = {
        "authorization": ("blocked", "authorization_gate_failed"),
        "reachability": ("signal", "reachability_unproven"),
        "reproducibility": ("signal", "reproduction_unproven"),
        "security_impact": ("candidate", "impact_unproven_with_hypothesis"),
        "evidence": ("needs_manual_validation", "validation_evidence_incomplete"),
    }
    failures = {
        "authorization": {"authorization": {"in_scope": False, "scope_confirmed": True, "credentials_authorized": True, "approval_required": False}},
        "reachability": {"reachability": {"evidence_type": "static_only"}},
        "reproducibility": {"reproducibility": {"baseline_recorded": True, "anomalous_response_recorded": True, "repeatable": False, "one_time_anomaly": False, "minimal_steps_recorded": True}},
        "security_impact": {"impact": {"category": None, "hypothesis": "cross-tenant read possible"}},
        "evidence": {"evidence_ref": ""},
    }
    for gate, (expected_status, expected_rule) in expectations.items():
        report = evaluate_finding_quality(base_confirmed_finding(**failures[gate]))
        assert report["finding_status"] == expected_status, gate
        assert report["status_rule_applied"] == expected_rule, gate
        assert gate in report["gates_failed"], gate
        assert report["confirmed_allowed"] is False, gate
        assert f"gate_{gate}_failed" in report["blockers"], gate
        assert validate_finding_quality_report(report) == [], gate


def test_banner_version_is_signal():
    """规格 2.1：Server Banner 暴露版本是 signal，不是 candidate。"""
    finding = base_confirmed_finding(
        finding_id="F-SIGNAL-1",
        vulnerability_family="information_disclosure",
        minimal_reproduction="GET / -> Server: nginx/1.14 banner",
        observed_result="version banner exposed",
        impact_statement="",
        manual_validation_status="not_started",
        impact={"category": None, "hypothesis": ""},
        evidence_ref="runs/x/evidence/banner.txt",
    )
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "signal"
    assert report["status_rule_applied"] == "impact_unproven_no_hypothesis"
    assert report["confirmed_allowed"] is False


def test_fixed_path_200_is_signal():
    finding = base_confirmed_finding(
        finding_id="F-SIGNAL-2",
        vulnerability_family="information_disclosure",
        minimal_reproduction="GET /actuator/health -> 200",
        observed_result="fixed path returns 200",
        impact_statement="",
        impact={"category": None, "hypothesis": ""},
        evidence_ref="runs/x/evidence/path200.txt",
    )
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "signal"


def test_reflection_without_execution_is_signal():
    """规格 2.3：自己的输入原样出现但无法执行 → signal。"""
    finding = base_confirmed_finding(
        finding_id="F-SIGNAL-3",
        vulnerability_family="xss",
        minimal_reproduction="GET /search?q=<b>marker</b> -> marker reflected in body",
        observed_result="marker reflected, no execution context",
        impact_statement="",
        impact={"category": None, "hypothesis": ""},
        evidence_ref="runs/x/evidence/reflect.txt",
    )
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "signal"


def test_static_sink_without_reachability_is_signal():
    """规格 2.2 门 2：只有静态代码证据而没有可触达链路 → 最多 signal（whitebox_candidate 映射）。"""
    finding = base_confirmed_finding(
        finding_id="F-WHITEBOX-1",
        reachability={"evidence_type": "static_only"},
        impact={"category": "code_or_command_execution", "hypothesis": "sink reachable via param"},
    )
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "signal"
    assert report["status_rule_applied"] == "reachability_unproven"
    assert "static_evidence_only" in report["gate_results"]["reachability"]["reasons"]


def test_candidate_with_impact_hypothesis_but_unproven():
    """规格 2.1 candidate 定义：有可复现性与技术关联、影响假设已记录但未证明。"""
    finding = base_confirmed_finding(
        finding_id="F-CAND-1",
        manual_validation_status="not_started",
        impact={"category": None, "hypothesis": "object id may be enumerable across tenants"},
    )
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "candidate"
    assert report["status_rule_applied"] == "impact_unproven_with_hypothesis"
    assert report["impact_hypothesis_recorded"] is True
    assert report["confirmed_allowed"] is False


def test_unverified_ai_candidate_is_needs_manual_validation():
    """五门全过但未经人工验证 → 不得 confirmed（needs_manual_validation）。"""
    finding = base_confirmed_finding(manual_validation_status="not_started")
    report = evaluate_finding_quality(finding)
    assert report["confirmed_allowed"] is True
    assert report["finding_status"] == "needs_manual_validation"
    assert "manual_validation_not_verified" in report["blockers"]


def test_in_progress_manual_validation_is_not_confirmed():
    finding = base_confirmed_finding(manual_validation_status="in_progress")
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "needs_manual_validation"


def test_out_of_scope_is_blocked():
    finding = base_confirmed_finding(
        authorization={"in_scope": False, "scope_confirmed": False, "credentials_authorized": True, "approval_required": False}
    )
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "blocked"
    assert report["status_rule_applied"] == "authorization_gate_failed"
    reasons = report["gate_results"]["authorization"]["reasons"]
    assert "out_of_scope" in reasons and "scope_unconfirmed" in reasons


def test_approval_required_without_record_is_blocked():
    finding = base_confirmed_finding(
        authorization={"in_scope": True, "scope_confirmed": True, "credentials_authorized": True, "approval_required": True, "approval_records": []}
    )
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "blocked"
    assert "approval_record_missing" in report["gate_results"]["authorization"]["reasons"]


@pytest.mark.parametrize("indicator", ["waf_blocked", "rate_limited", "no_valid_response"])
def test_probe_degradation_is_inconclusive(indicator):
    finding = base_confirmed_finding(probe_quality={indicator: True})
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "inconclusive"
    assert report["status_rule_applied"] == "inconclusive_indicators"
    assert indicator in report["inconclusive_indicators"]


def test_validation_result_inconclusive_is_inconclusive():
    finding = base_confirmed_finding(validation_result="inconclusive")
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "inconclusive"
    assert "validation_result_inconclusive" in report["blockers"]


def test_duplicate_merge_reference_wins():
    finding = base_confirmed_finding(duplicate_of="F-0000")
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "duplicate"
    assert report["status_rule_applied"] == "duplicate_merge_reference"
    assert "duplicate_of_set" in report["blockers"]


def test_explicit_rejection_reason_wins():
    finding = base_confirmed_finding(rejection_reason="human re-validation did not reproduce")
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "rejected"
    assert report["status_rule_applied"] == "explicit_rejection"


def test_manual_validation_rejected_is_rejected():
    finding = base_confirmed_finding(manual_validation_status="rejected")
    report = evaluate_finding_quality(finding)
    assert report["finding_status"] == "rejected"


def test_evaluation_is_deterministic():
    finding = base_confirmed_finding()
    assert evaluate_finding_quality(finding) == evaluate_finding_quality(finding)


def test_invalid_enum_inputs_fail_closed():
    finding = base_confirmed_finding(
        manual_validation_status="garbage",
        validation_result="garbage",
    )
    report = evaluate_finding_quality(finding)
    assert report["manual_validation_status"] == "not_started"
    assert report["validation_result"] is None
    assert report["finding_status"] == "needs_manual_validation"
    assert validate_finding_quality_report(report) == []


def test_unknown_reachability_evidence_type_is_unproven():
    finding = base_confirmed_finding(reachability={"evidence_type": "teleportation"})
    report = evaluate_finding_quality(finding)
    assert report["gate_results"]["reachability"]["passed"] is False
    assert "reachability_unproven" in report["gate_results"]["reachability"]["reasons"]
    assert report["finding_status"] == "signal"
    assert validate_finding_quality_report(report) == []


def test_empty_input_fails_closed_to_blocked():
    """规格 2.2 门 1：没有授权证明不能称漏洞——空记录 fail-closed 为 blocked（blocked_authorization）。"""
    report = evaluate_finding_quality({})
    assert report["finding_status"] == "blocked"
    assert report["confirmed_allowed"] is False
    assert "out_of_scope" in report["gate_results"]["authorization"]["reasons"]
    assert "credentials_not_authorized" in report["gate_results"]["authorization"]["reasons"]
    assert validate_finding_quality_report(report) == []


def test_all_eight_states_reachable():
    seen = {
        evaluate_finding_quality(base_confirmed_finding())["finding_status"],
        evaluate_finding_quality(base_confirmed_finding(manual_validation_status="not_started"))["finding_status"],
        evaluate_finding_quality(base_confirmed_finding(impact={"category": None, "hypothesis": "possible"}, manual_validation_status="not_started"))["finding_status"],
        evaluate_finding_quality(base_confirmed_finding(impact={"category": None, "hypothesis": ""}, manual_validation_status="not_started"))["finding_status"],
        evaluate_finding_quality(base_confirmed_finding(probe_quality={"waf_blocked": True}))["finding_status"],
        evaluate_finding_quality(base_confirmed_finding(authorization={"in_scope": False, "scope_confirmed": True, "credentials_authorized": True, "approval_required": False}))["finding_status"],
        evaluate_finding_quality(base_confirmed_finding(rejection_reason="not reproducible"))["finding_status"],
        evaluate_finding_quality(base_confirmed_finding(duplicate_of="F-0000"))["finding_status"],
    }
    assert seen == set(FINDING_STATUS_STATES)


def test_evidence_gate_uses_spec_14_fields():
    for field in EVIDENCE_REQUIRED_FIELDS:
        finding = base_confirmed_finding(**{field: ""})
        report = evaluate_finding_quality(finding)
        assert field in report["missing_evidence_fields"], field
        assert report["finding_status"] != "confirmed", field
        assert validate_finding_quality_report(report) == [], field


def test_validator_rejects_claimed_confirmed_with_failed_gate():
    report = evaluate_finding_quality(base_confirmed_finding())
    tampered = dict(report)
    tampered["gate_results"] = dict(report["gate_results"])
    tampered["gate_results"]["reproducibility"] = {"passed": False, "reasons": ["not_repeatable"]}
    errors = validate_finding_quality_report(tampered)
    assert any("gates_passed" in e or "gates_failed" in e or "inconsistent" in e for e in errors)


def test_validator_rejects_status_not_in_enum():
    report = evaluate_finding_quality(base_confirmed_finding())
    tampered = dict(report, finding_status="whitebox_candidate")
    errors = validate_finding_quality_report(tampered)
    assert any("finding_status not in schema enum" in e for e in errors)


def test_validator_rejects_gate_name_drift():
    report = evaluate_finding_quality(base_confirmed_finding())
    tampered = dict(report)
    tampered["gate_results"] = {k: v for k, v in report["gate_results"].items() if k != "evidence"}
    errors = validate_finding_quality_report(tampered)
    assert any("exactly the five gates" in e for e in errors)


def test_validator_rejects_reason_not_in_enum():
    report = evaluate_finding_quality(base_confirmed_finding())
    tampered = dict(report)
    tampered["gate_results"] = dict(report["gate_results"])
    tampered["gate_results"]["authorization"] = {"passed": True, "reasons": ["looks_fine"]}
    errors = validate_finding_quality_report(tampered)
    assert any("reason not in schema enum" in e for e in errors)


def test_validator_rejects_confirmed_allowed_true_with_failed_gate():
    report = evaluate_finding_quality(base_confirmed_finding(impact={"category": None, "hypothesis": "h"}))
    tampered = dict(report, confirmed_allowed=True)
    errors = validate_finding_quality_report(tampered)
    assert any("confirmed_allowed" in e for e in errors)


def test_validator_rejects_missing_required_field():
    report = evaluate_finding_quality(base_confirmed_finding())
    tampered = {k: v for k, v in report.items() if k != "finding_status"}
    errors = validate_finding_quality_report(tampered)
    assert any("missing required field: finding_status" in e for e in errors)


def test_validator_rejects_session_key_credential_like_key():
    """规格 4.4 点名 session_key；基础片段不含该词，本模块扫描必须扩展覆盖。"""
    report = evaluate_finding_quality(base_confirmed_finding())
    tampered = dict(report)
    tampered["session_key"] = "placeholder"
    errors = validate_finding_quality_report(tampered)
    assert any("session_key" in e for e in errors)


def test_validator_exempts_gate_name_authorization_key():
    """gate 名 authorization 是五门结构键，不是凭证键（policy_snapshot 豁免先例）。"""
    report = evaluate_finding_quality(base_confirmed_finding())
    assert validate_finding_quality_report(report) == []


def test_validator_accepts_non_confirmed_statuses():
    for finding in (
        base_confirmed_finding(),
        base_confirmed_finding(manual_validation_status="not_started"),
        base_confirmed_finding(impact={"category": None, "hypothesis": "h"}, manual_validation_status="not_started"),
        base_confirmed_finding(duplicate_of="F-0000"),
        evaluate_finding_quality({}),
    ):
        report = evaluate_finding_quality(finding)
        assert validate_finding_quality_report(report) == [], report["finding_status"]


def test_schema_contract_matches_module_constants():
    schema = load_finding_schema()
    assert schema, f"schema missing at {FINDING_SCHEMA_PATH}"
    assert schema["finding_status_states"] == list(FINDING_STATUS_STATES)
    assert schema["gates"] == list(FIVE_GATES)
    assert schema["impact_categories"] == list(IMPACT_CATEGORIES)
    assert schema["evidence_required_fields"] == list(EVIDENCE_REQUIRED_FIELDS)
    schema_rules = [item["rule"] for item in schema["status_decision_order"]]
    assert schema_rules == list(STATUS_RULE_IDS)
    for gate, reasons in schema["gate_reason_enums"].items():
        assert tuple(reasons) == GATE_REASON_ENUMS[gate]


def test_status_states_are_b1_superset():
    """B1 决议：8 状态超集，whitebox_candidate 不作为第九状态。"""
    assert FINDING_STATUS_STATES == (
        "signal",
        "candidate",
        "needs_manual_validation",
        "confirmed",
        "inconclusive",
        "blocked",
        "rejected",
        "duplicate",
    )


# ---------------------------------------------------------------------------
# batch2_1：补天口径映射与降级抑制（规格 2.5-2.9）
# ---------------------------------------------------------------------------

from authorized_assessment.quality.finding_quality_gate import (
    EXERCISE_RESULT_CLASSES,
    EXERCISE_RESULT_CLASS_BY_IMPACT_CATEGORY,
    FINDING_CLASSES,
    IMPACT_SCOPES,
    INTERNAL_PRIORITY_TO_PLATFORM_SEVERITY,
    PLATFORM_SEVERITIES,
    PLATFORM_SEVERITY_DEFAULT_BY_IMPACT_CATEGORY,
    SUBMISSION_ELIGIBILITIES,
    SUPPRESSION_RULES,
    build_finding_classification,
    classify_finding_class,
    map_platform_severity,
    validate_finding_classification,
)


def test_map_platform_severity_follows_spec_2_6():
    assert map_platform_severity("P0") == "high"
    assert map_platform_severity("P1") == "high"
    assert map_platform_severity("P2") == "medium"
    assert map_platform_severity("P3") == "low"
    assert map_platform_severity(None) is None
    assert map_platform_severity("PX") is None


def test_confirmed_without_priority_uses_category_default_table():
    for category, expected in PLATFORM_SEVERITY_DEFAULT_BY_IMPACT_CATEGORY.items():
        finding = base_confirmed_finding(impact={"category": category, "hypothesis": "proven"})
        classification = build_finding_classification(finding)
        assert classification["platform_severity"] == expected, category
        assert classification["platform_severity_basis"] == "impact_category_default", category
        assert validate_finding_classification(classification) == [], category


def test_internal_priority_overrides_category_defaults():
    finding = base_confirmed_finding(
        impact={"category": "sensitive_data_exposure", "hypothesis": "bulk exposure"},
        internal_priority="P1",
    )
    classification = build_finding_classification(finding)
    assert classification["platform_severity"] == "high"
    assert classification["platform_severity_basis"] == "internal_priority"


def test_unconfirmed_findings_cap_at_low():
    for override in (
        {"manual_validation_status": "not_started"},
        {"manual_validation_status": "not_started", "impact": {"category": None, "hypothesis": "guess"}},
    ):
        classification = build_finding_classification(base_confirmed_finding(**override))
        assert classification["platform_severity"] == "low"
        assert classification["platform_severity_basis"] == "status_ceiling"


def test_non_actionable_statuses_are_not_collectible():
    findings = (
        base_confirmed_finding(impact={"category": None, "hypothesis": ""}, manual_validation_status="not_started"),
        base_confirmed_finding(rejection_reason="not reproducible"),
        base_confirmed_finding(probe_quality={"waf_blocked": True}),
        base_confirmed_finding(authorization={"in_scope": False, "scope_confirmed": True, "credentials_authorized": True, "approval_required": False}),
        base_confirmed_finding(duplicate_of="F-0000"),
    )
    for finding in findings:
        classification = build_finding_classification(finding)
        assert classification["platform_severity"] == "not_collectible", classification["finding_status"]
        assert validate_finding_classification(classification) == []


def test_exercise_result_class_follows_impact_category():
    for category, expected in EXERCISE_RESULT_CLASS_BY_IMPACT_CATEGORY.items():
        finding = base_confirmed_finding(impact={"category": category, "hypothesis": "proven"})
        classification = build_finding_classification(finding)
        assert classification["exercise_result_class"] == expected, category
    signal_classification = build_finding_classification(
        base_confirmed_finding(impact={"category": None, "hypothesis": ""}, manual_validation_status="not_started")
    )
    assert signal_classification["exercise_result_class"] == "signal_only"


def test_finding_class_generic_vs_event():
    event_classification = classify_finding_class({"target": "https://t.example.com"})
    assert event_classification == ("event_vulnerability", [])
    generic_finding = {
        "product_or_component": "ECShop",
        "product_version_or_build": "4.0",
        "vulnerability_family": "sql_injection",
        "affected_condition": "specific param without WAF",
        "vendor_or_upstream_reference": "public advisory",
        "affected_instance_count": 3,
        "reproduction_stability": "stable",
        "whether_public_or_0day": "public",
    }
    assert classify_finding_class(generic_finding) == ("generic_vulnerability", [])
    partial = {"product_or_component": "ECShop"}
    finding_class, missing = classify_finding_class(partial)
    assert finding_class == "generic_vulnerability"
    assert "product_version_or_build" in missing and "whether_public_or_0day" in missing
    assert len(missing) == 7


def test_suppression_catalog_has_ten_rules_matching_schema():
    assert len(SUPPRESSION_RULES) == 10
    outcomes = {rule: spec["outcome"] for rule, spec in SUPPRESSION_RULES.items()}
    assert outcomes["RULE_6_SAME_TYPE_OVER_LIMIT"] == "duplicate"
    assert outcomes["RULE_7_SQLI_PER_ENDPOINT_MERGE"] == "duplicate"
    assert outcomes["RULE_8_GENERIC_ROOT_CAUSE_DUPLICATE"] == "duplicate"
    assert outcomes["RULE_3_UNEXPLOITABLE_INFO"] == "ignored"
    assert outcomes["RULE_4_NO_SENSITIVE_DATA"] == "ignored"
    assert outcomes["RULE_5_FORBIDDEN_PROOF_REQUIRED"] == "ignored"
    assert outcomes["RULE_1_LOW_VALUE_PATTERNS"] == "deprioritized"
    assert outcomes["RULE_2_CONFIG_HARDENING_ONLY"] == "deprioritized"
    assert outcomes["RULE_10_LOW_VALUE_SITE"] == "deprioritized"
    assert outcomes["RULE_9_UNVERIFIED_AI_CANDIDATE"] == "manual_review_required"
    schema = load_finding_schema()
    assert schema["suppression_rules"] == SUPPRESSION_RULES


def test_eligible_only_for_confirmed_verified_without_suppression():
    classification = build_finding_classification(base_confirmed_finding())
    assert classification["submission_eligibility"] == "eligible"
    assert classification["reason_not_a_vulnerability"] == ""
    assert classification["suppression_rules_applied"] == []
    assert validate_finding_classification(classification) == []


def test_unverified_ai_candidate_is_manual_review_required():
    """规格 2.7 规则 9：未经人工验证的 AI 候选 → manual_review_required。"""
    classification = build_finding_classification(
        base_confirmed_finding(manual_validation_status="not_started")
    )
    assert classification["submission_eligibility"] == "manual_review_required"
    assert "RULE_9_UNVERIFIED_AI_CANDIDATE" not in classification["suppression_rules_applied"]
    assert "manual_validation_not_verified" in classification["reason_not_a_vulnerability"]
    assert validate_finding_classification(classification) == []


def test_suppression_flags_downgrade_eligibility():
    confirmed = base_confirmed_finding()
    cases = (
        (["RULE_1_LOW_VALUE_PATTERNS"], "deprioritized"),
        (["RULE_2_CONFIG_HARDENING_ONLY"], "deprioritized"),
        (["RULE_10_LOW_VALUE_SITE"], "deprioritized"),
        (["RULE_3_UNEXPLOITABLE_INFO"], "ignored"),
        (["RULE_4_NO_SENSITIVE_DATA"], "ignored"),
        (["RULE_5_FORBIDDEN_PROOF_REQUIRED"], "ignored"),
        (["RULE_6_SAME_TYPE_OVER_LIMIT"], "duplicate"),
        (["RULE_7_SQLI_PER_ENDPOINT_MERGE"], "duplicate"),
        (["RULE_8_GENERIC_ROOT_CAUSE_DUPLICATE"], "duplicate"),
    )
    for flags, expected in cases:
        classification = build_finding_classification(
            base_confirmed_finding(suppression_flags=flags)
        )
        assert classification["submission_eligibility"] == expected, flags
        assert classification["suppression_rules_applied"] == flags
        assert classification["reason_not_a_vulnerability"] != ""
        assert validate_finding_classification(classification) == [], flags


def test_candidate_status_deprioritized():
    classification = build_finding_classification(
        base_confirmed_finding(
            manual_validation_status="not_started",
            impact={"category": None, "hypothesis": "enumerable ids"},
        )
    )
    assert classification["finding_status"] == "candidate"
    assert classification["submission_eligibility"] == "deprioritized"


def test_ignored_rule_beats_manual_review():
    """needs_manual_validation + RULE_3（无利用价值信息）→ ignored 优先。"""
    classification = build_finding_classification(
        base_confirmed_finding(
            manual_validation_status="not_started",
            suppression_flags=["RULE_3_UNEXPLOITABLE_INFO"],
        )
    )
    assert classification["submission_eligibility"] == "ignored"


def test_duplicate_flag_on_confirmed_forces_duplicate():
    classification = build_finding_classification(
        base_confirmed_finding(suppression_flags=["RULE_7_SQLI_PER_ENDPOINT_MERGE"])
    )
    assert classification["submission_eligibility"] == "duplicate"
    assert classification["reason_not_a_vulnerability"] != ""


def test_unknown_suppression_flags_do_not_suppress():
    """未知 flag 不触发抑制（抑制只会降低资格，忽略未知 flag 是安全方向），但显式留痕。"""
    classification = build_finding_classification(
        base_confirmed_finding(suppression_flags=["RULE_999_MADE_UP"])
    )
    assert classification["submission_eligibility"] == "eligible"
    assert classification["suppression_rules_unknown"] == ["RULE_999_MADE_UP"]
    assert validate_finding_classification(classification) == []


def test_classification_fields_default_values():
    classification = build_finding_classification(base_confirmed_finding())
    assert classification["impact_scope"] == "single_object"
    assert classification["root_cause_signature"] == ""
    assert classification["merge_group_id"] == ""
    classification["impact_scope"] = "garbage"
    errors = validate_finding_classification(classification)
    assert any("impact_scope not in schema enum" in e for e in errors)


def test_validator_rejects_enum_and_consistency_violations():
    base = build_finding_classification(base_confirmed_finding())

    eligible_unverified = build_finding_classification(
        base_confirmed_finding(manual_validation_status="not_started")
    )
    tampered = dict(eligible_unverified, submission_eligibility="eligible")
    errors = validate_finding_classification(tampered)
    assert any("eligible requires finding_status confirmed" in e for e in errors)

    high_unconfirmed = build_finding_classification(
        base_confirmed_finding(
            manual_validation_status="not_started",
            impact={"category": None, "hypothesis": "guess"},
        )
    )
    tampered = dict(high_unconfirmed, platform_severity="high")
    errors = validate_finding_classification(tampered)
    assert any("may only be suggested for confirmed" in e for e in errors)

    tampered = dict(base, submission_eligibility="duplicate")
    errors = validate_finding_classification(tampered)
    assert any("duplicate eligibility requires" in e for e in errors)

    tampered = dict(base, suppression_rules_applied=["RULE_999"])
    errors = validate_finding_classification(tampered)
    assert any("not in catalog" in e for e in errors)

    tampered = dict(base, finding_class="maybe")
    errors = validate_finding_classification(tampered)
    assert any("finding_class not in schema enum" in e for e in errors)

    tampered = dict(base, finding_status="candidate")
    errors = validate_finding_classification(tampered)
    assert any("does not match quality_report" in e for e in errors)


def test_classification_valid_for_all_eight_statuses():
    findings = (
        base_confirmed_finding(),
        base_confirmed_finding(manual_validation_status="not_started"),
        base_confirmed_finding(manual_validation_status="not_started", impact={"category": None, "hypothesis": "h"}),
        base_confirmed_finding(manual_validation_status="not_started", impact={"category": None, "hypothesis": ""}),
        base_confirmed_finding(probe_quality={"rate_limited": True}),
        base_confirmed_finding(authorization={"in_scope": False, "scope_confirmed": True, "credentials_authorized": True, "approval_required": False}),
        base_confirmed_finding(rejection_reason="not reproducible"),
        base_confirmed_finding(duplicate_of="F-0000"),
    )
    seen = set()
    for finding in findings:
        classification = build_finding_classification(finding)
        seen.add(classification["finding_status"])
        assert validate_finding_classification(classification) == [], classification["finding_status"]
    assert seen == set(FINDING_STATUS_STATES)


def test_schema_classification_enums_match_module_constants():
    schema = load_finding_schema()
    enums = schema["classification_enums"]
    assert enums["finding_class"] == list(FINDING_CLASSES)
    assert enums["platform_severity"] == list(PLATFORM_SEVERITIES)
    assert enums["exercise_result_class"] == list(EXERCISE_RESULT_CLASSES)
    assert enums["submission_eligibility"] == list(SUBMISSION_ELIGIBILITIES)
    assert enums["impact_scope"] == list(IMPACT_SCOPES)
    assert schema["internal_priority_to_platform_severity"] == INTERNAL_PRIORITY_TO_PLATFORM_SEVERITY
    assert schema["platform_severity_default_by_impact_category"] == PLATFORM_SEVERITY_DEFAULT_BY_IMPACT_CATEGORY
    assert schema["exercise_result_class_by_impact_category"] == EXERCISE_RESULT_CLASS_BY_IMPACT_CATEGORY
