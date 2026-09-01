"""tests/test_third_party_api_review.py —— 第三方 API 边界只读复核域测试
（batch8_2，规格 5.3 第三方 API 小节 + 3.1 triage 模块清单）。

覆盖：观察键→证据形态确定性映射、升级边界（10 形态永不升级、4 确认形态分类升级、
他类确认形态不跨类升级）、8 状态分级与 status_hint、候选行校验（非法 category/
status、candidate 缺 evidence_ref、升级证据不满足）、筛选汇总（三统计概念分离 +
注入类别路由违例 + 缺来源/版本不符违例 + na reason 契约）、CSV 表头契约。
纯离线数据变换，不发请求、不发送 webhook、不重放回调。
"""
from __future__ import annotations

from authorized_assessment.triage import injection_candidates as ic
from authorized_assessment.triage import third_party_api_review as tpr

FORM_EVIDENCE = {
    "third_party_call_present_observed": True,
    "webhook_endpoint_present_observed": True,
    "signature_field_absent_observed": True,
    "timestamp_field_absent_observed": True,
}

WEBHOOK_CONFIRMED_OBS = {
    "endpoint": "/callback/pay",
    "third_party": "pay.example-partner.cn",
    "category": "webhook_origin_validation",
    "applicability": "applicable",
    "evidence": {
        "webhook_endpoint_present_observed": True,
        "signature_field_absent_observed": True,
        "webhook_unauthenticated_confirmed": True,
    },
    "source": "runs/demo/evidence/api/pay-callback.json",
    "evidence_ref": "runs/demo/evidence/api/pay-callback.json:L7",
    "reason": "既有只读证据显示伪造回调被实际接受并产生状态变更",
    "precondition": "确认仅基于既有证据复核；不发送 webhook、不重放回调",
}

TRUST_CONFIRMED_OBS = {
    "endpoint": "/api/order/notify",
    "category": "third_party_response_trust",
    "applicability": "applicable",
    "evidence": {
        "third_party_call_present_observed": True,
        "unverified_decision_confirmed": True,
    },
    "source": "runs/demo/evidence/api/order-notify.json",
    "evidence_ref": "runs/demo/evidence/api/order-notify.json:L2",
    "reason": "未验证的第三方支付状态实际进入订单状态决策",
    "precondition": "确认仅基于既有证据复核；不发送 webhook、不重放回调",
}


def test_derive_evidence_kinds_maps_observation_keys():
    kinds = tpr.derive_third_party_evidence_kinds(
        {
            "third_party_call_present_observed": True,
            "differential_observed": True,
            "unknown_key": True,
        }
    )
    assert kinds == ["third_party_call_present", "differential"]
    assert tpr.derive_third_party_evidence_kinds({}) == []


def test_grade_form_observations_never_upgrade():
    """仅调用面/端点存在/缺失字段线索/敏感字段出现/支持性观察永不升级。"""
    for evidence in (
        FORM_EVIDENCE,
        {"foreign_domain_reference_observed": True},
        {"redirect_to_third_party_observed": True},
        {"sensitive_field_in_response_observed": True, "semantic_anomaly_observed": True},
        {"allowlist_absent_observed": True},
    ):
        for category in tpr.THIRD_PARTY_CATEGORIES:
            kinds = tpr.derive_third_party_evidence_kinds(evidence)
            assert tpr.grade_third_party_observation(category, kinds) == "signal"


def test_grade_confirmed_kinds_upgrade_per_category():
    """四确认形态各升对应类别；跨类不升级。"""
    mapping = {
        "unverified_decision_confirmed": "third_party_response_trust",
        "webhook_unauthenticated_confirmed": "webhook_origin_validation",
        "foreign_asset_in_scope_confirmed": "asset_scope_hygiene",
        "privilege_expansion_confirmed": "third_party_data_flow",
    }
    for kind, category in mapping.items():
        assert tpr.grade_third_party_observation(category, [kind]) == "candidate"
    for kind, category in mapping.items():
        for other in tpr.THIRD_PARTY_CATEGORIES:
            if other != category:
                assert tpr.grade_third_party_observation(other, [kind]) == "signal"


def test_status_hint_respected():
    kinds = tpr.derive_third_party_evidence_kinds(FORM_EVIDENCE)
    assert (
        tpr.grade_third_party_observation("webhook_origin_validation", kinds, "inconclusive")
        == "inconclusive"
    )


def test_validate_candidate_contract():
    violations = tpr.validate_third_party_candidate(
        {
            "candidate_id": "tp-0001",
            "category": "webhook_origin_validation",
            "status": "candidate",
            "evidence_kinds": ["webhook_unauthenticated_confirmed"],
            "source": "runs/demo/evidence.json",
            "evidence_ref": "runs/demo/evidence.json:L1",
        }
    )
    assert violations == []
    # 缺必需字段
    violations = tpr.validate_third_party_candidate({"category": "asset_scope_hygiene"})
    assert any("缺少必需字段" in v for v in violations)
    # 非法 category
    violations = tpr.validate_third_party_candidate(
        {
            "candidate_id": "x",
            "category": "sql",
            "status": "signal",
            "evidence_kinds": ["third_party_call_present"],
            "source": "s",
        }
    )
    assert any("category 非法" in v for v in violations)
    # 非法 status
    violations = tpr.validate_third_party_candidate(
        {
            "candidate_id": "x",
            "category": "third_party_data_flow",
            "status": "vuln",
            "evidence_kinds": ["privilege_expansion_confirmed"],
            "source": "s",
        }
    )
    assert any("status 非法" in v for v in violations)
    # candidate 无 evidence_ref
    violations = tpr.validate_third_party_candidate(
        {
            "candidate_id": "x",
            "category": "third_party_data_flow",
            "status": "candidate",
            "evidence_kinds": ["privilege_expansion_confirmed"],
            "source": "s",
            "evidence_ref": "",
        }
    )
    assert any("evidence_ref 为空" in v for v in violations)
    # 形态观察标 candidate 被拒
    violations = tpr.validate_third_party_candidate(
        {
            "candidate_id": "x",
            "category": "webhook_origin_validation",
            "status": "candidate",
            "evidence_kinds": ["signature_field_absent"],
            "source": "s",
            "evidence_ref": "r",
        }
    )
    assert any("升级证据不满足" in v for v in violations)


def test_screen_routes_injection_categories():
    rows, summaries, violations = tpr.screen_third_party_observations(
        [
            {"category": "ssti", "applicability": "applicable", "endpoint": "/api/x"},
        ]
    )
    assert rows == []
    assert sum("属注入域" in v for v in violations) == 1
    assert len(summaries) == len(tpr.THIRD_PARTY_CATEGORIES)


def test_screen_summary_contract_and_na_reason():
    rows, summaries, violations = tpr.screen_third_party_observations(
        [WEBHOOK_CONFIRMED_OBS, TRUST_CONFIRMED_OBS]
    )
    assert violations == []
    assert len(rows) == 2
    webhook = next(s for s in summaries if s["category"] == "webhook_origin_validation")
    assert webhook["status_counts"]["candidate"] == 1
    assert webhook["tested_count"] == 1
    assert webhook["category_status"] == "tested"
    assert webhook["precondition"]  # candidate>0 → precondition 非空（契约）
    # not_applicable 类别：汇总行 reason 非空
    rows2, summaries2, violations2 = tpr.screen_third_party_observations(
        [
            {
                "category": "asset_scope_hygiene",
                "applicability": "not_applicable",
                "reason": "目标无第三方资产引用面",
            }
        ]
    )
    assert rows2 == [] and violations2 == []
    asset = next(s for s in summaries2 if s["category"] == "asset_scope_hygiene")
    assert asset["category_status"] == "not_applicable"
    assert asset["reason"]


def test_screen_source_and_version_violations():
    rows, summaries, violations = tpr.screen_third_party_observations(
        [
            {
                "category": "third_party_data_flow",
                "applicability": "applicable",
                "observation_schema_version": "0.9",
                "evidence": {"redirect_to_third_party_observed": True},
            }
        ]
    )
    # 违例记录后行仍产出（产物如实落盘由 audit 处置，与前批各域语义一致）
    assert len(rows) == 1 and rows[0]["status"] == "signal"
    assert any("observation_schema_version" in v for v in violations)
    assert any("缺少来源" in v for v in violations)


def test_csv_header_contract():
    assert tpr.THIRD_PARTY_BOUNDARY_CSV_FIELDS == (
        "candidate_id",
        "category",
        "status",
        "evidence_kinds",
        "source",
        "evidence_ref",
        "precondition",
        "reason",
    )
    rows, _, _ = tpr.screen_third_party_observations([WEBHOOK_CONFIRMED_OBS])
    for field in tpr.THIRD_PARTY_BOUNDARY_CSV_FIELDS:
        assert field in rows[0]


def test_engine_and_status_model_single_source():
    """复用 ic 单一引擎/8 状态/汇总行契约（三统计概念分离不被新域绕过）。"""
    satisfied, _ = ic.rule_satisfied(
        {"required_any_groups": (("unverified_decision_confirmed",),)},
        ["unverified_decision_confirmed"],
        tpr.THIRD_PARTY_EVIDENCE_KINDS,
        tpr.THIRD_PARTY_INSUFFICIENT_EVIDENCE_KINDS,
    )
    assert satisfied
    assert len(ic.CANDIDATE_STATUS_VALUES) == 8
