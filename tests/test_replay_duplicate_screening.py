"""tests/test_replay_duplicate_screening.py —— 重放/重复提交假设筛选域测试
（batch9_1，规格 5.5 replay_duplicate 子分支 1453-1472 行）。

覆盖：观察键→证据形态确定性映射、升级边界（7 形态/支持性永不升级、4 确认形态
类别一一对应不跨类、"重复点击一次"形态组合仍 signal）、8 状态分级与 status_hint、
候选行校验负例、注入路由违例、缺来源/版本不符违例、汇总三统计概念分离与
candidate>0 时 precondition 非空契约、红线常量、CSV 表头契约、引擎单一来源引用。
纯离线数据变换，不发请求、不发并发/重复轰炸请求。
"""
from __future__ import annotations

from pathlib import Path

from authorized_assessment.triage import injection_candidates as ic
from authorized_assessment.triage import replay_duplicate_screening as rds

FORM_EVIDENCE = {
    "duplicate_request_accepted_observed": True,
    "idempotency_key_absent_observed": True,
    "no_dedup_feedback_observed": True,
    "response_similarity_observed": True,
}

SUPPORTED_EVIDENCE = {
    **FORM_EVIDENCE,
    "timing_gap_observed": True,
    "differential_observed": True,
    "semantic_anomaly_observed": True,
}

CONSUMPTION_CONFIRMED_OBS = {
    "endpoint": "/api/v1/coupons/1001/redeem",
    "object_ref": "coupon:1001",
    "category": "repeat_consumption",
    "applicability": "applicable",
    "evidence": {
        "duplicate_request_accepted_observed": True,
        "differential_observed": True,
        "duplicate_consumption_confirmed": True,
    },
    "source": "runs/demo/evidence/logic/redeem-records.json",
    "evidence_ref": "runs/demo/evidence/logic/redeem-records.json:L5",
    "reason": "既有只读证据显示同一券核销记录两条且库存扣两次、可复现",
    "precondition": "确认仅基于既有只读证据复核；不发起并发/重复轰炸验证",
}


def test_derive_evidence_kinds_maps_observation_keys():
    kinds = rds.derive_replay_duplicate_evidence_kinds(
        {
            "duplicate_request_accepted_observed": True,
            "differential_observed": True,
            "unknown_key": True,
        }
    )
    assert kinds == ["duplicate_request_accepted_observed", "differential"]
    assert rds.derive_replay_duplicate_evidence_kinds({}) == []


def test_grade_form_and_supporting_observations_never_upgrade():
    """形态观察（含"重复点击一次"的典型组合）与支持性观察永不升级——signal。"""
    for evidence in (
        FORM_EVIDENCE,
        SUPPORTED_EVIDENCE,
        {"idempotency_key_absent_observed": True},
        {"response_similarity_observed": True, "timing_gap_observed": True},
        {"no_dedup_feedback_observed": True, "differential_observed": True},
        {"semantic_anomaly_observed": True},
    ):
        for category in rds.REPLAY_DUPLICATE_CATEGORIES:
            kinds = rds.derive_replay_duplicate_evidence_kinds(evidence)
            assert rds.grade_replay_duplicate_observation(category, kinds) == "signal"


def test_grade_confirmed_kinds_upgrade_matching_category_only():
    """四确认形态与四类别一一对应；跨类不升级。"""
    mapping = {
        "repeat_consumption": "duplicate_consumption_confirmed",
        "repeat_grant": "duplicate_grant_confirmed",
        "repeat_deduction": "duplicate_deduction_confirmed",
        "repeat_approval": "duplicate_approval_confirmed",
    }
    for category, confirmed in mapping.items():
        assert rds.grade_replay_duplicate_observation(category, [confirmed]) == "candidate"
        for other in mapping.values():
            if other != confirmed:
                assert (
                    rds.grade_replay_duplicate_observation(category, [other]) == "signal"
                )


def test_status_hint_respected():
    kinds = rds.derive_replay_duplicate_evidence_kinds(SUPPORTED_EVIDENCE)
    assert (
        rds.grade_replay_duplicate_observation(
            "repeat_grant", kinds, "needs_manual_validation"
        )
        == "needs_manual_validation"
    )
    assert (
        rds.grade_replay_duplicate_observation("repeat_grant", kinds, "rejected")
        == "rejected"
    )


def test_candidate_row_validation_negatives():
    base = {
        "candidate_id": "rd-0001",
        "category": "repeat_consumption",
        "status": "candidate",
        "evidence_kinds": ["duplicate_consumption_confirmed"],
        "source": "runs/demo/evidence/logic/redeem-records.json",
        "evidence_ref": "runs/demo/evidence/logic/redeem-records.json:L5",
    }
    assert rds.validate_replay_duplicate_candidate(base) == []
    # 非法类别
    violations = rds.validate_replay_duplicate_candidate({**base, "category": "xss"})
    assert any("category 非法" in v for v in violations)
    # 非法状态
    violations = rds.validate_replay_duplicate_candidate({**base, "status": "vulnerable"})
    assert any("status 非法" in v for v in violations)
    # candidate 但升级证据不满足（仅形态观察）
    violations = rds.validate_replay_duplicate_candidate(
        {**base, "evidence_kinds": ["duplicate_request_accepted_observed"]}
    )
    assert any("升级证据不满足" in v for v in violations)
    # candidate 但 evidence_ref 为空
    violations = rds.validate_replay_duplicate_candidate({**base, "evidence_ref": ""})
    assert any("evidence_ref 为空" in v for v in violations)
    # 未知证据形态
    violations = rds.validate_replay_duplicate_candidate(
        {**base, "evidence_kinds": ["made_up_kind"]}
    )
    assert any("未知形态" in v for v in violations)
    # 空证据列表
    violations = rds.validate_replay_duplicate_candidate({**base, "evidence_kinds": []})
    assert any("不能为空" in v for v in violations)
    # 缺必需字段 / 非映射
    assert any("缺少必需字段" in v for v in rds.validate_replay_duplicate_candidate({}))
    assert rds.validate_replay_duplicate_candidate("nope") != []


def test_injection_category_routing_violation():
    rows, summaries, violations = rds.screen_replay_duplicate_observations(
        [
            {
                "category": "sql",
                "applicability": "applicable",
                "endpoint": "/api/v1/items",
                "source": "runs/demo/evidence/api/items.json",
            }
        ]
    )
    assert rows == []  # 违例观察不产出行
    assert len(summaries) == 4  # all_categories=True 仍产出全类别零计数汇总
    assert any("属注入域" in v and "不双计" in v for v in violations)


def test_screening_source_and_version_violations():
    no_source = {
        "category": "repeat_deduction",
        "applicability": "applicable",
        "evidence": {"duplicate_deduction_confirmed": True},
    }
    rows, _, violations = rds.screen_replay_duplicate_observations([no_source])
    assert len(rows) == 1
    assert any("缺少来源" in v for v in violations)
    bad_version = {
        **CONSUMPTION_CONFIRMED_OBS,
        "observation_schema_version": "9.9",
    }
    _, _, violations = rds.screen_replay_duplicate_observations([bad_version])
    assert any("observation_schema_version" in v and "不符" in v for v in violations)
    bad_applicability = {
        **CONSUMPTION_CONFIRMED_OBS,
        "applicability": "maybe",
    }
    _, _, violations = rds.screen_replay_duplicate_observations([bad_applicability])
    assert any("applicability 非法" in v for v in violations)


def test_screening_rows_summaries_and_stats_separation():
    rows, summaries, violations = rds.screen_replay_duplicate_observations(
        [
            CONSUMPTION_CONFIRMED_OBS,
            {
                "endpoint": "/api/v1/rewards/claim",
                "object_ref": "reward:u1",
                "category": "repeat_grant",
                "applicability": "applicable",
                "evidence": {
                    "duplicate_request_accepted_observed": True,
                    "response_similarity_observed": True,
                },
                "source": "runs/demo/evidence/logic/reward-claims.json",
                "reason": "仅重复请求被接受的形态观察",
            },
            {
                "category": "repeat_deduction",
                "applicability": "not_applicable",
                "source": "runs/demo/evidence/logic/no-payment.json",
                "reason": "目标流程无支付环节",
            },
        ]
    )
    assert violations == []
    by_id = {r["candidate_id"]: r for r in rows}
    assert by_id["rd-0001"]["status"] == "candidate"
    assert by_id["rd-0002"]["status"] == "signal"
    consumption, grant, deduction, approval = summaries
    # 三统计概念分离：category_status / applicability_counts / status_counts / tested_count
    assert consumption["category_status"] == "tested"
    assert consumption["status_counts"]["candidate"] == 1
    assert consumption["tested_count"] == 1
    assert consumption["applicability_counts"] == {
        "applicable": 1,
        "not_applicable": 0,
        "unknown": 0,
    }
    assert consumption["precondition"] != ""  # candidate>0 时 precondition 非空
    assert grant["category_status"] == "inconclusive"
    assert grant["status_counts"]["signal"] == 1 and grant["tested_count"] == 0
    assert deduction["category_status"] == "not_applicable"
    assert "无支付环节" in deduction["reason"]
    assert approval["category_status"] == "inconclusive"
    assert all(s["category"] in rds.REPLAY_DUPLICATE_CATEGORIES for s in summaries)


def test_summary_candidate_requires_precondition_negative():
    """构造 candidate>0 但 precondition 为空的汇总行 → 校验拒绝（既有契约负例）。"""
    bad_summary = {
        "category": "repeat_consumption",
        "category_status": "tested",
        "applicability_counts": {"applicable": 1, "not_applicable": 0, "unknown": 0},
        "status_counts": {s: 0 for s in ic.CANDIDATE_STATUS_VALUES}
        | {"candidate": 1},
        "tested_count": 1,
        "reason": "x",
        "source": "runs/demo/evidence/logic/redeem-records.json",
        "precondition": "",
    }
    violations = ic.validate_category_summary(
        bad_summary, categories=rds.REPLAY_DUPLICATE_CATEGORIES
    )
    assert any("precondition 为空" in v for v in violations)


def test_redline_constants():
    assert "重复点击一次" in rds.SINGLE_REPEAT_NOT_RACE_RULE
    assert "重复消费/发放/扣款/审批结果" in rds.SINGLE_REPEAT_NOT_RACE_RULE
    assert "并发" in rds.NO_CONCURRENT_VALIDATION_RULE
    for confirmed in (
        "duplicate_consumption_confirmed",
        "duplicate_grant_confirmed",
        "duplicate_deduction_confirmed",
        "duplicate_approval_confirmed",
    ):
        assert "不发起并发/重复轰炸验证" in rds.REPLAY_DUPLICATE_OBSERVATION_FIELD_DOCS[confirmed]


def test_csv_fields_contract():
    assert rds.REPLAY_DUPLICATE_REVIEW_CSV_FIELDS == (
        "candidate_id",
        "category",
        "status",
        "evidence_kinds",
        "source",
        "evidence_ref",
        "precondition",
        "reason",
    )


def test_engine_single_source_reference():
    """模块复用 ic 单一引擎（rule_satisfied/8 状态/汇总校验），不重复实现。"""
    source = Path(rds.__file__).read_text(encoding="utf-8")
    assert "from authorized_assessment.triage import injection_candidates as ic" in source
    assert "ic.rule_satisfied" in source
    assert "ic.validate_category_summary" in source
    assert "ic.aggregate_category_status" in source
