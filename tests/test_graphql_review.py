"""tests/test_graphql_review.py —— GraphQL 复核筛选测试（batch7_0，规格 5.3 + 11.3 + 13.2）。

覆盖：统一筛选模式（观察键→证据形态→rule_satisfied→8 状态分级）；公开文档类证据
永不升级（introspection/GraphiQL/schema 可见/字段建议）；授权边界升级正例；差分单独
不升级；注入类别路由违例；适用性优先与汇总行三统计概念分离；来源强制与版本不符。
纯离线数据变换，不发任何请求。
"""
from __future__ import annotations

import json
from pathlib import Path

from authorized_assessment.triage import graphql_review as gr
from authorized_assessment.triage import injection_candidates as ic

ROOT = Path(__file__).resolve().parents[1]


def _introspection_obs(**overrides):
    obs = {
        "endpoint": "https://target.example.com/graphql",
        "category": "introspection_exposure",
        "applicability": "applicable",
        "evidence": {"introspection_enabled_observed": True},
        "evidence_ref": "runs/demo/evidence/graphql/introspection.json",
        "reason": "introspection 查询返回 __schema",
        "source": "runs/demo/evidence/graphql/introspection.json",
    }
    obs.update(overrides)
    return obs


def test_introspection_never_upgrades():
    rows, summaries, violations = gr.screen_graphql_observations([_introspection_obs()])
    assert rows[0]["status"] == "signal"
    assert rows[0]["evidence_kinds"] == ["introspection_enabled"]
    assert all(s["category_status"] in ("inconclusive", "needs_manual_validation", "tested") for s in summaries)
    assert violations == []


def test_all_insufficient_kinds_never_upgrade():
    obs = _introspection_obs(
        category="field_suggestion",
        evidence={
            "introspection_enabled_observed": True,
            "graphiql_exposed_observed": True,
            "field_suggestion_observed": True,
        },
    )
    rows, _, violations = gr.screen_graphql_observations([obs])
    assert rows[0]["status"] == "signal"
    assert violations == []


def test_cross_user_access_upgrades_object_authorization():
    obs = {
        "endpoint": "https://target.example.com/graphql",
        "operation_name": "GetOrder",
        "category": "object_authorization",
        "applicability": "applicable",
        "evidence": {"cross_user_object_access_confirmed": True},
        "evidence_ref": "runs/demo/evidence/graphql/idor/order-a-vs-b.json",
        "reason": "用户 A 上下文取回用户 B 订单可复现",
        "precondition": "两个测试账号的对象引用",
    }
    rows, summaries, violations = gr.screen_graphql_observations([obs])
    assert rows[0]["status"] == "candidate"
    assert violations == []
    summary = next(s for s in summaries if s["category"] == "object_authorization")
    assert summary["category_status"] == "tested"
    assert summary["status_counts"]["candidate"] == 1
    assert summary["tested_count"] == 1
    assert summary["precondition"]


def test_unauthenticated_access_upgrades_object_authorization():
    obs = {
        "endpoint": "/graphql",
        "category": "object_authorization",
        "applicability": "applicable",
        "evidence": {"unauthenticated_data_access_confirmed": True},
        "evidence_ref": "runs/demo/evidence/graphql/anon/user.json",
        "source": "runs/demo/evidence/graphql/anon/user.json",
        "precondition": "匿名上下文可复现取回",
    }
    rows, _, violations = gr.screen_graphql_observations([obs])
    assert rows[0]["status"] == "candidate"
    assert violations == []


def test_differential_alone_never_upgrades():
    """差分/语义异常是支持性观察：用户访问自己的对象不是漏洞（规格 2.7/11.3）。"""
    obs = {
        "endpoint": "/graphql",
        "category": "object_authorization",
        "applicability": "applicable",
        "evidence": {"differential_observed": True, "semantic_anomaly_observed": True},
        "evidence_ref": "runs/demo/evidence/graphql/diff.json",
        "source": "runs/demo/evidence/graphql/diff.json",
    }
    rows, _, violations = gr.screen_graphql_observations([obs])
    assert rows[0]["status"] == "signal"
    assert violations == []


def test_operation_allowed_upgrades_operation_authorization():
    obs = {
        "endpoint": "/graphql",
        "category": "operation_authorization",
        "applicability": "applicable",
        "evidence": {"operation_allowed_confirmed": True},
        "evidence_ref": "runs/demo/evidence/graphql/mutation/admin-op.json",
        "source": "runs/demo/evidence/graphql/mutation/admin-op.json",
        "precondition": "受限变更操作在普通用户上下文执行",
    }
    rows, _, violations = gr.screen_graphql_observations([obs])
    assert rows[0]["status"] == "candidate"
    assert violations == []


def test_injection_category_routed_to_injection_domain():
    """GraphQL 面内注入归 injection_candidate_screening（契约 routing_rule 不双计）。"""
    obs = _introspection_obs(category="sql", evidence={"differential_observed": True})
    rows, summaries, violations = gr.screen_graphql_observations([obs])
    assert rows == []
    assert any("routing_rule" in v and "sql" in v for v in violations)
    # 未产生任何 graphql 候选行：四类别汇总均为空。
    assert all(s["tested_count"] == 0 for s in summaries)


def test_unknown_category_violation():
    rows, _, violations = gr.screen_graphql_observations(
        [_introspection_obs(category="websocket_origin")]
    )
    assert rows == []
    assert any("category 非法" in v for v in violations)


def test_candidate_without_upgrade_rule_rejected():
    """公开文档类类别手工标记 candidate 必须被行校验拒绝。"""
    row = {
        "candidate_id": "gql-0001",
        "category": "introspection_exposure",
        "status": "candidate",
        "evidence_kinds": ["introspection_enabled"],
        "source": "proxy",
        "evidence_ref": "runs/demo/evidence/graphql/introspection.json",
    }
    violations = gr.validate_graphql_candidate(row)
    assert any("永不升级" in v for v in violations)


def test_candidate_missing_evidence_ref_violation():
    row = {
        "candidate_id": "gql-0002",
        "category": "object_authorization",
        "status": "candidate",
        "evidence_kinds": ["cross_user_object_access"],
        "source": "proxy",
        "evidence_ref": "",
    }
    violations = gr.validate_graphql_candidate(row)
    assert any("evidence_ref 为空" in v for v in violations)


def test_status_hint_respected_and_invalid_falls_back():
    hint_obs = {
        "endpoint": "/graphql",
        "category": "object_authorization",
        "applicability": "applicable",
        "evidence": {"differential_observed": True},
        "source": "proxy",
        "evidence_ref": "runs/demo/evidence/graphql/diff.json",
        "status_hint": "needs_manual_validation",
    }
    rows, _, violations = gr.screen_graphql_observations([hint_obs])
    assert rows[0]["status"] == "needs_manual_validation"
    assert violations == []
    bad_hint = {**hint_obs, "status_hint": "surely_vulnerable"}
    rows, _, _ = gr.screen_graphql_observations([bad_hint])
    assert rows[0]["status"] == "signal"  # 非法 hint 回退证据分级


def test_not_applicable_observation_counts_only():
    obs = _introspection_obs(
        applicability="not_applicable", reason="未发现 GraphQL 面（无 graphql 端点标记）"
    )
    rows, summaries, violations = gr.screen_graphql_observations([obs])
    assert rows == []
    assert violations == []
    summary = next(s for s in summaries if s["category"] == "introspection_exposure")
    assert summary["applicability_counts"]["not_applicable"] == 1
    assert summary["applicability_counts"]["applicable"] == 0
    assert summary["category_status"] == "not_applicable"
    assert "未发现 GraphQL 面" in summary["reason"]


def test_missing_source_violation():
    obs = _introspection_obs(source="", endpoint="", evidence_ref="")
    rows, _, violations = gr.screen_graphql_observations([obs])
    assert rows
    assert any("缺少来源" in v for v in violations)


def test_observation_version_mismatch_violation():
    obs = _introspection_obs(observation_schema_version="0.9")
    _, _, violations = gr.screen_graphql_observations([obs])
    assert any("observation_schema_version" in v for v in violations)


def test_summaries_cover_all_four_categories_and_pass_shared_validator():
    obs = {
        "endpoint": "/graphql",
        "category": "object_authorization",
        "applicability": "applicable",
        "evidence": {"cross_user_object_access_confirmed": True},
        "evidence_ref": "runs/demo/evidence/graphql/idor.json",
        "source": "proxy",
        "precondition": "两个测试账号对象引用",
    }
    rows, summaries, violations = gr.screen_graphql_observations([obs])
    assert len(summaries) == 4
    assert {s["category"] for s in summaries} == set(gr.GRAPHQL_CATEGORIES)
    assert violations == []
    for summary in summaries:
        assert ic.validate_category_summary(
            summary, label="check", categories=gr.GRAPHQL_CATEGORIES
        ) == []
    tested = next(s for s in summaries if s["category"] == "object_authorization")
    assert tested["tested_count"] == sum(
        tested["status_counts"][s] for s in ic.DEFINITIVE_RESULT_STATUSES
    )
    # 共享校验器在篡改下必须拒绝（三统计概念分离不被 graphql 域绕过）。
    tested["tested_count"] = 5
    assert ic.validate_category_summary(
        tested, label="check", categories=gr.GRAPHQL_CATEGORIES
    )


def test_observation_schema_version_matches_contract():
    contract = json.loads(
        (ROOT / "contracts" / "graphql_schema.json").read_text(encoding="utf-8")
    )
    assert contract["observation_schema"]["version"] == ic.OBSERVATION_SCHEMA_VERSION
    assert set(contract["observation_schema"]["fields"]) == set(gr.OBSERVATION_FIELD_DOCS)
    assert contract["observation_schema"]["fields"] == gr.OBSERVATION_FIELD_DOCS
