"""tests/test_websocket_review.py —— WebSocket 复核筛选测试（batch7_1，规格 5.3 + 2.7/11.3）。

覆盖：统一筛选模式（观察键→证据形态→rule_satisfied→8 状态分级）；形态观察
（Origin 回显/明文 ws 存在）永不升级；升级正例（跨 Origin 连接收数据/明文敏感数据/
匿名收消息/跨用户消息）；注入类别路由违例；适用性优先与汇总行三统计概念分离；
来源强制与版本不符。纯离线数据变换，不建立任何连接。
"""
from __future__ import annotations

from authorized_assessment.triage import injection_candidates as ic
from authorized_assessment.triage import websocket_review as wr


def _obs(**overrides):
    obs = {
        "endpoint": "wss://target.example.com/realtime",
        "category": "origin_validation",
        "applicability": "applicable",
        "evidence": {"origin_echo_observed": True},
        "evidence_ref": "runs/demo/evidence/ws/origin-echo.json",
        "source": "runs/demo/evidence/ws/origin-echo.json",
        "reason": "服务端对任意 Origin 头均回显允许",
    }
    obs.update(overrides)
    return obs


def test_origin_echo_never_upgrades():
    rows, summaries, violations = wr.screen_websocket_observations([_obs()])
    assert rows[0]["status"] == "signal"
    assert rows[0]["evidence_kinds"] == ["origin_echo"]
    assert violations == []
    summary = next(s for s in summaries if s["category"] == "origin_validation")
    assert summary["category_status"] == "inconclusive"
    assert summary["tested_count"] == 0


def test_cross_origin_connect_upgrades():
    rows, _, violations = wr.screen_websocket_observations(
        [
            _obs(
                evidence={"origin_echo_observed": True, "cross_origin_connect_confirmed": True},
                evidence_ref="runs/demo/evidence/ws/cross-origin.json",
                precondition="浏览器外伪造 Origin 的连接脚本与抓包",
            )
        ]
    )
    assert rows[0]["status"] == "candidate"
    assert violations == []


def test_cleartext_ws_observed_alone_never_upgrades():
    rows, _, violations = wr.screen_websocket_observations(
        [
            _obs(
                category="cleartext_transport",
                evidence={"cleartext_ws_observed": True},
                reason="ws:// 明文通道存在",
            )
        ]
    )
    assert rows[0]["status"] == "signal"
    assert violations == []


def test_cleartext_sensitive_data_upgrades():
    rows, _, violations = wr.screen_websocket_observations(
        [
            _obs(
                category="cleartext_transport",
                evidence={"cleartext_sensitive_data_confirmed": True},
                evidence_ref="runs/demo/evidence/ws/cleartext-token.json",
                source="runs/demo/evidence/ws/cleartext-token.json",
                precondition="明文通道抓包显示会话凭据",
            )
        ]
    )
    assert rows[0]["status"] == "candidate"
    assert violations == []


def test_unauthenticated_message_access_upgrades_channel_authentication():
    rows, _, violations = wr.screen_websocket_observations(
        [
            _obs(
                category="channel_authentication",
                evidence={"unauthenticated_message_access_confirmed": True},
                evidence_ref="runs/demo/evidence/ws/anon-messages.json",
                source="runs/demo/evidence/ws/anon-messages.json",
                precondition="无凭据连接订阅私有频道",
            )
        ]
    )
    assert rows[0]["status"] == "candidate"
    assert violations == []


def test_cross_user_message_access_upgrades_channel_authentication():
    rows, _, violations = wr.screen_websocket_observations(
        [
            _obs(
                category="channel_authentication",
                evidence={"cross_user_message_access_confirmed": True},
                evidence_ref="runs/demo/evidence/ws/cross-user.json",
                source="runs/demo/evidence/ws/cross-user.json",
                precondition="用户 A 订阅用户 B 私信频道",
            )
        ]
    )
    assert rows[0]["status"] == "candidate"
    assert violations == []


def test_differential_alone_never_upgrades():
    rows, _, violations = wr.screen_websocket_observations(
        [
            _obs(
                category="channel_authentication",
                evidence={"differential_observed": True, "semantic_anomaly_observed": True},
            )
        ]
    )
    assert rows[0]["status"] == "signal"
    assert violations == []


def test_injection_category_routed_to_injection_domain():
    rows, summaries, violations = wr.screen_websocket_observations(
        [_obs(category="sql", evidence={"differential_observed": True})]
    )
    assert rows == []
    assert any("sql" in v and "injection_candidate_screening" in v for v in violations)
    assert all(s["tested_count"] == 0 for s in summaries)


def test_unknown_category_violation():
    rows, _, violations = wr.screen_websocket_observations([_obs(category="graphql_ws")])
    assert rows == []
    assert any("category 非法" in v for v in violations)


def test_candidate_missing_evidence_ref_violation():
    row = {
        "candidate_id": "ws-0001",
        "category": "origin_validation",
        "status": "candidate",
        "evidence_kinds": ["cross_origin_connect"],
        "source": "proxy",
        "evidence_ref": "",
    }
    violations = wr.validate_websocket_candidate(row)
    assert any("evidence_ref 为空" in v for v in violations)


def test_candidate_with_insufficient_only_evidence_rejected():
    row = {
        "candidate_id": "ws-0002",
        "category": "cleartext_transport",
        "status": "candidate",
        "evidence_kinds": ["cleartext_ws"],
        "source": "proxy",
        "evidence_ref": "runs/demo/evidence/ws/x.json",
    }
    violations = wr.validate_websocket_candidate(row)
    assert any("升级证据不满足" in v for v in violations)


def test_status_hint_respected_and_invalid_falls_back():
    hint_obs = _obs(
        category="channel_authentication",
        evidence={"differential_observed": True},
        status_hint="needs_manual_validation",
    )
    rows, _, violations = wr.screen_websocket_observations([hint_obs])
    assert rows[0]["status"] == "needs_manual_validation"
    assert violations == []
    bad_hint = {**hint_obs, "status_hint": "vulnerable_for_sure"}
    rows, _, _ = wr.screen_websocket_observations([bad_hint])
    assert rows[0]["status"] == "signal"


def test_not_applicable_observation_counts_only():
    rows, summaries, violations = wr.screen_websocket_observations(
        [_obs(applicability="not_applicable", reason="目标无 WebSocket 面（JS 无标记）")]
    )
    assert rows == []
    assert violations == []
    summary = next(s for s in summaries if s["category"] == "origin_validation")
    assert summary["applicability_counts"]["not_applicable"] == 1
    assert summary["category_status"] == "not_applicable"


def test_missing_source_violation():
    rows, _, violations = wr.screen_websocket_observations(
        [_obs(source="", endpoint="", evidence_ref="")]
    )
    assert rows
    assert any("缺少来源" in v for v in violations)


def test_observation_version_mismatch_violation():
    _, _, violations = wr.screen_websocket_observations([_obs(observation_schema_version="0.9")])
    assert any("observation_schema_version" in v for v in violations)


def test_summaries_cover_all_categories_and_pass_shared_validator():
    rows, summaries, violations = wr.screen_websocket_observations(
        [
            _obs(
                evidence={"cross_origin_connect_confirmed": True},
                evidence_ref="runs/demo/evidence/ws/cross-origin.json",
                precondition="伪造 Origin 连接",
            )
        ]
    )
    assert len(summaries) == 3
    assert {s["category"] for s in summaries} == set(wr.WEBSOCKET_CATEGORIES)
    assert violations == []
    for summary in summaries:
        assert (
            ic.validate_category_summary(
                summary, label="check", categories=wr.WEBSOCKET_CATEGORIES
            )
            == []
        )
    tested = next(s for s in summaries if s["category"] == "origin_validation")
    assert tested["tested_count"] == sum(
        tested["status_counts"][s] for s in ic.DEFINITIVE_RESULT_STATUSES
    )
    tested["tested_count"] = 3
    assert ic.validate_category_summary(
        tested, label="check", categories=wr.WEBSOCKET_CATEGORIES
    )
