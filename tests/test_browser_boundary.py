"""tests/test_browser_boundary.py —— 浏览器边界只读复核测试（batch7_2，规格 5.4 + 3.1）。

覆盖：观察键→证据形态确定性映射、升级边界（13 形态永不升级、6 确认形态才升级、
类别确认形态不可跨类别升级）、8 状态分级与 status_hint、候选行校验、筛选汇总
（三统计概念分离 + 注入路由违例）、报告构建/解析往返与确定性、规格 5.4 明示产物
路径登记。纯离线数据变换，不发请求、不渲染页面、不执行 JS。
"""
from __future__ import annotations

from authorized_assessment.triage import browser_boundary as bb
from authorized_assessment.triage import input_testing as itp
from authorized_assessment.triage import injection_candidates as ic

FORM_EVIDENCE = {
    "cors_origin_reflection_observed": True,
    "cors_credentials_allowed_observed": True,
    "preflight_broad_accept_observed": True,
}

CORS_READ_CONFIRMED_OBS = {
    "endpoint": "/api/profile",
    "category": "cors_policy",
    "applicability": "applicable",
    "evidence": {**FORM_EVIDENCE, "cors_cross_origin_read_confirmed": True},
    "source": "runs/demo/evidence/cors/read.json",
    "evidence_ref": "runs/demo/evidence/cors/read.json:L12",
    "reason": "跨站上下文实际读取到带凭证私有响应",
    "precondition": "受害者持有有效会话；确认读取经授权演练环境录得",
}

CSRF_FORM_OBS = {
    "endpoint": "/api/password/change",
    "category": "csrf_protection",
    "applicability": "applicable",
    "evidence": {
        "csrf_token_missing_observed": True,
        "samesite_none_observed": True,
        "origin_referer_unchecked_observed": True,
    },
    "source": "runs/demo/evidence/csrf/form.json",
    "reason": "写端点缺 token 且不校验 Origin（仅形态）",
}


def test_derive_evidence_kinds_maps_observation_keys():
    kinds = bb.derive_browser_boundary_evidence_kinds(
        {"redirect_param_reflected_observed": True, "differential_observed": True}
    )
    assert kinds == ["redirect_param_reflected", "differential"]
    assert bb.derive_browser_boundary_evidence_kinds({}) == []
    assert bb.derive_browser_boundary_evidence_kinds({"unknown_key": True}) == []


def test_grade_form_observations_never_upgrade():
    """仅配置/形态观察（反射 Origin + credentials + preflight）永不升级。"""
    kinds = bb.derive_browser_boundary_evidence_kinds(FORM_EVIDENCE)
    assert bb.grade_browser_boundary_observation("cors_policy", kinds) == "signal"


def test_grade_confirmed_cross_origin_read_upgrades():
    kinds = bb.derive_browser_boundary_evidence_kinds(CORS_READ_CONFIRMED_OBS["evidence"])
    assert bb.grade_browser_boundary_observation("cors_policy", kinds) == "candidate"


def test_grade_each_category_requires_own_confirmation():
    """六类别各自的确认形态才升级；他类确认形态不跨界升级。"""
    confirmations = {
        "cors_policy": "cors_cross_origin_read_confirmed",
        "csrf_protection": "csrf_cross_user_action_confirmed",
        "cache_privacy": "cached_sensitive_data_confirmed",
        "clickjacking_protection": "clickjacking_action_confirmed",
        "open_redirect": "external_redirect_confirmed",
        "postmessage_origin": "postmessage_cross_origin_data_confirmed",
    }
    for category, kind in confirmations.items():
        assert bb.grade_browser_boundary_observation(category, [kind]) == "candidate"
    # 形态观察 + 他类确认形态 → 仍 signal
    assert bb.grade_browser_boundary_observation("cors_policy", ["csrf_token_missing"]) == "signal"
    assert bb.grade_browser_boundary_observation("cache_privacy", ["framing_not_denied"]) == "signal"


def test_grade_status_hint_respected():
    kinds = bb.derive_browser_boundary_evidence_kinds(FORM_EVIDENCE)
    assert (
        bb.grade_browser_boundary_observation("cors_policy", kinds, "needs_manual_validation")
        == "needs_manual_validation"
    )


def test_validate_candidate_unknown_kind_and_category():
    violations = bb.validate_browser_boundary_candidate(
        {
            "candidate_id": "bb-0001",
            "category": "ghost",
            "status": "signal",
            "evidence_kinds": ["not_a_kind"],
            "source": "s",
        }
    )
    assert any("category 非法" in v for v in violations)
    assert any("未知形态" in v for v in violations)


def test_validate_candidate_requires_upgrade_evidence():
    """status=candidate 但仅有形态证据 → 违例（永不升级边界）。"""
    violations = bb.validate_browser_boundary_candidate(
        {
            "candidate_id": "bb-0002",
            "category": "open_redirect",
            "status": "candidate",
            "evidence_kinds": ["redirect_param_reflected"],
            "source": "s",
            "evidence_ref": "e.json",
        }
    )
    assert any("升级证据不满足" in v for v in violations)


def test_validate_candidate_requires_evidence_ref():
    for status in ("candidate", "confirmed", "needs_manual_validation"):
        violations = bb.validate_browser_boundary_candidate(
            {
                "candidate_id": "bb-0003",
                "category": "postmessage_origin",
                "status": status,
                "evidence_kinds": ["postmessage_cross_origin_data_confirmed"],
                "source": "s",
            }
        )
        assert any("evidence_ref 为空" in v for v in violations), status


def test_screen_candidate_and_summary_counts():
    signal_obs = {
        "endpoint": "/api/list",
        "category": "cors_policy",
        "applicability": "applicable",
        "evidence": dict(FORM_EVIDENCE),
        "source": "runs/demo/evidence/cors/headers.json",
        "reason": "仅反射形态",
    }
    rows, summaries, violations = bb.screen_browser_boundary_observations(
        [CORS_READ_CONFIRMED_OBS, signal_obs]
    )
    assert violations == []
    assert [r["status"] for r in rows] == ["candidate", "signal"]
    assert [r["candidate_id"] for r in rows] == ["bb-0001", "bb-0002"]
    cors_summary = next(s for s in summaries if s["category"] == "cors_policy")
    assert cors_summary["status_counts"]["candidate"] == 1
    assert cors_summary["status_counts"]["signal"] == 1
    assert cors_summary["tested_count"] == 1  # signal 不算 tested
    assert cors_summary["applicability_counts"] == {
        "applicable": 2,
        "not_applicable": 0,
        "unknown": 0,
    }
    # all_categories 缺省：六类别汇总行齐备，其余类别为 inconclusive/0
    assert [s["category"] for s in summaries] == list(bb.BROWSER_BOUNDARY_CATEGORIES)
    other = next(s for s in summaries if s["category"] == "csrf_protection")
    assert other["category_status"] == "inconclusive"
    assert other["tested_count"] == 0


def test_screen_not_applicable_needs_reason_and_stays_out_of_rows():
    na_obs = {
        "category": "open_redirect",
        "applicability": "not_applicable",
        "reason": "目标为服务端固定跳转，无可控重定向参数",
    }
    rows, summaries, violations = bb.screen_browser_boundary_observations([na_obs])
    assert violations == []
    assert rows == []
    summary = next(s for s in summaries if s["category"] == "open_redirect")
    assert summary["category_status"] == "not_applicable"
    assert summary["applicability_counts"]["not_applicable"] == 1
    assert "固定跳转" in summary["reason"]

    # "not_applicable 需 reason" 为汇总行级契约（batch6_4 锁定），非观察级：
    # 筛选层对 na 无 reason 的观察以默认 reason 兜底，不记违例；
    # 汇总行 category_status=not_applicable 而 reason 为空由 validate_category_summary 拒绝。
    _, _, violations = bb.screen_browser_boundary_observations([dict(na_obs, reason="")])
    assert violations == []
    bad_summary = dict(summary, reason="")
    violations = ic.validate_category_summary(
        bad_summary, label="summary", categories=bb.BROWSER_BOUNDARY_CATEGORIES
    )
    assert any("category_status=not_applicable 但 reason 为空" in v for v in violations)


def test_screen_injection_category_routing_violation():
    obs = {
        "endpoint": "/ws/chat",
        "category": "sql",
        "applicability": "applicable",
        "evidence": {"differential_observed": True},
        "source": "p",
    }
    rows, summaries, violations = bb.screen_browser_boundary_observations([obs])
    assert rows == []
    assert any("injection_candidate_screening" in v and "不双计" in v for v in violations)
    assert all(s["tested_count"] == 0 for s in summaries)


def test_screen_missing_source_violation():
    obs = {
        "category": "clickjacking_protection",
        "applicability": "applicable",
        "evidence": {"framing_not_denied_observed": True},
    }
    rows, _, violations = bb.screen_browser_boundary_observations([obs])
    assert len(rows) == 1
    assert any("缺少来源" in v for v in violations)


def test_screen_version_mismatch_violation():
    obs = dict(CORS_READ_CONFIRMED_OBS, observation_schema_version="0.9")
    _, _, violations = bb.screen_browser_boundary_observations([obs])
    assert any("observation_schema_version" in v for v in violations)
    _, _, violations = bb.screen_browser_boundary_observations(
        [dict(CORS_READ_CONFIRMED_OBS, observation_schema_version=ic.OBSERVATION_SCHEMA_VERSION)]
    )
    assert not any("observation_schema_version" in v for v in violations)


def test_screen_unknown_category_violation():
    obs = {
        "category": "xss",
        "applicability": "applicable",
        "evidence": {"semantic_anomaly_observed": True},
        "source": "p",
    }
    rows, _, violations = bb.screen_browser_boundary_observations([obs])
    assert rows == []
    assert any("category 非法" in v for v in violations)


def test_report_roundtrip_and_domain_field():
    rows, summaries, violations = bb.screen_browser_boundary_observations(
        [CORS_READ_CONFIRMED_OBS]
    )
    assert violations == []
    report = bb.build_browser_boundary_report(summaries, violations)
    payload, err = bb.extract_report_summary(report)
    assert err is None
    assert payload["domain"] == "browser_boundary"
    assert payload["schema_version"] == bb.REPORT_SCHEMA_VERSION
    assert len(payload["category_summaries"]) == 6
    cors_summary = next(
        s for s in payload["category_summaries"] if s["category"] == "cors_policy"
    )
    assert cors_summary["tested_count"] == 1


def test_report_is_deterministic():
    _, summaries, violations = bb.screen_browser_boundary_observations(
        [CORS_READ_CONFIRMED_OBS]
    )
    assert bb.build_browser_boundary_report(summaries, violations) == (
        bb.build_browser_boundary_report(summaries, violations)
    )


def test_extract_report_summary_rejects_broken_blocks():
    assert bb.extract_report_summary("no block here")[0] is None
    assert bb.extract_report_summary("```json\n{\"a\": 1}")[0] is None  # 未闭合
    assert bb.extract_report_summary("```json\nnot json\n```")[0] is None
    assert bb.extract_report_summary("```json\n[1, 2]\n```")[0] is None  # 非对象


def test_spec_artifact_paths_registered():
    """规格 5.4 明示的两件产物必须在编排器登记表内且路径一致。"""
    assert (
        itp.INPUT_TESTING_ARTIFACTS["browser_boundary_jsonl"]
        == "artifacts/browser-boundary/cors-csrf-cache.jsonl"
    )
    assert (
        itp.INPUT_TESTING_ARTIFACTS["browser_boundary_report_md"]
        == "reports/browser-boundary.md"
    )
