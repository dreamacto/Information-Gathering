"""tests/test_response_baseline.py —— 规格 4.1 固定路径基线降噪验收。

覆盖：规格 1082-1091 行默认输出字段、六条升级证据正反例（1093-1100 行）、
13.2 负例（通用 200 错误页/登录页/WAF/403/429）、无基线 fail-closed、
校验器负例、两个 CLI 集成（默认参数网络行为不变、基线抓取 opt-in 计数）。
全部离线：不发起任何网络请求（capture_baselines 用 monkeypatch 替身）。
"""
from __future__ import annotations

import json

import pytest

from authorized_assessment.triage import response_baseline as rb
from authorized_assessment.triage.response_baseline import (
    PROMOTION_CRITERIA,
    build_baseline_profile,
    classify_fixed_path,
    compare_fixed_path,
    detect_known_false_positive_pattern,
    evaluate_promotion,
    load_baseline_profiles,
    response_similarity,
    summarize_body,
    validate_fixed_path_result,
)

ENV_TEXT = "DB_HOST=localhost\nDB_PASSWORD=<redacted>\nAPP_KEY=<redacted>\n"
HOME_TEXT = "<html><body>welcome to example.com home page</body></html>"
LOGIN_TEXT = (
    "<html><title>登录</title><body><form action='/login'>"
    "<input name='username'><input name='password'></form></body></html>"
)
ERROR_TEXT = "<html><body><h1>404 Not Found</h1><p>page not found</p></body></html>"


def env_record(**overrides):
    record = {
        "url": "http://example.com/.env",
        "path": "/.env",
        "status": 200,
        "content_type": "text/plain",
        "title": "",
        "sample_sha256": "a" * 64,
        "text": ENV_TEXT,
    }
    record.update(overrides)
    return record


def home_baseline(**overrides):
    record = {
        "url": "http://example.com/",
        "origin": "http://example.com",
        "status": 200,
        "content_type": "text/html",
        "title": "Example.com Home",
        "sample_sha256": "b" * 64,
        "text": HOME_TEXT,
    }
    record.update(overrides)
    return build_baseline_profile(record, kind=record.pop("baseline_kind", "target_baseline"))


PROMOTING_KWARGS = {"reproducible": True, "impact_hypothesis": "配置文件暴露数据库连接串（测试占位）"}


def test_default_output_fields_for_unbaselined_fixed_path():
    assessment = classify_fixed_path(env_record(), [])
    # 规格 1082-1091 行默认输出字段全集
    assert assessment["signal_type"] == "fixed_path"
    assert assessment["confidence"] == "low"
    assert assessment["promotion_status"] == "not_promoted"
    assert assessment["baseline_similarity"] == 0.0
    assert isinstance(assessment["body_semantic_match"], bool)
    assert assessment["known_false_positive_pattern"] is None
    assert assessment["baseline_available"] is False
    assert validate_fixed_path_result(assessment) == []


def test_no_baseline_fail_closed():
    assessment = classify_fixed_path(env_record(), [])
    criteria = {c["criterion"]: c for c in assessment["promotion"]["criteria"]}
    assert criteria["stable_baseline_difference"]["satisfied"] is False
    assert criteria["stable_baseline_difference"]["reason"] == "no_baseline_records"
    assert assessment["promotion"]["promoted"] is False
    assert "stable_baseline_difference" in assessment["promotion"]["remaining_blockers"]


def test_generic_200_error_page_detected():
    record = env_record(url="http://example.com/backup", path="/backup", text=ERROR_TEXT)
    assert detect_known_false_positive_pattern(record) == "generic_200_error_page"
    assessment = classify_fixed_path(record, [home_baseline()], **PROMOTING_KWARGS)
    assert assessment["known_false_positive_pattern"] == "generic_200_error_page"
    assert assessment["promotion_status"] == "not_promoted"
    assert assessment["confidence"] == "low"


def test_login_page_detected():
    record = env_record(url="http://example.com/admin", path="/admin", text=LOGIN_TEXT, title="登录")
    assert detect_known_false_positive_pattern(record) == "login_page"
    assessment = classify_fixed_path(record, [home_baseline()], **PROMOTING_KWARGS)
    assert assessment["known_false_positive_pattern"] == "login_page"
    assert assessment["promotion_status"] == "not_promoted"


def test_login_form_without_title_still_detected():
    record = env_record(text=LOGIN_TEXT)
    assert detect_known_false_positive_pattern(record) == "login_page"


def test_env_config_lines_not_misclassified_as_login():
    # DB_PASSWORD= 行含 password 字样但无 <form → 不得误判登录页（规格 4.1 稳定差异前提）
    assert detect_known_false_positive_pattern(env_record()) is None


@pytest.mark.parametrize("status", [403, 429])
def test_waf_block_pages_detected(status):
    record = env_record(status=status, text="request blocked by waf")
    assert detect_known_false_positive_pattern(record) == "waf_block_page"
    assessment = classify_fixed_path(record, [home_baseline()], **PROMOTING_KWARGS)
    assert assessment["known_false_positive_pattern"] == "waf_block_page"
    assert assessment["promotion_status"] == "not_promoted"


def test_cdn_challenge_page_detected():
    record = env_record(text="Checking your browser before accessing. captcha required")
    assert detect_known_false_positive_pattern(record) == "cdn_challenge_page"


def test_empty_success_page_detected():
    assert detect_known_false_positive_pattern(env_record(text="")) == "empty_success_page"


def test_identical_baseline_blocks_promotion():
    same_baseline = home_baseline(text=ENV_TEXT, sha="a" * 64, content_type="text/plain", title="")
    assessment = classify_fixed_path(env_record(), [same_baseline], **PROMOTING_KWARGS)
    assert assessment["baseline_similarity"] == 1.0
    criteria = {c["criterion"]: c for c in assessment["promotion"]["criteria"]}
    assert criteria["stable_baseline_difference"]["satisfied"] is False
    assert assessment["promotion_status"] == "not_promoted"


def test_all_six_criteria_promote_to_candidate():
    assessment = classify_fixed_path(env_record(), [home_baseline()], **PROMOTING_KWARGS)
    assert assessment["promotion"]["promoted"] is True
    assert assessment["promotion"]["remaining_blockers"] == []
    assert assessment["promotion_status"] == "promoted_candidate"
    assert assessment["confidence"] == "medium"
    assert validate_fixed_path_result(assessment) == []


@pytest.mark.parametrize(
    "overrides, kwargs, blocker",
    [
        # 1 稳定差异：基线内容与响应近乎一致
        ({"text": HOME_TEXT, "sample_sha256": "b" * 64}, PROMOTING_KWARGS, "stable_baseline_difference"),
        # 2 Content-Type 与资源类型不一致：/.env 返回 HTML
        ({"content_type": "text/html"}, PROMOTING_KWARGS, "content_type_matches_resource"),
        ({"content_type": ""}, PROMOTING_KWARGS, "content_type_matches_resource"),
        # 3 相互支持信号不足：other 家族且无语义标记
        (
            {"url": "http://example.com/random/path.bin", "path": "/random/path.bin", "text": "hello world"},
            PROMOTING_KWARGS,
            "mutually_supporting_signals",
        ),
        # 4 已知误报页：登录页 body
        ({"text": LOGIN_TEXT}, PROMOTING_KWARGS, "not_known_false_positive_page"),
        # 5 不可低预算复现
        ({}, {"reproducible": False, "impact_hypothesis": "配置文件暴露数据库连接串（测试占位）"},
         "low_budget_reproducible"),
        # 6 无明确影响假设
        ({}, {"reproducible": True, "impact_hypothesis": "  "}, "explicit_impact_hypothesis"),
    ],
)
def test_missing_any_criterion_blocks_promotion(overrides, kwargs, blocker):
    baselines = [home_baseline()] if blocker != "stable_baseline_difference" else [home_baseline()]
    assessment = classify_fixed_path(env_record(**overrides), baselines, **kwargs)
    assert assessment["promotion_status"] == "not_promoted"
    assert assessment["confidence"] == "low"
    assert blocker in assessment["promotion"]["remaining_blockers"]
    criteria = {c["criterion"]: c for c in assessment["promotion"]["criteria"]}
    assert criteria[blocker]["satisfied"] is False


def test_similarity_deterministic_and_bounded():
    profile_env = build_baseline_profile(env_record(), kind="target_baseline")
    profile_home = home_baseline()
    first = response_similarity(profile_env, profile_home)
    second = response_similarity(profile_env, profile_home)
    assert first == second
    assert 0.0 <= first <= 1.0
    assert response_similarity(profile_env, profile_env) == 1.0
    assert response_similarity(profile_env, profile_home) == 0.0


def test_body_semantic_match_requires_family_markers():
    assessment = compare_fixed_path(env_record(), [home_baseline()])
    assert assessment["body_semantic_match"] is True  # env 行匹配 ^[A-Z_]+= 语义标记
    other = compare_fixed_path(
        env_record(url="http://example.com/x.bin", path="/x.bin", text="hello"), [home_baseline()]
    )
    assert other["body_semantic_match"] is False


def test_compare_reports_compared_against_kinds():
    baselines = [home_baseline(), home_baseline(baseline_kind="generic_error_page")]
    comparison = compare_fixed_path(env_record(), baselines)
    assert comparison["compared_against"] == ["target_baseline", "generic_error_page"]
    assert comparison["baseline_available"] is True


def test_validator_rejects_tampered_results():
    base = classify_fixed_path(env_record(), [home_baseline()], **PROMOTING_KWARGS)

    missing = dict(base)
    del missing["confidence"]
    assert any("missing required field" in e for e in validate_fixed_path_result(missing))

    bad_enum = dict(base)
    bad_enum["confidence"] = "high"
    assert any("confidence not in enum" in e for e in validate_fixed_path_result(bad_enum))

    bad_status = dict(base)
    bad_status["promotion_status"] = "promoted"
    assert any("promotion_status not in enum" in e for e in validate_fixed_path_result(bad_status))

    out_of_range = dict(base)
    out_of_range["baseline_similarity"] = 1.5
    assert any("baseline_similarity" in e for e in validate_fixed_path_result(out_of_range))

    bad_fp = dict(base)
    bad_fp["known_false_positive_pattern"] = "made_up_pattern"
    assert any("known_false_positive_pattern not in enum" in e for e in validate_fixed_path_result(bad_fp))

    inconsistent = dict(base)
    inconsistent["promotion_status"] = "promoted_candidate"
    inconsistent["promotion"] = dict(base["promotion"], promoted=False)
    assert validate_fixed_path_result(inconsistent)

    fake_promotion = {
        "promoted": True,
        "criteria": [
            {"criterion": name, "satisfied": name != PROMOTION_CRITERIA[0], "reason": "x"}
            for name in PROMOTION_CRITERIA
        ],
        "remaining_blockers": [],
    }
    tampered = dict(base)
    tampered["promotion"] = fake_promotion
    assert any("all six promotion criteria" in e for e in validate_fixed_path_result(tampered))

    credential_key = dict(base)
    credential_key["session_id_hint"] = "value"
    assert any("credential-like key" in e for e in validate_fixed_path_result(credential_key))

    assert validate_fixed_path_result("not a dict")


def test_baseline_profile_rejects_unknown_kind():
    with pytest.raises(ValueError):
        build_baseline_profile(env_record(), kind="made_up_kind")


def test_load_baseline_profiles_roundtrip_and_negative(tmp_path):
    rows = [
        home_baseline(),
        home_baseline(baseline_kind="generic_error_page"),
    ]
    path = tmp_path / "baselines.jsonl"
    path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows), encoding="utf-8")
    loaded = load_baseline_profiles(path)
    assert len(loaded) == 2
    assert {row["baseline_kind"] for row in loaded} == {"target_baseline", "generic_error_page"}

    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"baseline_kind": "made_up"}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_baseline_profiles(bad)


def test_readonly_confirm_cli_defaults_keep_network_behavior():
    from authorized_assessment.triage import readonly_endpoint_confirm as cli

    args = cli.build_parser().parse_args(["--urls", "u.txt", "--out", "o.jsonl"])
    assert args.with_baseline is False
    assert args.baseline_file is None
    assert args.delay == 2.0  # 既有默认速率不变

    record = cli.attach_fixed_path_assessment(
        env_record(), text=ENV_TEXT, baselines=[]
    )
    assert record["fixed_path_assessment"]["promotion_status"] == "not_promoted"
    assert validate_fixed_path_result(record["fixed_path_assessment"]) == []


def test_readonly_confirm_capture_baselines_makes_two_requests(monkeypatch):
    from authorized_assessment.triage import readonly_endpoint_confirm as cli

    calls = []

    def fake_fetch(url, timeout, baselines=None):
        calls.append(url)
        return {
            "url": url,
            "status": 200,
            "content_type": "text/html",
            "title": "t",
            "sample_sha256": "c" * 64,
            "text": HOME_TEXT,
        }

    monkeypatch.setattr(cli, "fetch", fake_fetch)
    profiles = cli.capture_baselines("http://example.com/.env", 1.0)
    assert len(calls) == 2  # 每 origin 恰好 2 个基线 GET（opt-in 才发生）
    assert [p["baseline_kind"] for p in profiles] == ["target_baseline", "generic_error_page"]
    assert all(p["origin"] == "http://example.com" for p in profiles)


def test_deep_triage_attachment_coexists_with_classifier():
    from authorized_assessment.triage import deep_readonly_triage as cli

    record = env_record()
    cli.attach_fixed_path_assessment(record, baselines=[])
    assert "fixed_path_assessment" in record
    classified = cli.classify_config(record)
    # classify_* 弹出 text 后，fixed_path_assessment 保留且分类行为不变
    assert "text" not in classified
    assert classified["category"] in {"sensitive_config_exposed", "config_exposed_no_secret"}
    assert classified["fixed_path_assessment"]["signal_type"] == "fixed_path"
    assert validate_fixed_path_result(classified["fixed_path_assessment"]) == []


def test_deep_triage_cli_defaults_keep_network_behavior():
    from authorized_assessment.triage import deep_readonly_triage as cli

    args = cli.build_parser().parse_args(["--targets", "t.txt", "--out", "o.jsonl"])
    assert args.with_baseline is False
    assert args.baseline_file is None
    assert args.delay == 3.0  # 既有默认速率不变


def test_summarize_body_deterministic():
    lines_first = summarize_body("A\nb \n\nA")
    lines_second = summarize_body("A\nb \n\nA")
    assert lines_first == lines_second == ["a", "b"]
