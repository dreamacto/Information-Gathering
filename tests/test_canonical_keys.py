"""tests/test_canonical_keys.py —— 规格 4.2 统一去重键 + 2.7 合并键验收。

覆盖：三套键字段与规格 1102-1153 行逐一精确一致（契约↔模块双向断言）、
2.7 合并器七键与 sqli 参数不敏感规则（460-481 行）、归一化正反例、
identity_hash 确定性、跨 run 五字段常量、校验器负例（含凭证键）。
"""
from __future__ import annotations

import pytest

from authorized_assessment.triage import canonical_keys as ck
from authorized_assessment.triage.canonical_keys import (
    API_KEY_FIELDS,
    CROSS_RUN_RETENTION_FIELDS,
    GENERIC_KEY_FIELDS,
    MERGE_KEY_FIELDS,
    MINIAPP_KEY_FIELDS,
    compute_candidate_identity,
    canonical_host,
    canonical_target,
    generic_candidate_key,
    api_candidate_key,
    identity_hash,
    merge_key,
    miniapp_candidate_key,
    normalize_endpoint,
    validate_candidate_identity,
    validate_merge_key,
)


def test_spec_key_field_sets_match_contract():
    schema = ck.load_identity_schema()
    key_fields = schema["key_fields"]
    assert list(key_fields["generic"]) == list(GENERIC_KEY_FIELDS)
    assert list(key_fields["api"]) == list(API_KEY_FIELDS)
    assert list(key_fields["miniapp"]) == list(MINIAPP_KEY_FIELDS)
    assert list(schema["merge_keys"]["fields"]) == list(MERGE_KEY_FIELDS)
    assert list(schema["cross_run_retention"]["fields"]) == list(CROSS_RUN_RETENTION_FIELDS)


def test_generic_key_fields_exact_per_spec():
    # 规格 4.2 通用键逐字对照
    assert GENERIC_KEY_FIELDS == (
        "canonical_target", "endpoint", "http_method", "parameter_name", "input_location", "test_family",
    )


def test_api_key_fields_exact_per_spec():
    # 规格 4.2 API 键逐字对照
    assert API_KEY_FIELDS == (
        "canonical_host", "normalized_path", "http_method", "parameter_names", "content_type", "source_kind",
    )


def test_miniapp_key_fields_exact_per_spec():
    # 规格 4.2 小程序键逐字对照
    assert MINIAPP_KEY_FIELDS == (
        "miniapp_id", "backend_host", "normalized_path", "http_method", "parameter_names", "package_version",
    )


def test_merge_key_fields_exact_per_spec():
    # 规格 2.7 合并器七键逐字对照
    assert MERGE_KEY_FIELDS == (
        "canonical_target", "product_or_component", "normalized_endpoint", "http_method",
        "vulnerability_family", "root_cause_signature", "parameter_scope",
    )


def test_canonical_target_normalization():
    assert canonical_target("https://Example.com/") == "https://example.com"
    assert canonical_target("http://example.com:80/a") == "http://example.com"
    assert canonical_target("https://example.com:443") == "https://example.com"
    assert canonical_target("https://example.com:8443/x") == "https://example.com:8443"
    assert canonical_target("example.com") == "example.com"


def test_normalize_endpoint_rules():
    assert normalize_endpoint("/API/v1/Users/") == "/api/v1/users"
    assert normalize_endpoint("https://example.com/api?x=1#frag") == "/api"
    assert normalize_endpoint("/") == "/"
    assert normalize_endpoint("//a///b//") == "/a/b"
    assert normalize_endpoint("/user/123/profile") == "/user/{n}/profile"
    assert normalize_endpoint(
        "/u/550e8400-e29b-41d4-a716-446655440000"
    ) == "/u/{uuid}"
    assert normalize_endpoint("/f/deadbeefdeadbeefdeadbeefdeadbeef") == "/f/{hex}"
    # 数字段归一：不同 ID 同端点 → 同键（规格 2.7 不得因 URL 制造多个漏洞）
    assert normalize_endpoint("/user/123") == normalize_endpoint("/user/456")
    # query 不同不改变端点键
    assert normalize_endpoint("/api?a=1") == normalize_endpoint("/api?a=2")


def test_generic_candidate_key_normalizes_and_matches_contract():
    candidate = {
        "identity_kind": "generic",
        "url": "https://Example.com/search?q=1",
        "endpoint": "https://example.com/search?q=1",
        "http_method": "get",
        "parameter_name": " Q ",
        "input_location": "Query",
        "test_family": "sqli",
    }
    identity = compute_candidate_identity(candidate)
    assert identity["identity_kind"] == "generic"
    assert set(identity["key"]) == set(GENERIC_KEY_FIELDS)
    assert identity["key"] == {
        "canonical_target": "https://example.com",
        "endpoint": "/search",
        "http_method": "GET",
        "parameter_name": "q",
        "input_location": "query",
        "test_family": "sqli",
    }
    assert validate_candidate_identity(identity) == []


def test_api_candidate_key_matches_contract():
    candidate = {
        "identity_kind": "api",
        "url": "https://api.example.com:443/v1/Users/42?b=2&a=1",
        "http_method": "POST",
        "parameter_names": ["b", "a", "a"],
        "content_type": "Application/JSON; charset=utf-8",
        "source_kind": "c",
    }
    identity = compute_candidate_identity(candidate)
    assert set(identity["key"]) == set(API_KEY_FIELDS)
    assert identity["key"] == {
        "canonical_host": "api.example.com",
        "normalized_path": "/v1/users/{n}",
        "http_method": "POST",
        "parameter_names": ["a", "b"],
        "content_type": "application/json",
        "source_kind": "C",
    }
    assert validate_candidate_identity(identity) == []


def test_miniapp_candidate_key_matches_contract():
    candidate = {
        "identity_kind": "miniapp",
        "miniapp_id": "WX App-1",
        "backend_host": "https://api.example.com",
        "path": "/mp/orders/",
        "http_method": "GET",
        "parameter_names": ["openid"],
        "package_version": "1.2.3",
    }
    identity = compute_candidate_identity(candidate)
    assert set(identity["key"]) == set(MINIAPP_KEY_FIELDS)
    assert identity["key"]["miniapp_id"] == "wx app-1"
    assert identity["key"]["backend_host"] == "api.example.com"
    assert identity["key"]["normalized_path"] == "/mp/orders"
    assert identity["key"]["package_version"] == "1.2.3"
    assert validate_candidate_identity(identity) == []


def test_identity_hash_deterministic_and_order_insensitive():
    a = api_candidate_key({"url": "https://a.example.com/x", "http_method": "GET",
                           "parameter_names": ["p", "q"], "source_kind": "A",
                           "content_type": "application/json"})
    b = api_candidate_key({"url": "https://a.example.com/x", "http_method": "GET",
                           "parameter_names": ["q", "p"], "source_kind": "A",
                           "content_type": "application/json"})
    assert identity_hash(a) == identity_hash(b)
    assert len(identity_hash(a)) == 64


def test_sqli_merge_key_is_parameter_insensitive():
    base = {
        "canonical_target": "https://example.com",
        "product_or_component": "Acme Portal",
        "http_method": "GET",
        "vulnerability_family": "sqli",
        "root_cause_signature": "string concat in search handler",
    }
    first = merge_key({**base, "normalized_endpoint": "/search", "parameter_scope": "single_parameter"})
    second = merge_key({**base, "normalized_endpoint": "/search", "parameter_scope": "endpoint_all_parameters"})
    # 同一接口多个参数的 SQL 注入合并为一个 finding（规格 2.7）
    assert first == second
    assert first["parameter_scope"] == "endpoint_all_parameters"
    assert validate_merge_key(first) == []


def test_merge_key_non_sqli_keeps_declared_scope():
    finding = {
        "canonical_target": "https://example.com",
        "product_or_component": "Acme Portal",
        "normalized_endpoint": "/api/update",
        "http_method": "POST",
        "vulnerability_family": "idor",
        "root_cause_signature": "missing object ownership check",
        "parameter_scope": "single_parameter",
    }
    result = merge_key(finding)
    assert result["parameter_scope"] == "single_parameter"
    assert validate_merge_key(result) == []


def test_source_kind_eligibility_mapping():
    assert ck.SOURCE_KIND_ELIGIBILITY["queue_eligible"] == ("A", "B", "C")
    assert ck.SOURCE_KIND_ELIGIBILITY["needs_extra_response_evidence"] == ("D",)
    assert ck.SOURCE_KIND_ELIGIBILITY["low_confidence_signal"] == ("E",)
    schema = ck.load_identity_schema()
    assert schema["source_kind_eligibility"]["queue_eligible"] == ["A", "B", "C"]


def test_validator_rejects_tampered_identities():
    good = compute_candidate_identity({
        "identity_kind": "api",
        "url": "https://api.example.com/v1/items",
        "http_method": "GET",
        "parameter_names": ["p"],
        "content_type": "application/json",
        "source_kind": "A",
    })

    missing = dict(good)
    del missing["identity_hash"]
    assert any("missing required field" in e for e in validate_candidate_identity(missing))

    bad_kind = dict(good, identity_kind="web")
    assert any("identity_kind not in enum" in e for e in validate_candidate_identity(bad_kind))

    extra_field = {**good, "key": {**good["key"], "extra": 1}}
    assert any("unexpected key field" in e for e in validate_candidate_identity(extra_field))

    bad_method = {**good, "key": {**good["key"], "http_method": "FETCH"}}
    assert any("http_method not in enum" in e for e in validate_candidate_identity(bad_method))

    bad_source = {**good, "key": {**good["key"], "source_kind": "Z"}}
    assert any("source_kind not in enum" in e for e in validate_candidate_identity(bad_source))

    unsorted = {**good, "key": {**good["key"], "parameter_names": ["b", "a"]}}
    assert any("sorted and deduplicated" in e for e in validate_candidate_identity(unsorted))

    bad_hash = dict(good, identity_hash="0" * 64)
    assert any("identity_hash does not match" in e for e in validate_candidate_identity(bad_hash))

    cred = {**good, "key": {**good["key"]}, "session_token": "x"}
    assert any("credential-like key" in e for e in validate_candidate_identity(cred))

    assert validate_candidate_identity("not a dict")


def test_validator_rejects_bad_generic_inputs():
    identity = compute_candidate_identity({
        "identity_kind": "generic",
        "url": "https://example.com/s",
        "http_method": "GET",
        "parameter_name": "q",
        "input_location": "query",
        "test_family": "sqli",
    })
    bad_location = {**identity, "key": {**identity["key"], "input_location": "header2"}}
    assert any("input_location not in enum" in e for e in validate_candidate_identity(bad_location))

    bad_family = {**identity, "key": {**identity["key"], "test_family": "sql_injection_typosquat"}}
    assert any("test_family not in enum" in e for e in validate_candidate_identity(bad_family))

    empty_param = {**identity, "key": {**identity["key"], "parameter_name": ""}}
    assert any("parameter_name must be non-empty" in e for e in validate_candidate_identity(empty_param))


def test_validate_merge_key_rejects_drift():
    good = merge_key({
        "canonical_target": "https://example.com",
        "product_or_component": "Acme Portal",
        "normalized_endpoint": "/search",
        "http_method": "GET",
        "vulnerability_family": "xss",
        "root_cause_signature": "unescaped echo",
        "parameter_scope": "single_parameter",
    })
    bad_scope = dict(good, parameter_scope="everything")
    assert any("parameter_scope not in enum" in e for e in validate_merge_key(bad_scope))

    bad_sqli = dict(good, vulnerability_family="sqli")
    assert any("endpoint_all_parameters" in e for e in validate_merge_key(bad_sqli))

    missing = dict(good)
    del missing["root_cause_signature"]
    assert any("missing merge key field" in e for e in validate_merge_key(missing))

    cred = dict(good, auth_cookie_meta="x")
    assert any("credential-like key" in e for e in validate_merge_key(cred))


def test_quota_constant_matches_contract():
    schema = ck.load_identity_schema()
    assert schema["quota_rules"]["max_per_system_and_family"] == ck.QUOTA_MAX_PER_SYSTEM_AND_FAMILY
