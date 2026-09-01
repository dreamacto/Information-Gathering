"""tests/test_candidate_dedup.py —— 候选去重引擎验收（规格 4.2 + 2.7 + 13.2 负例）。

覆盖：13.2 "重复 API 候选"负例（同 API 键折叠 + duplicate_of 正确）、去重确定性、
代表选择确定性、sqli 同接口多参数合并（2.7 规则1）、同系统同族 >3 限量（2.7 规则6）、
通用产品跨实例合并（2.7 规则8）、跨 run 五字段折叠（4.2）、
duplicate_of 与 finding_quality_gate duplicate 状态的衔接（B1 决议）、校验器负例。
"""
from __future__ import annotations

import pytest

from authorized_assessment.triage import candidate_dedup as cd
from authorized_assessment.triage.candidate_dedup import (
    apply_merge_rules,
    dedupe_candidates,
    merge_cross_run,
    validate_cross_run_records,
    validate_dedup_report,
    validate_merge_rules_report,
)
from authorized_assessment.triage.canonical_keys import QUOTA_MAX_PER_SYSTEM_AND_FAMILY


def api_row(finding_id, *, path="/v1/users", method="GET", params=("id",),
            content_type="application/json", source_kind="B", host="api.example.com",
            seen_at="2026-08-29T10:00:00+08:00", status="candidate", evidence_ref="evidence/a.json"):
    return {
        "finding_id": finding_id,
        "identity_kind": "api",
        "url": f"https://{host}{path}",
        "http_method": method,
        "parameter_names": list(params),
        "content_type": content_type,
        "source_kind": source_kind,
        "seen_at": seen_at,
        "finding_status": status,
        "evidence_ref": evidence_ref,
    }


def sqli_finding(finding_id, *, endpoint="/search", param="q", seen_at="2026-08-29T10:00:00+08:00",
                 target="https://shop.example.com"):
    return {
        "finding_id": finding_id,
        "canonical_target": target,
        "product_or_component": "acme shop",
        "normalized_endpoint": endpoint,
        "http_method": "GET",
        "vulnerability_family": "sqli",
        "root_cause_signature": "string concat in search handler",
        "parameter_name": param,
        "seen_at": seen_at,
    }


def test_duplicate_api_candidates_folded_with_duplicate_of():
    # 规格 13.2 负例：重复 API 候选
    rows = [
        api_row("F-002", seen_at="2026-08-29T11:00:00+08:00"),
        api_row("F-001"),
    ]
    report = dedupe_candidates(rows)
    assert report["summary"]["input_rows"] == 2
    assert report["summary"]["duplicate_count"] == 1
    assert report["summary"]["group_count"] == 1
    by_id = {row["finding_id"]: row for row in report["rows"]}
    assert "duplicate_of" not in by_id["F-001"]  # 最早 seen_at 为代表
    assert by_id["F-002"]["duplicate_of"] == "F-001"
    # 代表行 finding_status 不被改写；duplicate 行也由 finding_quality_gate 判定（引擎不越权）
    assert by_id["F-001"]["finding_status"] == "candidate"
    assert by_id["F-002"]["finding_status"] == "candidate"
    assert validate_dedup_report(report) == []


def test_dedup_is_order_independent_and_deterministic():
    rows = [
        api_row("F-1", path="/a", seen_at="2026-08-29T10:00:00+08:00"),
        api_row("F-2", path="/a", seen_at="2026-08-29T09:00:00+08:00"),
        api_row("F-3", path="/b"),
        api_row("F-4", path="/b", seen_at="2026-08-29T08:00:00+08:00"),
    ]
    first = dedupe_candidates(rows)
    second = dedupe_candidates(list(reversed(rows)))
    assert [row["finding_id"] for row in first["rows"]] == [row["finding_id"] for row in second["rows"]]
    a_by_id = {row["finding_id"]: row.get("duplicate_of") for row in first["rows"]}
    b_by_id = {row["finding_id"]: row.get("duplicate_of") for row in second["rows"]}
    expected = {"F-2": None, "F-1": "F-2", "F-4": None, "F-3": "F-4"}
    assert a_by_id == b_by_id == expected


def test_representative_tie_broken_by_finding_id():
    rows = [
        api_row("B-2", seen_at="2026-08-29T10:00:00+08:00"),
        api_row("A-9", seen_at="2026-08-29T10:00:00+08:00"),
    ]
    report = dedupe_candidates(rows)
    by_id = {row["finding_id"]: row for row in report["rows"]}
    assert by_id["B-2"]["duplicate_of"] == "A-9"
    assert "duplicate_of" not in by_id["A-9"]


def test_different_api_keys_not_merged():
    # source_kind/content_type 属于规格 4.2 API 键字段——不同值 = 不同身份键，不得合并
    rows = [
        api_row("F-1", path="/v1/users"),
        api_row("F-2", path="/v1/orders"),
        api_row("F-3", path="/v1/users", source_kind="E"),
    ]
    report = dedupe_candidates(rows)
    assert report["summary"]["duplicate_count"] == 0
    assert report["summary"]["group_count"] == 3
    by_id = {row["finding_id"]: row for row in report["rows"]}
    assert all("duplicate_of" not in row for row in by_id.values())


def test_rows_without_identity_kind_rejected():
    with pytest.raises(ValueError, match="identity_kind"):
        dedupe_candidates([{"finding_id": "F-1", "url": "https://x.example.com/a"}])


def test_sqli_same_endpoint_multiple_params_merge_to_one():
    # 规格 2.7 规则1：同一接口多个参数的 SQL 注入合并为一个 finding
    rows = [
        sqli_finding("S-1", param="q"),
        sqli_finding("S-2", param="page", seen_at="2026-08-29T11:00:00+08:00"),
        sqli_finding("S-3", param="sort", seen_at="2026-08-29T12:00:00+08:00"),
    ]
    report = apply_merge_rules(rows)
    assert report["summary"]["merge_group_count"] == 1
    assert report["summary"]["duplicate_count"] == 2
    group = report["merge_groups"][0]
    assert group["representative_id"] == "S-1"
    assert group["merged_parameters"] == ["page", "q", "sort"]
    by_id = {row["finding_id"]: row for row in report["rows"]}
    assert by_id["S-1"]["merged_parameters"] == ["page", "q", "sort"]
    assert by_id["S-2"]["duplicate_of"] == "S-1"
    assert validate_merge_rules_report(report) == []


def test_sqli_different_endpoints_not_merged():
    rows = [
        sqli_finding("S-1", endpoint="/search", param="q"),
        sqli_finding("S-2", endpoint="/admin/login", param="user"),
    ]
    report = apply_merge_rules(rows)
    assert report["summary"]["duplicate_count"] == 0
    assert report["summary"]["merge_group_count"] == 2


def test_same_system_same_family_quota_over_three():
    # 规格 2.7 规则6：同一系统同一漏洞类型超过三个，后续只保留代表性证据和合并引用
    rows = [
        sqli_finding(f"Q-{i}", endpoint=f"/p{i}", seen_at=f"2026-08-29T1{i}:00:00+08:00")
        for i in range(5)
    ]
    report = apply_merge_rules(rows)
    assert len(rows) == 5
    assert report["summary"]["duplicate_count"] == 2  # 5 - 3
    quota = report["quota_groups"][0]
    assert quota["kept_ids"] == ["Q-0", "Q-1", "Q-2"]
    assert quota["merged_ids"] == ["Q-3", "Q-4"]
    by_id = {row["finding_id"]: row for row in report["rows"]}
    assert by_id["Q-3"]["duplicate_of"] == "Q-0"
    assert by_id["Q-4"]["duplicate_of"] == "Q-0"
    assert validate_merge_rules_report(report) == []


def test_quota_not_triggered_within_limit():
    rows = [sqli_finding(f"Q-{i}", endpoint=f"/p{i}") for i in range(QUOTA_MAX_PER_SYSTEM_AND_FAMILY)]
    report = apply_merge_rules(rows)
    assert report["summary"]["duplicate_count"] == 0
    assert report["quota_groups"] == []


def test_generic_product_merge_across_targets():
    # 规格 2.7 规则8：同一通用产品缺陷在多个企业实例出现 → 一个 generic finding + 实例清单
    rows = [
        sqli_finding("G-1", target="https://shop-a.example.com"),
        sqli_finding("G-2", target="https://shop-b.example.com"),
        sqli_finding("G-3", target="https://shop-c.example.com"),
    ]
    report = apply_merge_rules(rows)
    assert report["summary"]["generic_cluster_count"] == 1
    cluster = report["generic_clusters"][0]
    assert cluster["lead_id"] == "G-1"
    assert cluster["instance_targets"] == [
        "https://shop-a.example.com", "https://shop-b.example.com", "https://shop-c.example.com",
    ]
    by_id = {row["finding_id"]: row for row in report["rows"]}
    assert by_id["G-1"]["generic_cluster"] is True
    # 实例代表保持独立（不串联），由 generic finding 挂接清单
    assert "duplicate_of" not in by_id["G-2"]
    assert validate_merge_rules_report(report) == []


def test_same_target_clusters_do_not_create_generic_finding():
    rows = [sqli_finding("G-1"), sqli_finding("G-2", endpoint="/other", param="x")]
    report = apply_merge_rules(rows)
    # 不同 endpoint → 不同合并键；同 target → 不构成通用产品跨实例合并
    assert report["generic_clusters"] == []


def test_merge_rules_missing_required_field_rejected():
    bad = sqli_finding("S-1")
    del bad["root_cause_signature"]
    with pytest.raises(ValueError, match="missing fields"):
        apply_merge_rules([bad])


def test_cross_run_merge_retains_five_fields():
    rows = [
        api_row("F-1", seen_at="2026-08-01T10:00:00+08:00", status="signal",
                evidence_ref="runs/a/evidence/old.json"),
        api_row("F-2", seen_at="2026-08-20T10:00:00+08:00", status="candidate",
                evidence_ref="runs/b/evidence/new.json"),
        api_row("F-3", seen_at="2026-08-10T10:00:00+08:00", status="needs_manual_validation",
                evidence_ref="runs/c/evidence/mid.json"),
    ]
    records = merge_cross_run(rows)
    assert len(records) == 1
    record = records[0]
    assert set(record) == {"identity_kind", "identity_hash", "first_seen", "last_seen",
                           "seen_count", "latest_status", "latest_evidence_ref"}
    assert record["first_seen"] == "2026-08-01T10:00:00+08:00"
    assert record["last_seen"] == "2026-08-20T10:00:00+08:00"
    assert record["seen_count"] == 3
    # latest 行按 seen_at 最大者取（不依赖输入顺序）
    assert record["latest_status"] == "candidate"
    assert record["latest_evidence_ref"] == "runs/b/evidence/new.json"
    assert validate_cross_run_records(records) == []


def test_cross_run_missing_status_fail_closed():
    row = api_row("F-1")
    del row["finding_status"]
    with pytest.raises(ValueError, match="finding_status"):
        merge_cross_run([row])


def test_cross_run_validator_rejects_bad_records():
    good = merge_cross_run([api_row("F-1")])[0]

    bad_kind = dict(good, identity_kind="web")
    assert any("identity_kind not in enum" in e for e in validate_cross_run_records([bad_kind]))

    bad_hash = dict(good, identity_hash="xyz")
    assert any("64-hex" in e for e in validate_cross_run_records([bad_hash]))

    missing_field = dict(good)
    del missing_field["seen_count"]
    assert any("missing cross-run field" in e for e in validate_cross_run_records([missing_field]))

    bad_count = dict(good, seen_count=0)
    assert any("seen_count" in e for e in validate_cross_run_records([bad_count]))

    bad_status = dict(good, latest_status="maybe_vuln")
    assert any("latest_status not in finding status enum" in e
               for e in validate_cross_run_records([bad_status]))

    reversed_time = dict(good, first_seen="2026-08-29T10:00:00+08:00",
                         last_seen="2026-08-01T10:00:00+08:00")
    assert any("first_seen must not be after" in e for e in validate_cross_run_records([reversed_time]))

    cred = dict(good, session_cookie_hint="x")
    assert any("credential-like key" in e for e in validate_cross_run_records([cred]))

    assert validate_cross_run_records("not a list")


def test_dedup_report_validator_rejects_tampering():
    good = dedupe_candidates([api_row("F-1"), api_row("F-2", seen_at="2026-08-29T11:00:00+08:00")])

    dangling = {
        "rows": [dict(api_row("F-1"), duplicate_of="F-404")],
        "summary": {"input_rows": 1, "representative_count": 0, "duplicate_count": 1, "group_count": 1},
    }
    assert any("references unknown finding_id" in e for e in validate_dedup_report(dangling))

    self_ref = {
        "rows": [dict(api_row("F-1"), duplicate_of="F-1")],
        "summary": {"input_rows": 1, "representative_count": 0, "duplicate_count": 1, "group_count": 1},
    }
    assert any("must not self-reference" in e for e in validate_dedup_report(self_ref))

    chained = {
        "rows": [
            dict(api_row("F-1"), duplicate_of="F-2"),
            dict(api_row("F-2"), duplicate_of="F-3"),
            api_row("F-3"),
        ],
        "summary": {"input_rows": 3, "representative_count": 1, "duplicate_count": 2, "group_count": 1},
    }
    assert any("chained duplicate_of is forbidden" in e for e in validate_dedup_report(chained))

    bad_summary = dict(good, summary={"input_rows": 99, "representative_count": 0,
                                      "duplicate_count": 0, "group_count": 1})
    assert any("summary.input_rows inconsistent" in e for e in validate_dedup_report(bad_summary))

    missing_section = {"rows": good["rows"]}
    assert any("missing required section" in e for e in validate_dedup_report(missing_section))

    cred = dict(good, rows=[dict(row, auth_token_ref="x") for row in good["rows"]])
    assert any("credential-like key" in e for e in validate_dedup_report(cred))

    assert validate_dedup_report("not a dict")


def test_duplicate_of_feeds_finding_quality_gate_duplicate_status():
    # B1 决议衔接：引擎产出 duplicate_of → finding_quality_gate 派生 duplicate 状态
    from authorized_assessment.quality.finding_quality_gate import evaluate_finding_quality

    report = dedupe_candidates([api_row("F-1"), api_row("F-2", seen_at="2026-08-29T11:00:00+08:00")])
    duplicate_row = next(row for row in report["rows"] if row["finding_id"] == "F-2")
    quality = evaluate_finding_quality({"finding_id": "F-2", "duplicate_of": duplicate_row["duplicate_of"]})
    assert quality["finding_status"] == "duplicate"
