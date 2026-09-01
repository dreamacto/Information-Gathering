"""tests/test_input_testing_pipeline.py —— input_testing 编排器端到端离线测试
（Batch 6 整改 batch6_4 决定④补齐编排器；Batch 7 batch7_2 接入 browser_boundary_review、
batch7_3 接入 file_path_candidate_screening）。

覆盖：
  - init 幂等骨架（登记表全量产物；重复 init 不覆盖既有文件）；
  - run 筛选落盘（离线端到端：观察 → 产物文件，含 browser_boundary/file_path 域）；
  - audit 正例（正例观察产生的产物全部通过：存在性 + 行契约 + summary↔候选一致性
    + 报告机读块↔候选行一致性）；
  - audit 负例：产物缺失、summary 与候选行不一致（篡改 status_counts/tested_count）、
    候选行违反升级规则、manifest 公共 OAST 域、browser-boundary 报告摘要篡改、
    browser-boundary 候选行类别搬移、file-path 汇总篡改；
  - orchestration_only 边界：run 不发请求不签发 token（manifest 仅骨架）。
"""
from __future__ import annotations

import json
from pathlib import Path

from authorized_assessment.triage import browser_boundary as bb
from authorized_assessment.triage import input_testing as itp
from authorized_assessment.triage import ssrf_candidate_screening as ssrf

SQL_OBS = {
    "endpoint": "/api/user/list",
    "http_method": "GET",
    "input_location": "query",
    "parameter_name": "sort",
    "category": "sql",
    "applicability": "applicable",
    "evidence": {"query_input_point_confirmed": True, "differential_observed": True},
    "evidence_ref": "runs/demo/evidence/sqli/diff.json",
    "reason": "排序参数差分",
    "precondition": "SQLMap 仅审批门下单候选",
}

SOAP_OBS = {
    "endpoint": "/services/SoapService",
    "content_type": "application/soap+xml",
    "http_method": "POST",
    "input_location": "body",
    "parameter_name": "xmlPayload",
    "applicability": "applicable",
    "evidence": {"parser_confirmed": True},
    "evidence_ref": "runs/demo/evidence/xml/entity.json",
    "reason": "SOAP 解析器确认",
}

SSRF_OBS = {
    "endpoint": "/api/fetch-avatar",
    "http_method": "GET",
    "parameter_name": "image",
    "applicability": "applicable",
    "evidence": {
        "server_fetch_evidence_observed": True,
        "timing_differential_observed": True,
    },
    "evidence_ref": "runs/demo/evidence/ssrf/timing.json",
    "reason": "图片拉取参数时间差分",
    "precondition": "OOB/内网验证均为审批门",
}


def test_init_artifacts_creates_all_registered_and_is_idempotent(tmp_path):
    created = itp.init_input_testing_artifacts(tmp_path)
    assert len(created) == len(itp.INPUT_TESTING_ARTIFACTS) == 11
    for rel in itp.INPUT_TESTING_ARTIFACTS.values():
        assert (tmp_path / rel).is_file(), rel
    marker = tmp_path / itp.INPUT_TESTING_ARTIFACTS["oob_token_manifest"]
    marker.write_text('{"schema_version": "1.0", "tokens": [{"token": "keep"}]}', encoding="utf-8")
    created_again = itp.init_input_testing_artifacts(tmp_path)
    assert created_again == []
    assert "keep" in marker.read_text(encoding="utf-8")


def test_run_writes_artifacts_and_report(tmp_path):
    report = itp.run_input_testing_screening(
        tmp_path,
        injection_observations=[SQL_OBS],
        parser_observations=[SOAP_OBS],
        ssrf_observations=[SSRF_OBS],
    )
    assert report["violations"] == []
    assert report["domains"]["injection_candidate_screening"]["candidates"] == 1
    assert report["domains"]["parser_deserialization_screening"]["candidates"] == 1
    assert report["domains"]["ssrf_candidate_screening"]["candidates"] == 1
    for rel in itp.INPUT_TESTING_ARTIFACTS.values():
        assert (tmp_path / rel).is_file(), rel
    candidates = [
        json.loads(line)
        for line in (tmp_path / itp.INPUT_TESTING_ARTIFACTS["injection_candidates_jsonl"])
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert candidates[0]["category"] == "sql"
    assert candidates[0]["status"] == "candidate"
    queue_lines = (
        (tmp_path / itp.INPUT_TESTING_ARTIFACTS["ssrf_review_queue_csv"]).read_text(encoding="utf-8").strip()
    )
    assert "ssrf-0001" in queue_lines


def test_run_orchestration_only_never_touches_oob_tokens(tmp_path):
    """orchestration_only（操作员决定⑥）：run 只筛选落盘，不签发/不探测 OOB token。"""
    itp.run_input_testing_screening(tmp_path, ssrf_observations=[SSRF_OBS])
    manifest = json.loads(
        (tmp_path / itp.INPUT_TESTING_ARTIFACTS["oob_token_manifest"]).read_text(encoding="utf-8")
    )
    assert manifest["tokens"] == []


def test_audit_passes_on_clean_workspace(tmp_path):
    itp.run_input_testing_screening(
        tmp_path,
        injection_observations=[SQL_OBS],
        parser_observations=[SOAP_OBS],
        ssrf_observations=[SSRF_OBS],
    )
    ok, violations = itp.audit_input_testing(tmp_path)
    assert ok, violations
    assert violations == []


def test_audit_flags_missing_artifacts(tmp_path):
    itp.init_input_testing_artifacts(tmp_path)
    (tmp_path / itp.INPUT_TESTING_ARTIFACTS["ssrf_candidates_jsonl"]).unlink()
    ok, violations = itp.audit_input_testing(tmp_path)
    assert not ok
    assert any("缺少产物文件" in v for v in violations)
    ok, violations = itp.audit_input_testing(tmp_path / "nonexistent")
    assert not ok
    assert any("缺少产物文件" in v for v in violations)


def test_audit_flags_summary_candidate_inconsistency(tmp_path):
    itp.run_input_testing_screening(tmp_path, injection_observations=[SQL_OBS])
    summary_path = tmp_path / itp.INPUT_TESTING_ARTIFACTS["injection_summary_csv"]
    summaries, parse_violations = itp._read_summary_csv(summary_path)
    assert parse_violations == []
    for summary in summaries:
        if summary["category"] == "sql":
            summary["status_counts"]["candidate"] = 0
    itp._write_summary_csv(summary_path, summaries)
    ok, violations = itp.audit_input_testing(tmp_path)
    assert not ok
    assert any("status_counts.candidate" in v and "与候选行重算" in v for v in violations)


def test_audit_flags_tampered_tested_count(tmp_path):
    itp.run_input_testing_screening(tmp_path, injection_observations=[SQL_OBS])
    summary_path = tmp_path / itp.INPUT_TESTING_ARTIFACTS["injection_summary_csv"]
    summaries, parse_violations = itp._read_summary_csv(summary_path)
    assert parse_violations == []
    for summary in summaries:
        if summary["category"] == "sql":
            summary["tested_count"] = 4
    itp._write_summary_csv(summary_path, summaries)
    ok, violations = itp.audit_input_testing(tmp_path)
    assert not ok
    assert any("tested_count" in v for v in violations)


def test_audit_flags_category_moved_candidate(tmp_path):
    """候选行类别被篡改后，原类别与新类别的 status_counts 都与重算不一致。"""
    itp.run_input_testing_screening(tmp_path, injection_observations=[SQL_OBS])
    candidates_path = tmp_path / itp.INPUT_TESTING_ARTIFACTS["injection_candidates_jsonl"]
    row = json.loads(candidates_path.read_text(encoding="utf-8").splitlines()[0])
    row["category"] = "ssti"
    candidates_path.write_text(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )
    ok, violations = itp.audit_input_testing(tmp_path)
    assert not ok
    assert any("[sql].status_counts.candidate=1" in v and "重算 0" in v for v in violations)
    assert any("[ssti].status_counts.candidate=0" in v and "重算 1" in v for v in violations)


def test_audit_flags_bad_oob_manifest(tmp_path):
    itp.run_input_testing_screening(tmp_path, ssrf_observations=[SSRF_OBS])
    manifest_path = tmp_path / itp.INPUT_TESTING_ARTIFACTS["oob_token_manifest"]
    manifest_path.write_text(
        json.dumps(
            {
                "tokens": [
                    {
                        "token": "aabbccddeeff",
                        "callback_host": "x.oast.pro",
                        "issued_at": "2026-08-29T22:00:00+08:00",
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    ok, violations = itp.audit_input_testing(tmp_path)
    assert not ok
    assert any("公共 OAST" in v for v in violations)


def test_artifacts_registry_matches_spec_ssrf_paths():
    """规格 5.4 明示的 artifacts/ssrf/ 三件必须在登记表内且路径一致。"""
    assert itp.INPUT_TESTING_ARTIFACTS["ssrf_candidates_jsonl"] == "artifacts/ssrf/ssrf_candidates.jsonl"
    assert itp.INPUT_TESTING_ARTIFACTS["ssrf_review_queue_csv"] == "artifacts/ssrf/ssrf_review_queue.csv"
    assert itp.INPUT_TESTING_ARTIFACTS["oob_token_manifest"] == "artifacts/ssrf/oob_token_manifest.json"


def test_ssrf_screening_module_still_exported_helpers_used_by_pipeline():
    """编排器复用既有域模块（不造第二套判定）。"""
    assert hasattr(ssrf, "screen_ssrf_observations")
    assert hasattr(ssrf, "validate_oob_token_manifest")


CORS_CONFIRMED_OBS = {
    "endpoint": "/api/profile",
    "category": "cors_policy",
    "applicability": "applicable",
    "evidence": {"cors_cross_origin_read_confirmed": True},
    "source": "runs/demo/evidence/cors/read.json",
    "evidence_ref": "runs/demo/evidence/cors/read.json:L12",
    "reason": "跨站上下文实际读取到带凭证私有响应",
    "precondition": "受害者持有有效会话；确认读取经授权演练环境录得",
}


def test_run_with_browser_boundary_observations_writes_report_and_audits(tmp_path):
    report = itp.run_input_testing_screening(
        tmp_path, browser_boundary_observations=[CORS_CONFIRMED_OBS]
    )
    assert report["violations"] == []
    assert report["domains"]["browser_boundary_review"]["candidates"] == 1
    assert report["domains"]["browser_boundary_review"]["summaries"] == 6
    candidates = [
        json.loads(line)
        for line in (tmp_path / itp.INPUT_TESTING_ARTIFACTS["browser_boundary_jsonl"])
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert candidates[0]["category"] == "cors_policy"
    assert candidates[0]["status"] == "candidate"
    payload, err = bb.extract_report_summary(
        (tmp_path / itp.INPUT_TESTING_ARTIFACTS["browser_boundary_report_md"]).read_text(
            encoding="utf-8"
        )
    )
    assert err is None
    cors_summary = next(
        s for s in payload["category_summaries"] if s["category"] == "cors_policy"
    )
    assert cors_summary["tested_count"] == 1
    ok, violations = itp.audit_input_testing(tmp_path)
    assert ok, violations


def test_audit_flags_tampered_browser_report_summary(tmp_path):
    itp.run_input_testing_screening(
        tmp_path, browser_boundary_observations=[CORS_CONFIRMED_OBS]
    )
    report_path = tmp_path / itp.INPUT_TESTING_ARTIFACTS["browser_boundary_report_md"]
    payload, err = bb.extract_report_summary(report_path.read_text(encoding="utf-8"))
    assert err is None
    for summary in payload["category_summaries"]:
        if summary["category"] == "cors_policy":
            summary["status_counts"]["candidate"] = 0
    report_path.write_text(
        bb.build_browser_boundary_report(payload["category_summaries"], payload["violations"]),
        encoding="utf-8",
    )
    ok, violations = itp.audit_input_testing(tmp_path)
    assert not ok
    assert any(
        "browser-boundary-report[cors_policy].status_counts.candidate" in v for v in violations
    )


def test_audit_flags_tampered_browser_candidate_row(tmp_path):
    itp.run_input_testing_screening(
        tmp_path, browser_boundary_observations=[CORS_CONFIRMED_OBS]
    )
    rows_path = tmp_path / itp.INPUT_TESTING_ARTIFACTS["browser_boundary_jsonl"]
    row = json.loads(rows_path.read_text(encoding="utf-8").splitlines()[0])
    row["category"] = "open_redirect"
    rows_path.write_text(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )
    ok, violations = itp.audit_input_testing(tmp_path)
    assert not ok
    assert any(
        "browser-boundary-report[cors_policy].status_counts.candidate=1" in v
        and "重算 0" in v
        for v in violations
    )
    assert any(
        "browser-boundary-report[open_redirect].status_counts.candidate=0" in v
        and "重算 1" in v
        for v in violations
    )


TRAVERSAL_CONFIRMED_OBS = {
    "endpoint": "/download",
    "parameter_name": "file",
    "category": "path_traversal_boundary",
    "applicability": "applicable",
    "evidence": {"traversal_boundary_crossed_confirmed": True},
    "source": "runs/demo/evidence/filepath/traversal.json",
    "evidence_ref": "runs/demo/evidence/filepath/traversal.json:L8",
    "reason": "可控路径越出预期目录且取回可区分内容（授权环境低敏感文件）",
    "precondition": "确认读取仅限授权环境低敏感文件，不读本地敏感文件",
}


def test_run_with_file_path_observations_writes_artifacts_and_audits(tmp_path):
    report = itp.run_input_testing_screening(
        tmp_path, file_path_observations=[TRAVERSAL_CONFIRMED_OBS]
    )
    assert report["violations"] == []
    assert report["domains"]["file_path_candidate_screening"]["candidates"] == 1
    assert report["domains"]["file_path_candidate_screening"]["summaries"] == 2
    candidates = [
        json.loads(line)
        for line in (tmp_path / itp.INPUT_TESTING_ARTIFACTS["file_path_candidates_jsonl"])
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert candidates[0]["candidate_id"] == "fp-0001"
    assert candidates[0]["status"] == "candidate"
    ok, violations = itp.audit_input_testing(tmp_path)
    assert ok, violations


def test_audit_flags_tampered_file_path_summary(tmp_path):
    itp.run_input_testing_screening(
        tmp_path, file_path_observations=[TRAVERSAL_CONFIRMED_OBS]
    )
    summary_path = tmp_path / itp.INPUT_TESTING_ARTIFACTS["file_path_summary_csv"]
    summaries, parse_violations = itp._read_summary_csv(summary_path)
    assert parse_violations == []
    for summary in summaries:
        if summary["category"] == "path_traversal_boundary":
            summary["tested_count"] = 3
    itp._write_summary_csv(summary_path, summaries)
    ok, violations = itp.audit_input_testing(tmp_path)
    assert not ok
    assert any(
        "file-path-category-summary[path_traversal_boundary].tested_count=3" in v
        and "重算 1" in v
        for v in violations
    )
