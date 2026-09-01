"""tests/test_file_path_candidate_screening.py —— 路径穿越/LFI 文件面独立筛选域测试
（batch7_3，操作员 batch6_4 决定⑤ + 规格 5.4 子阶段清单）。

覆盖：观察键→证据形态确定性映射、升级边界（6 形态永不升级、2 确认形态才升级、
他类确认形态不跨类升级）、8 状态分级与 status_hint、候选行校验（非法 category
提示注入域归属）、筛选汇总（三统计概念分离 + 注入类别路由违例含 path_traversal/
lfi）、编排器登记表规格路径。纯离线数据变换，不发请求、不读本地文件、不构造
穿越 payload。
"""
from __future__ import annotations

from authorized_assessment.triage import file_path_candidate_screening as fp
from authorized_assessment.triage import input_testing as itp
from authorized_assessment.triage import injection_candidates as ic

FORM_EVIDENCE = {
    "file_path_parameter_observed": True,
    "extension_whitelist_only_observed": True,
}

TRAVERSAL_CONFIRMED_OBS = {
    "endpoint": "/download",
    "http_method": "GET",
    "parameter_name": "file",
    "category": "path_traversal_boundary",
    "applicability": "applicable",
    "evidence": {
        "file_path_parameter_observed": True,
        "traversal_filter_response_observed": True,
        "traversal_boundary_crossed_confirmed": True,
    },
    "source": "runs/demo/evidence/filepath/traversal.json",
    "evidence_ref": "runs/demo/evidence/filepath/traversal.json:L8",
    "reason": "可控路径越出预期目录且取回可区分内容（授权环境低敏感文件）",
    "precondition": "确认读取仅限授权环境低敏感文件，不读本地敏感文件",
}

LFI_FORM_OBS = {
    "endpoint": "/api/export",
    "parameter_name": "template",
    "category": "lfi_read_boundary",
    "applicability": "applicable",
    "evidence": dict(FORM_EVIDENCE),
    "source": "runs/demo/evidence/filepath/export.js",
    "reason": "模板参数承载路径值且仅前端白名单（仅形态）",
}


def test_derive_evidence_kinds_maps_observation_keys():
    kinds = fp.derive_file_path_evidence_kinds(
        {"file_path_parameter_observed": True, "differential_observed": True}
    )
    assert kinds == ["file_path_parameter", "differential"]
    assert fp.derive_file_path_evidence_kinds({}) == []
    assert fp.derive_file_path_evidence_kinds({"unknown_key": True}) == []


def test_grade_form_observations_never_upgrade():
    """仅参数面/白名单/静态拼接/处理迹象/差分/语义异常永不升级。"""
    for evidence in (
        FORM_EVIDENCE,
        {"static_path_concatenation_observed": True},
        {"traversal_filter_response_observed": True, "differential_observed": True},
        {"semantic_anomaly_observed": True},
    ):
        kinds = fp.derive_file_path_evidence_kinds(evidence)
        assert fp.grade_file_path_observation("path_traversal_boundary", kinds) == "signal"
        assert fp.grade_file_path_observation("lfi_read_boundary", kinds) == "signal"


def test_grade_confirmed_kinds_upgrade():
    kinds = fp.derive_file_path_evidence_kinds(TRAVERSAL_CONFIRMED_OBS["evidence"])
    assert fp.grade_file_path_observation("path_traversal_boundary", kinds) == "candidate"
    assert fp.grade_file_path_observation("lfi_read_boundary", ["known_file_content_confirmed"]) == "candidate"
    # 穿越越界确认同样满足 LFI 类（穿越读文件即 LFI，两形态 OR）
    assert fp.grade_file_path_observation("lfi_read_boundary", ["traversal_boundary_crossed_confirmed"]) == "candidate"


def test_grade_confirmation_not_cross_category():
    """文件面确认形态对未知类别无规则 → signal（跨域形态不升级）。"""
    assert fp.grade_file_path_observation("path_traversal_boundary", ["known_file_content_confirmed"]) == "signal"


def test_grade_status_hint_respected():
    kinds = fp.derive_file_path_evidence_kinds(FORM_EVIDENCE)
    assert (
        fp.grade_file_path_observation("path_traversal_boundary", kinds, "needs_manual_validation")
        == "needs_manual_validation"
    )


def test_validate_candidate_unknown_kind_and_status():
    violations = fp.validate_file_path_candidate(
        {
            "candidate_id": "fp-0001",
            "category": "path_traversal_boundary",
            "status": "maybe",
            "evidence_kinds": ["not_a_kind"],
            "source": "s",
        }
    )
    assert any("status 非法" in v for v in violations)
    assert any("未知形态" in v for v in violations)


def test_validate_candidate_rejects_injection_category():
    """候选行 category 为注入类别 → 违例并提示归属域。"""
    violations = fp.validate_file_path_candidate(
        {
            "candidate_id": "fp-0002",
            "category": "lfi",
            "status": "signal",
            "evidence_kinds": ["differential"],
            "source": "s",
        }
    )
    assert any("category 非法" in v and "injection_candidate_screening" in v for v in violations)


def test_validate_candidate_requires_upgrade_evidence():
    """status=candidate 但仅有形态证据 → 违例（永不升级边界）。"""
    violations = fp.validate_file_path_candidate(
        {
            "candidate_id": "fp-0003",
            "category": "lfi_read_boundary",
            "status": "candidate",
            "evidence_kinds": ["file_path_parameter"],
            "source": "s",
            "evidence_ref": "e.json",
        }
    )
    assert any("升级证据不满足" in v for v in violations)


def test_validate_candidate_requires_evidence_ref():
    for status in ("candidate", "confirmed", "needs_manual_validation"):
        violations = fp.validate_file_path_candidate(
            {
                "candidate_id": "fp-0004",
                "category": "path_traversal_boundary",
                "status": status,
                "evidence_kinds": ["traversal_boundary_crossed_confirmed"],
                "source": "s",
            }
        )
        assert any("evidence_ref 为空" in v for v in violations), status


def test_screen_candidate_and_summary_counts():
    rows, summaries, violations = fp.screen_file_path_observations(
        [TRAVERSAL_CONFIRMED_OBS, LFI_FORM_OBS]
    )
    assert violations == []
    assert [r["status"] for r in rows] == ["candidate", "signal"]
    assert [r["candidate_id"] for r in rows] == ["fp-0001", "fp-0002"]
    traversal_summary = next(s for s in summaries if s["category"] == "path_traversal_boundary")
    assert traversal_summary["status_counts"]["candidate"] == 1
    assert traversal_summary["tested_count"] == 1
    lfi_summary = next(s for s in summaries if s["category"] == "lfi_read_boundary")
    assert lfi_summary["status_counts"]["signal"] == 1
    assert lfi_summary["tested_count"] == 0  # signal 不算 tested
    assert [s["category"] for s in summaries] == list(fp.FILE_PATH_CATEGORIES)


def test_screen_injection_category_routing_violation():
    """观察声明注入类别（含 path_traversal/lfi 本尊）→ 路由违例不双计。"""
    for injection_category in ("path_traversal", "lfi", "sql"):
        obs = {
            "endpoint": "/download",
            "parameter_name": "file",
            "category": injection_category,
            "applicability": "applicable",
            "evidence": {"differential_observed": True},
            "source": "p",
        }
        rows, summaries, violations = fp.screen_file_path_observations([obs])
        assert rows == []
        assert any("injection_candidate_screening" in v and "不双计" in v for v in violations)
        assert all(s["tested_count"] == 0 for s in summaries)


def test_screen_missing_source_violation():
    obs = {
        "category": "lfi_read_boundary",
        "applicability": "applicable",
        "evidence": {"known_file_content_confirmed": True},
    }
    rows, _, violations = fp.screen_file_path_observations([obs])
    assert len(rows) == 1
    assert any("缺少来源" in v for v in violations)


def test_screen_version_mismatch_violation():
    obs = dict(TRAVERSAL_CONFIRMED_OBS, observation_schema_version="0.9")
    _, _, violations = fp.screen_file_path_observations([obs])
    assert any("observation_schema_version" in v for v in violations)
    _, _, violations = fp.screen_file_path_observations(
        [dict(TRAVERSAL_CONFIRMED_OBS, observation_schema_version=ic.OBSERVATION_SCHEMA_VERSION)]
    )
    assert not any("observation_schema_version" in v for v in violations)


def test_screen_unknown_category_violation():
    obs = {
        "category": "path_traversal_boundary_x",
        "applicability": "applicable",
        "evidence": {"differential_observed": True},
        "source": "p",
    }
    rows, _, violations = fp.screen_file_path_observations([obs])
    assert rows == []
    assert any("category 非法" in v for v in violations)


def test_not_applicable_semantics_follow_summary_level_contract():
    """na 有 reason 计入豁免且不产生行；na 无 reason 由筛选层默认 reason 兜底，
    汇总行级缺 reason 由 validate_category_summary 拒绝（batch6_4 锁定语义）。"""
    na_obs = {
        "category": "lfi_read_boundary",
        "applicability": "not_applicable",
        "reason": "目标无文件路径输入面（JS 与代理记录均无文件参数）",
    }
    rows, summaries, violations = fp.screen_file_path_observations([na_obs])
    assert violations == [] and rows == []
    summary = next(s for s in summaries if s["category"] == "lfi_read_boundary")
    assert summary["category_status"] == "not_applicable"
    assert summary["applicability_counts"]["not_applicable"] == 1
    _, _, violations = fp.screen_file_path_observations([dict(na_obs, reason="")])
    assert violations == []
    violations = ic.validate_category_summary(
        dict(summary, reason=""), label="summary", categories=fp.FILE_PATH_CATEGORIES
    )
    assert any("category_status=not_applicable 但 reason 为空" in v for v in violations)


def test_spec_artifact_paths_registered_in_orchestrator():
    """决定⑤：file_path 为独立子域——登记表内独立产物路径（实现定义留痕）。"""
    assert (
        itp.INPUT_TESTING_ARTIFACTS["file_path_summary_csv"]
        == "artifacts/file-path/file-path-category-summary.csv"
    )
    assert (
        itp.INPUT_TESTING_ARTIFACTS["file_path_candidates_jsonl"]
        == "artifacts/file-path/file-path-candidates.jsonl"
    )
