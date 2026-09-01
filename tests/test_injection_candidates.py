"""tests/test_injection_candidates.py —— 统一注入候选契约测试（Batch 6 / 规格 5.4 + 13.2）。

覆盖：
  - 契约 ↔ 实现常量无漂移（15 类别、两子阶段归属、汇总行结构、8 状态、15 证据形态、
    观察字段说明、definitive 状态集合、category_status 六状态同源）；
  - 8 状态三方一致（契约 ↔ finding_quality_schema ↔ finding_quality_gate.FINDING_STATUS_STATES）；
  - upgrade_rules 覆盖全部 category 且契约规则 ↔ 模块规则语义一致；
  - 汇总行三统计概念分离（category_status / applicability_counts / status_counts /
    tested_count——操作员决定①③）正例与负例：tested_count 一致性、not_applicable
    完整性、状态可证明性；
  - 观察记录 schema（操作员决定②）：版本不符违例、来源强制违例、字段说明与契约一致；
  - 13.2 负例：SSTI 仅语法形态、反序列化仅指纹、XML 输入非解析器、反射不可执行、
    未知 category/状态/证据形态、缺 evidence_ref、approval_required 无 reason。
"""
from __future__ import annotations

import json
from pathlib import Path

from authorized_assessment.quality import finding_quality_gate
from authorized_assessment.triage import injection_candidates as ic

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "injection_candidate_schema.json"
FINDING_CONTRACT = ROOT / "contracts" / "finding_quality_schema.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _candidate(**overrides: object) -> dict:
    cand = {
        "candidate_id": "inj-0001",
        "category": "sql",
        "status": "candidate",
        "evidence_kinds": ["query_input_point", "differential"],
        "source": "02_业务API只读确认项.csv#L12",
        "evidence_ref": "runs/demo/evidence/sqli/diff.json",
        "precondition": "参数 id 进入列表查询",
        "approval_required": True,
        "reason": "SQLMap 需审批门后单候选使用",
    }
    cand.update(overrides)
    return cand


def _summary_row(**overrides: object) -> dict:
    row = {
        "category": "sql",
        "category_status": "tested",
        "applicability_counts": {"applicable": 2, "not_applicable": 0, "unknown": 0},
        "status_counts": {
            "signal": 1,
            "candidate": 1,
            "needs_manual_validation": 0,
            "confirmed": 0,
            "inconclusive": 0,
            "blocked": 0,
            "rejected": 0,
            "duplicate": 0,
        },
        "tested_count": 1,
        "reason": "两个查询输入点完成低风险差分，一个升级为候选",
        "source": "runs/demo/01_重要_人工复核入口/02_业务API只读确认项.csv",
        "precondition": "SQLMap 仅审批门下单候选；先人工确认参数进入查询",
    }
    row.update(overrides)
    return row


# ---------------------------------------------------------------------------
# 契约 ↔ 实现常量无漂移
# ---------------------------------------------------------------------------

def test_contract_matches_module_constants():
    data = _load(CONTRACT)
    assert tuple(data["categories"]) == ic.INJECTION_CATEGORIES
    assert len(data["categories"]) == 15
    for phase, cats in data["category_screening"].items():
        assert tuple(cats) == ic.CATEGORY_SCREENING[phase]
    assert tuple(data["category_summary_required_fields"]) == ic.CATEGORY_SUMMARY_FIELDS
    assert tuple(data["applicable_values"]) == ic.APPLICABLE_VALUES
    assert tuple(data["candidate_status_values"]) == ic.CANDIDATE_STATUS_VALUES
    assert tuple(data["evidence_kinds"]) == ic.EVIDENCE_KINDS
    assert tuple(data["insufficient_evidence_kinds"]) == ic.INSUFFICIENT_EVIDENCE_KINDS
    # 操作员决定①②③：三统计概念分离 + definitive 状态 + category_status 同源 + 观察版本
    assert tuple(data["definitive_result_statuses"]) == ic.DEFINITIVE_RESULT_STATUSES
    assert tuple(data["category_status_values"]) == ic.CATEGORY_STATUS_VALUES
    assert data["observation_schema"]["version"] == ic.OBSERVATION_SCHEMA_VERSION
    assert isinstance(data["summary_structure"], str) and data["summary_structure"]


def test_observation_field_docs_match_contract():
    data = _load(CONTRACT)
    fields = data["observation_schema"]["fields"]
    assert set(fields) == set(ic.OBSERVATION_FIELD_DOCS)
    assert set(fields) == set(ic.OBSERVATION_EVIDENCE_MAP)
    for key in ("versioning_rule", "not_proof_semantics", "source_required"):
        assert data["observation_schema"].get(key), f"observation_schema.{key} missing"


def test_category_screening_partition_complete_and_disjoint():
    injection = set(ic.CATEGORY_SCREENING["injection_candidate_screening"])
    parser = set(ic.CATEGORY_SCREENING["parser_deserialization_screening"])
    assert not injection & parser
    assert injection | parser == set(ic.INJECTION_CATEGORIES)


def test_candidate_status_three_way_alignment():
    data = _load(CONTRACT)
    finding = _load(FINDING_CONTRACT)
    assert tuple(data["candidate_status_values"]) == finding_quality_gate.FINDING_STATUS_STATES
    assert tuple(finding["finding_status_states"]) == finding_quality_gate.FINDING_STATUS_STATES


def test_upgrade_rules_cover_all_categories_and_match_contract():
    data = _load(CONTRACT)
    rules = data["upgrade_rules"]
    assert set(rules) == set(ic.INJECTION_CATEGORIES)
    for category, rule in rules.items():
        groups = rule.get("required_any_groups", [])
        branches = rule.get("required_any_branches", [])
        required_all = rule.get("required_all", [])
        assert groups or branches or required_all, f"{category} 缺少升级规则"
        for kind in required_all:
            assert kind in data["evidence_kinds"]
        for group in groups:
            assert group, f"{category} 存在空证据组"
            for kind in group:
                assert kind in data["evidence_kinds"]
        for branch in branches:
            assert branch, f"{category} 存在空证据分支"
            for kind in branch:
                assert kind in data["evidence_kinds"]
    # 模块规则与契约规则语义一致（转换为同构后对比）
    for category, module_rule in ic._UPGRADE_RULES.items():
        contract_rule = rules[category]
        assert tuple(module_rule.get("required_all", ())) == tuple(contract_rule.get("required_all", []))
        assert tuple(tuple(g) for g in module_rule.get("required_any_groups", ())) == tuple(
            tuple(g) for g in contract_rule.get("required_any_groups", [])
        )
        assert tuple(tuple(b) for b in module_rule.get("required_any_branches", ())) == tuple(
            tuple(b) for b in contract_rule.get("required_any_branches", [])
        )


def test_insufficient_evidence_kinds_are_subset():
    assert set(ic.INSUFFICIENT_EVIDENCE_KINDS) <= set(ic.EVIDENCE_KINDS)


# ---------------------------------------------------------------------------
# upgrade_satisfied 行为
# ---------------------------------------------------------------------------

def test_upgrade_satisfied_sql_requires_query_point_plus_signal():
    ok, _ = ic.upgrade_satisfied("sql", ["query_input_point", "differential"])
    assert ok
    ok, why = ic.upgrade_satisfied("sql", ["query_input_point"])
    assert not ok and "至少一个证据" in why
    ok, _ = ic.upgrade_satisfied("sql", ["differential"])
    assert not ok


def test_upgrade_satisfied_ssti_rejects_syntax_only():
    ok, _ = ic.upgrade_satisfied("ssti", ["server_side_evaluation"])
    assert ok
    ok, why = ic.upgrade_satisfied("ssti", ["template_syntax_seen"])
    assert not ok and "不算漏洞" in why


def test_upgrade_satisfied_deserialization_requires_all_three():
    ok, _ = ic.upgrade_satisfied(
        "unsafe_deserialization",
        ["external_input_into_parser", "unsafe_type_recovery", "reproducible_impact"],
    )
    assert ok
    ok, why = ic.upgrade_satisfied(
        "unsafe_deserialization", ["external_input_into_parser", "unsafe_type_recovery"]
    )
    assert not ok and "required_all" in why
    ok, _ = ic.upgrade_satisfied("unsafe_deserialization", ["fingerprint_or_name_only"])
    assert not ok


def test_upgrade_satisfied_xxe_requires_parser_confirmation():
    ok, _ = ic.upgrade_satisfied("xxe", ["parser_confirmed"])
    assert ok
    ok, _ = ic.upgrade_satisfied("xxe", ["external_input_into_parser", "unsafe_type_recovery"])
    assert ok
    ok, _ = ic.upgrade_satisfied("xxe", ["xml_content_seen"])
    assert not ok


def test_upgrade_satisfied_unknown_inputs_rejected():
    ok, why = ic.upgrade_satisfied("nosuch", ["error_based"])
    assert not ok and "未知 category" in why
    ok, why = ic.upgrade_satisfied("sql", [])
    assert not ok
    ok, why = ic.upgrade_satisfied("sql", ["ghost_kind"])
    assert not ok and "未知证据形态" in why


# ---------------------------------------------------------------------------
# 汇总行校验（三统计概念分离：操作员决定①③）
# ---------------------------------------------------------------------------

def test_valid_summary_row_passes():
    assert ic.validate_category_summary(_summary_row()) == []


def test_summary_missing_field_violation():
    row = _summary_row()
    del row["tested_count"]
    violations = ic.validate_category_summary(row)
    assert any("缺少必需字段 tested_count" in v for v in violations)


def test_summary_unknown_category_and_status_violation():
    violations = ic.validate_category_summary(_summary_row(category="nosuch"))
    assert any("category 非法" in v for v in violations)
    violations = ic.validate_category_summary(_summary_row(category_status="done"))
    assert any("category_status 非法" in v for v in violations)


def test_summary_status_counts_shape_violation():
    row = _summary_row()
    row["status_counts"] = {"candidate": 1}
    violations = ic.validate_category_summary(row)
    assert any("status_counts 缺少键" in v for v in violations)
    row["status_counts"] = {**row["status_counts"], "ghost": 1}
    violations = ic.validate_category_summary(row)
    assert any("未知键" in v for v in violations)


def test_summary_non_integer_counts_violation():
    row = _summary_row()
    row["status_counts"]["candidate"] = True
    violations = ic.validate_category_summary(row)
    assert any("candidate 必须为非负整数" in v for v in violations)
    row["status_counts"]["candidate"] = -1
    violations = ic.validate_category_summary(row)
    assert any("candidate 必须为非负整数" in v for v in violations)


def test_summary_tested_count_consistency_negative():
    row = _summary_row(tested_count=3)
    violations = ic.validate_category_summary(row)
    assert any("不一致（行数矛盾拒绝）" in v for v in violations)
    row = _summary_row(tested_count=True)
    violations = ic.validate_category_summary(row)
    assert any("tested_count 必须为非负整数" in v for v in violations)


def test_summary_tested_count_consistency_positive():
    """tested_count 重定义（操作员决定①）：candidate+confirmed+blocked+rejected+duplicate 之和。"""
    row = _summary_row()
    row["status_counts"] = {
        "signal": 2,
        "candidate": 1,
        "needs_manual_validation": 2,
        "confirmed": 1,
        "inconclusive": 1,
        "blocked": 1,
        "rejected": 1,
        "duplicate": 1,
    }
    row["tested_count"] = 5  # candidate+confirmed+blocked+rejected+duplicate；排除 signal/NMV/inconclusive
    assert ic.validate_category_summary(row) == []


def test_summary_not_applicable_full_integrity():
    """③：category_status=not_applicable 时 status_counts 全 0 + applicable/unknown 为 0 +
    not_applicable 计数豁免 + reason 非空。"""
    row = _summary_row(
        category="ldap",
        category_status="not_applicable",
        applicability_counts={"applicable": 0, "not_applicable": 3, "unknown": 0},
        status_counts={s: 0 for s in ic.CANDIDATE_STATUS_VALUES},
        tested_count=0,
        reason="目标无 LDAP 认证入口，适用性五问完成",
        precondition="",
    )
    assert ic.validate_category_summary(row) == []


def test_summary_not_applicable_with_candidate_count_violation():
    row = _summary_row(
        category_status="not_applicable",
        applicability_counts={"applicable": 0, "not_applicable": 1, "unknown": 0},
    )
    violations = ic.validate_category_summary(row)
    assert any("status_counts 非零" in v for v in violations)


def test_summary_not_applicable_with_applicable_observation_violation():
    row = _summary_row(
        category_status="not_applicable",
        applicability_counts={"applicable": 1, "not_applicable": 1, "unknown": 0},
    )
    violations = ic.validate_category_summary(row)
    assert any("applicable/unknown 计数" in v for v in violations)


def test_summary_not_applicable_without_reason_violation():
    row = _summary_row(
        category_status="not_applicable",
        applicability_counts={"applicable": 0, "not_applicable": 1, "unknown": 0},
        status_counts={s: 0 for s in ic.CANDIDATE_STATUS_VALUES},
        tested_count=0,
        reason="",
    )
    violations = ic.validate_category_summary(row)
    assert any("reason 为空" in v for v in violations)


def test_summary_status_proves_counts_violations():
    row = _summary_row(category_status="tested", tested_count=0)
    row["status_counts"] = {s: 0 for s in ic.CANDIDATE_STATUS_VALUES}
    violations = ic.validate_category_summary(row)
    assert any("tested_count=0" in v for v in violations)
    row = _summary_row(
        category_status="needs_manual_validation",
        tested_count=0,
        status_counts={**{s: 0 for s in ic.CANDIDATE_STATUS_VALUES}},
    )
    violations = ic.validate_category_summary(row)
    assert any("needs_manual_validation" in v and "无该状态计数" in v for v in violations)
    row = _summary_row(
        category_status="approval_required",
        tested_count=0,
        status_counts={**{s: 0 for s in ic.CANDIDATE_STATUS_VALUES}, "signal": 1},
    )
    violations = ic.validate_category_summary(row)
    assert any("approval_required" in v and "candidate=0" in v for v in violations)


def test_summary_counts_without_source_violation():
    violations = ic.validate_category_summary(_summary_row(source=""))
    assert any("source 为空" in v for v in violations)


def test_summary_candidate_without_precondition_violation():
    violations = ic.validate_category_summary(_summary_row(precondition=""))
    assert any("precondition 为空" in v for v in violations)


def test_summary_non_mapping_violation():
    violations = ic.validate_category_summary("not-a-row")  # type: ignore[arg-type]
    assert violations == ["injection_summary: 行必须是键值映射"]


def test_aggregate_category_status_priority():
    assert ic.aggregate_category_status([], False) == "inconclusive"
    assert ic.aggregate_category_status([], True) == "not_applicable"
    assert ic.aggregate_category_status(["signal", "candidate"], True) == "tested"
    assert ic.aggregate_category_status(["signal", "needs_manual_validation"], True) == "needs_manual_validation"
    assert ic.aggregate_category_status(["signal"], True) == "inconclusive"


# ---------------------------------------------------------------------------
# 候选条目校验（13.2 负例）
# ---------------------------------------------------------------------------

def test_valid_candidate_passes():
    assert ic.validate_injection_candidate(_candidate()) == []


def test_signal_candidate_without_evidence_ref_passes():
    cand = _candidate(
        status="signal", evidence_ref="", approval_required=False, reason="",
        evidence_kinds=["template_syntax_seen"],
    )
    assert ic.validate_injection_candidate(cand) == []


def test_ssti_candidate_with_syntax_only_rejected():
    violations = ic.validate_injection_candidate(
        _candidate(
            category="ssti",
            evidence_kinds=["template_syntax_seen"],
            evidence_ref="runs/demo/evidence/ssti/echo.html",
        )
    )
    assert any("升级证据不满足" in v and "不算漏洞" in v for v in violations)


def test_deserialization_candidate_with_name_only_rejected():
    violations = ic.validate_injection_candidate(
        _candidate(
            category="unsafe_deserialization",
            evidence_kinds=["fingerprint_or_name_only"],
            evidence_ref="runs/demo/evidence/deser/lib.txt",
        )
    )
    assert any("升级证据不满足" in v for v in violations)


def test_xxe_candidate_with_xml_content_only_rejected():
    violations = ic.validate_injection_candidate(
        _candidate(
            category="xxe",
            evidence_kinds=["xml_content_seen"],
            evidence_ref="runs/demo/evidence/xxe/req.xml",
        )
    )
    assert any("升级证据不满足" in v for v in violations)


def test_candidate_unknown_status_and_category_violation():
    violations = ic.validate_injection_candidate(_candidate(status="vulnerable", category="nosuch"))
    assert any("status 非法" in v for v in violations)
    assert any("category 非法" in v for v in violations)


def test_candidate_missing_required_fields_violation():
    violations = ic.validate_injection_candidate({"candidate_id": "inj-x"})
    assert any("缺少必需字段 category" in v for v in violations)
    assert any("缺少必需字段 evidence_kinds" in v for v in violations)


def test_candidate_empty_or_unknown_evidence_kinds_violation():
    violations = ic.validate_injection_candidate(_candidate(evidence_kinds=[]))
    assert any("evidence_kinds 不能为空" in v for v in violations)
    violations = ic.validate_injection_candidate(_candidate(evidence_kinds=["ghost"]))
    assert any("未知形态" in v for v in violations)


def test_candidate_candidate_status_without_evidence_ref_violation():
    violations = ic.validate_injection_candidate(_candidate(evidence_ref=""))
    assert any("evidence_ref 为空" in v for v in violations)


def test_candidate_approval_required_without_reason_violation():
    violations = ic.validate_injection_candidate(_candidate(reason=""))
    assert any("reason 为空" in v for v in violations)


def test_candidate_needs_manual_validation_requires_evidence_ref():
    violations = ic.validate_injection_candidate(
        _candidate(
            status="needs_manual_validation",
            evidence_kinds=["reflected_only"],
            evidence_ref="",
        )
    )
    assert any("evidence_ref 为空" in v for v in violations)


# ---------------------------------------------------------------------------
# 筛选行为（derive_evidence_kinds / grade_observation / screen_observations）
# ---------------------------------------------------------------------------

def test_derive_evidence_kinds_deterministic_mapping():
    kinds = ic.derive_evidence_kinds(
        {
            "query_input_point_confirmed": True,
            "differential_observed": True,
            "template_syntax_observed": True,
            "irrelevant_key": True,
        }
    )
    assert kinds == ["query_input_point", "differential", "template_syntax_seen"]
    assert ic.derive_evidence_kinds({}) == []


def test_grade_observation_upgrades_only_with_sufficient_evidence():
    assert ic.grade_observation("sql", ["query_input_point", "error_based"]) == "candidate"
    assert ic.grade_observation("ssti", ["template_syntax_seen"]) == "signal"
    assert ic.grade_observation("sql", []) == "signal"


def test_grade_observation_status_hint_and_fallback():
    assert ic.grade_observation("sql", [], status_hint="blocked") == "blocked"
    assert ic.grade_observation("sql", [], status_hint="not-a-status") == "signal"


def test_screen_observations_sql_candidate_and_summary():
    obs = {
        "observation_schema_version": ic.OBSERVATION_SCHEMA_VERSION,
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
    rows, summaries, violations = ic.screen_observations([obs])
    assert violations == []
    assert len(rows) == 1
    assert rows[0]["candidate_id"] == "inj-0001"
    assert rows[0]["status"] == "candidate"
    assert rows[0]["source"] == "/api/user/list GET query sort"
    assert ic.validate_injection_candidate(rows[0]) == []
    assert len(summaries) == 15
    by_cat = {s["category"]: s for s in summaries}
    assert by_cat["sql"]["category_status"] == "tested"
    assert by_cat["sql"]["applicability_counts"] == {"applicable": 1, "not_applicable": 0, "unknown": 0}
    assert by_cat["sql"]["status_counts"]["candidate"] == 1
    assert by_cat["sql"]["tested_count"] == 1
    assert by_cat["nosql"]["category_status"] == "inconclusive"
    assert by_cat["nosql"]["status_counts"]["candidate"] == 0
    assert by_cat["nosql"]["tested_count"] == 0
    for summary in summaries:
        assert ic.validate_category_summary(summary) == []


def test_screen_observations_not_applicable_summary_shape():
    """③：not_applicable 观察只进 applicability_counts.not_applicable，不产候选。"""
    obs = {
        "category": "nosql",
        "applicability": "not_applicable",
        "reason": "目标无文档数据库查询端点",
    }
    rows, summaries, violations = ic.screen_observations([obs], all_categories=False)
    assert violations == []
    assert rows == []
    summary = summaries[0]
    assert summary["category_status"] == "not_applicable"
    assert summary["applicability_counts"]["not_applicable"] == 1
    assert summary["applicability_counts"]["applicable"] == 0
    assert all(v == 0 for v in summary["status_counts"].values())
    assert summary["tested_count"] == 0
    assert summary["reason"] == "目标无文档数据库查询端点"


def test_screen_observations_mixed_applicability_prefers_applicable():
    obs_ok = {
        "endpoint": "/a",
        "category": "lfi",
        "applicability": "applicable",
        "evidence": {"differential_observed": True},
        "evidence_ref": "runs/demo/evidence/lfi/diff.json",
        "source": "/a",
        "precondition": "人工确认 include 参数进入文件读取",
    }
    obs_na = {"category": "lfi", "applicability": "not_applicable", "reason": "无 include 面"}
    _, summaries, violations = ic.screen_observations([obs_ok, obs_na], all_categories=False)
    assert violations == []
    assert summaries[0]["category_status"] == "tested"
    assert summaries[0]["applicability_counts"] == {"applicable": 1, "not_applicable": 1, "unknown": 0}


def test_screen_observations_reflected_only_stays_signal():
    obs = {
        "endpoint": "/search",
        "category": "sql",
        "applicability": "applicable",
        "evidence": {"reflected_observed": True},
        "source": "01_重要_Cookie 队列",
    }
    rows, summaries, violations = ic.screen_observations([obs], all_categories=False)
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert summaries[0]["status_counts"]["candidate"] == 0
    assert summaries[0]["tested_count"] == 0
    assert summaries[0]["category_status"] == "inconclusive"


def test_screen_observations_unknown_applicability_stays_unknown():
    obs = {
        "endpoint": "/render",
        "category": "ssti",
        "applicability": "unknown",
        "evidence": {"template_syntax_observed": True},
        "source": "runs/demo/evidence/ssti/echo.html",
    }
    rows, summaries, violations = ic.screen_observations([obs], all_categories=False)
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert summaries[0]["category_status"] == "inconclusive"
    assert summaries[0]["applicability_counts"]["unknown"] == 1


def test_screen_observations_observation_version_mismatch_violation():
    obs = {
        "observation_schema_version": "9.9",
        "endpoint": "/a",
        "category": "sql",
        "applicability": "not_applicable",
        "reason": "无查询面",
    }
    _, _, violations = ic.screen_observations([obs], all_categories=False)
    assert any("observation_schema_version" in v for v in violations)
    ok_obs = dict(obs, observation_schema_version=ic.OBSERVATION_SCHEMA_VERSION)
    _, _, violations = ic.screen_observations([ok_obs], all_categories=False)
    assert violations == []


def test_screen_observations_missing_source_violation():
    obs = {
        "category": "ldap",
        "applicability": "applicable",
        "evidence": {"error_message_observed": True},
        "evidence_ref": "runs/demo/evidence/ldap/err.txt",
    }
    _, summaries, violations = ic.screen_observations([obs], all_categories=False)
    assert any("缺少来源" in v for v in violations)
    assert summaries[0]["status_counts"]["candidate"] == 1  # error_based 满足 ldap 升级规则


def test_screen_observations_all_categories_false_lists_only_seen():
    obs = {
        "category": "ldap",
        "applicability": "not_applicable",
        "reason": "无 LDAP 认证",
    }
    _, summaries, violations = ic.screen_observations([obs], all_categories=False)
    assert violations == []
    assert [s["category"] for s in summaries] == ["ldap"]


def test_screen_observations_invalid_inputs_reported():
    _, _, violations = ic.screen_observations([{"category": "ghost", "applicability": "applicable"}])
    assert any("category 非法" in v for v in violations)
    _, _, violations = ic.screen_observations(
        [{"category": "sql", "applicability": "maybe"}]
    )
    assert any("applicability 非法" in v for v in violations)
    _, _, violations = ic.screen_observations(["bad"])  # type: ignore[list-item]
    assert any("必须是键值映射" in v for v in violations)


def test_screen_observations_candidate_row_violations_surface():
    """观察缺 evidence_ref 且升级为 candidate 时，行级违例必须透传（evidence gate 前置）。"""
    obs = {
        "endpoint": "/a",
        "category": "os_command",
        "applicability": "applicable",
        "evidence": {"semantic_anomaly_observed": True},
        "source": "/a",
    }
    _, summaries, violations = ic.screen_observations([obs], all_categories=False)
    assert any("evidence_ref 为空" in v for v in violations)
    assert summaries[0]["status_counts"]["candidate"] == 1
