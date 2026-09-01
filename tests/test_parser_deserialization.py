"""tests/test_parser_deserialization.py —— 解析器/反序列化筛选测试（Batch 6 / 规格 5.4 + 13.2）。

覆盖：
  - 解析面确定性识别（content_type/端点/正文形态标记 → xxe/xml_parser/yaml_parser/
    unsafe_deserialization 四类子集）；
  - 规格 5.4 XXE 五类前置条件命中/未命中；
  - screen_parser_observations：SOAP 差分证据 → xml_parser candidate；无证据 → signal；
    序列化面仅指纹/依赖名 → signal（13.2：仅有依赖名称、类名或序列化格式不算漏洞）；
    not_applicable 记录落入汇总计数；宣称适用但无前置条件被拒；类别与推断不符被拒；
  - 汇总行只含 parser 四类且通过契约校验。
"""
from __future__ import annotations

from authorized_assessment.triage import injection_candidates as ic
from authorized_assessment.triage import parser_deserialization as pd


def _soap_observation(**overrides: object) -> dict:
    obs = {
        "endpoint": "/services/SoapService",
        "content_type": "application/soap+xml",
        "http_method": "POST",
        "input_location": "body",
        "parameter_name": "xmlPayload",
        "applicability": "applicable",
        "category": "xml_parser",
        "evidence": {"differential_observed": True, "query_input_point_confirmed": True},
        "evidence_ref": "runs/demo/evidence/xml/diff.json",
        "reason": "SOAP 端点差分证据",
    }
    obs.update(overrides)
    return obs


# ---------------------------------------------------------------------------
# 解析面识别与前置条件
# ---------------------------------------------------------------------------

def test_surface_categories_from_content_type():
    assert pd.surface_categories(content_type="application/xml") == ["xml_parser"]
    assert pd.surface_categories(content_type="image/svg+xml") == ["xml_parser"]
    assert pd.surface_categories(content_type="application/x-yaml") == ["yaml_parser"]
    assert pd.surface_categories(content_type="application/x-java-serialized-object") == [
        "unsafe_deserialization"
    ]


def test_surface_categories_from_endpoint_and_body_markers():
    assert pd.surface_categories(endpoint="/services/SoapService") == ["xml_parser"]
    assert pd.surface_categories(endpoint="/saml/acs") == ["xml_parser"]
    assert pd.surface_categories(endpoint="/config/yml") == ["yaml_parser"]
    assert pd.surface_categories(body_markers=["<!doctype", "<?xml"]) == ["xml_parser"]
    assert pd.surface_categories(body_markers=["rO0AB"]) == ["unsafe_deserialization"]
    assert pd.surface_categories() == []


def test_surface_categories_stable_dedup_and_subset():
    got = pd.surface_categories(
        content_type="application/xml",
        endpoint="/soap/config/yml",
        body_markers=["rO0AB"],
    )
    assert got == ["xml_parser", "yaml_parser", "unsafe_deserialization"]
    assert set(got) <= set(pd.PARSER_CATEGORIES)


def test_preconditions_hit_each_kind():
    assert pd.parse_surface_preconditions(content_type="application/xml") == {
        "xml_api": "content_type=application/xml"
    }
    assert pd.parse_surface_preconditions(endpoint="/saml/acs")["soap_saml_feed"]
    assert pd.parse_surface_preconditions(
        content_type="application/xml", endpoint="/import/xml"
    )["document_upload_import"]
    assert pd.parse_surface_preconditions(
        content_type="application/xml", endpoint="/config/import"
    )["xml_config_import"]
    assert pd.parse_surface_preconditions(parser_confirmed=True) == {
        "backend_parser": "parser_confirmed 观察证据"
    }


def test_preconditions_empty_when_no_surface():
    assert pd.parse_surface_preconditions() == {}
    assert pd.parse_surface_preconditions(content_type="application/json") == {}
    assert pd.parse_surface_preconditions(endpoint="/api/user") == {}


# ---------------------------------------------------------------------------
# screen_parser_observations 行为
# ---------------------------------------------------------------------------

def test_soap_parser_confirmed_upgrades_to_candidate():
    obs = _soap_observation(
        evidence={"parser_confirmed": True},
        evidence_ref="runs/demo/evidence/xml/entity-echo.json",
    )
    rows, summaries, violations = pd.screen_parser_observations([obs])
    assert violations == []
    assert len(rows) == 1
    assert rows[0]["category"] == "xml_parser"
    assert rows[0]["status"] == "candidate"
    assert "parser_confirmed" in rows[0]["evidence_kinds"]
    assert summaries[0]["category"] == "xml_parser"
    assert summaries[0]["category_status"] == "tested"
    assert summaries[0]["status_counts"]["candidate"] == 1
    assert summaries[0]["precondition"]
    assert ic.validate_injection_candidate(rows[0]) == []
    assert ic.validate_category_summary(summaries[0]) == []


def test_soap_differential_only_stays_signal():
    """差分/查询点证据是 SQL 规则，不满足 xml_parser 的 parser 分支 → signal（不越规则升级）。"""
    rows, summaries, violations = pd.screen_parser_observations([_soap_observation()])
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert summaries[0]["status_counts"]["candidate"] == 0


def test_parser_signal_without_upgrade_evidence():
    rows, summaries, violations = pd.screen_parser_observations(
        [_soap_observation(evidence={"xml_content_observed": True}, evidence_ref="")]
    )
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert summaries[0]["status_counts"]["candidate"] == 0


def test_serialization_surface_with_name_only_stays_signal():
    obs = {
        "endpoint": "/remoting/invoke",
        "content_type": "application/x-java-serialized-object",
        "applicability": "applicable",
        "evidence": {"fingerprint_or_name_only_observed": True},
        "source": "runs/demo/evidence/deser/lib.txt",
    }
    rows, summaries, violations = pd.screen_parser_observations([obs])
    assert violations == []
    assert rows[0]["category"] == "unsafe_deserialization"
    assert rows[0]["status"] == "signal"
    assert summaries[0]["status_counts"]["candidate"] == 0


def test_yaml_surface_detection():
    obs = {
        "endpoint": "/api/config/yml",
        "content_type": "text/yaml",
        "applicability": "applicable",
        "evidence": {
            "external_input_into_parser_observed": True,
            "unsafe_type_recovery_observed": True,
        },
        "evidence_ref": "runs/demo/evidence/yaml/req.txt",
        "source": "config/yml 端点",
    }
    rows, summaries, violations = pd.screen_parser_observations([obs])
    assert violations == []
    assert rows[0]["category"] == "yaml_parser"
    # 外部输入进入解析器 + 不安全类型恢复满足 yaml 分支规则（与 xxe/xml_parser 同源）→ candidate
    assert rows[0]["status"] == "candidate"


def test_not_applicable_without_precondition_falls_into_summary_count():
    obs = {
        "category": "xml_parser",
        "applicability": "not_applicable",
        "reason": "目标无 XML API/SOAP/SAML/RSS/Atom 与文档导入面",
    }
    rows, summaries, violations = pd.screen_parser_observations([obs])
    assert violations == []
    assert rows == []
    assert summaries[0]["category"] == "xml_parser"
    assert summaries[0]["category_status"] == "not_applicable"
    assert summaries[0]["applicability_counts"]["not_applicable"] == 1
    assert all(v == 0 for v in summaries[0]["status_counts"].values())
    assert summaries[0]["reason"]


def test_applicable_without_precondition_is_violation():
    obs = {"applicability": "applicable", "content_type": "application/json"}
    _, _, violations = pd.screen_parser_observations([obs])
    assert any("未命中任何解析面前置条件" in v for v in violations)


def test_declared_category_conflicting_with_inference_is_violation():
    obs = _soap_observation(category="yaml_parser")
    _, _, violations = pd.screen_parser_observations([obs])
    assert any("与解析面推断" in v for v in violations)


def test_summaries_only_cover_parser_categories():
    rows, summaries, _ = pd.screen_parser_observations([_soap_observation()])
    assert {s["category"] for s in summaries} <= set(pd.PARSER_CATEGORIES)
    assert len(summaries) == 1
    assert rows


def test_non_mapping_observation_is_violation():
    _, _, violations = pd.screen_parser_observations(["bad"])  # type: ignore[list-item]
    assert any("必须是键值映射" in v for v in violations)


def test_precondition_note_carries_spec_kinds():
    _, summaries, _ = pd.screen_parser_observations([_soap_observation()])
    assert "soap_saml_feed" in summaries[0]["precondition"]
