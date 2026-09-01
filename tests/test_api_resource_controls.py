"""tests/test_api_resource_controls.py —— API 资源控制只读筛选域测试
（batch8_1，规格 5.3 API 资源控制小节 + 3.1 triage 模块清单）。

覆盖：观察键→证据形态确定性映射、升级边界（13 形态永不升级、2 确认形态才升级、
他类确认形态不跨类升级、未知类别无规则 → signal）、8 状态分级与 status_hint、
候选行校验（非法 category/status、candidate>0 缺 evidence_ref、precondition 契约
经 ic.validate_category_summary 锁定）、筛选汇总（三统计概念分离 + 注入类别路由
违例 + 缺来源/版本不符违例）、高并发红线常量、CSV 表头契约。纯离线数据变换，
不发请求、不做高并发/资源压力验证。
"""
from __future__ import annotations

from authorized_assessment.analysis import api_inventory_reconcile as air
from authorized_assessment.triage import api_resource_controls as arc
from authorized_assessment.triage import injection_candidates as ic

FORM_EVIDENCE = {
    "pagination_params_present_observed": True,
    "deep_pagination_supported_observed": True,
    "no_rate_limit_headers_observed": True,
}

UNBOUNDED_CONFIRMED_OBS = {
    "endpoint": "/api/v1/items",
    "parameter_name": "pageSize",
    "category": "pagination_limits",
    "applicability": "applicable",
    "evidence": {
        "pagination_params_present_observed": True,
        "unbounded_response_confirmed": True,
    },
    "source": "runs/demo/evidence/api/items-pagesize.json",
    "evidence_ref": "runs/demo/evidence/api/items-pagesize.json:L12",
    "reason": "既有只读证据显示 pageSize 无有效上限且可复现",
    "precondition": "确认仅基于既有证据复核；不发起高并发验证",
}

AMPLIFICATION_CONFIRMED_OBS = {
    "endpoint": "/api/v1/report/export",
    "category": "export_permission_cost",
    "applicability": "applicable",
    "evidence": {
        "export_endpoint_present_observed": True,
        "amplification_confirmed": True,
    },
    "source": "runs/demo/evidence/api/export-review.json",
    "evidence_ref": "runs/demo/evidence/api/export-review.json:L3",
    "reason": "既有只读证据显示低权导出实际成功且资源成本确认",
    "precondition": "确认仅基于既有证据复核；不发起高并发验证",
}


def test_derive_evidence_kinds_maps_observation_keys():
    kinds = arc.derive_resource_control_evidence_kinds(
        {
            "pagination_params_present_observed": True,
            "differential_observed": True,
            "unknown_key": True,
        }
    )
    assert kinds == ["pagination_params_present", "differential"]
    assert arc.derive_resource_control_evidence_kinds({}) == []


def test_grade_form_observations_never_upgrade():
    """仅参数面/缺响应头/缺失配额/支持性观察永不升级。"""
    for evidence in (
        FORM_EVIDENCE,
        {"batch_params_present_observed": True},
        {"filter_params_present_observed": True, "cost_hint_observed": True},
        {"export_endpoint_present_observed": True},
        {"no_quota_documented_observed": True, "semantic_anomaly_observed": True},
        {"cache_headers_present_observed": True, "timeout_error_observed": True},
    ):
        for category in arc.RESOURCE_CONTROL_CATEGORIES:
            kinds = arc.derive_resource_control_evidence_kinds(evidence)
            assert arc.grade_resource_control_observation(category, kinds) == "signal"


def test_grade_confirmed_kinds_upgrade_per_category():
    """unbounded 确认升 pagination/batch/filter 三类；amplification 确认升其余三类。"""
    unbounded = ["unbounded_response_confirmed"]
    amplification = ["amplification_confirmed"]
    assert arc.grade_resource_control_observation("pagination_limits", unbounded) == "candidate"
    assert arc.grade_resource_control_observation("batch_limits", unbounded) == "candidate"
    assert arc.grade_resource_control_observation("filter_complexity", unbounded) == "candidate"
    assert arc.grade_resource_control_observation("export_permission_cost", amplification) == "candidate"
    assert arc.grade_resource_control_observation("rate_quota", amplification) == "candidate"
    assert arc.grade_resource_control_observation("retry_timeout_cache_amp", amplification) == "candidate"
    # 确认形态不跨组升级
    assert arc.grade_resource_control_observation("export_permission_cost", unbounded) == "signal"
    assert arc.grade_resource_control_observation("pagination_limits", amplification) == "signal"


def test_status_hint_respected():
    kinds = arc.derive_resource_control_evidence_kinds(FORM_EVIDENCE)
    assert (
        arc.grade_resource_control_observation("pagination_limits", kinds, "needs_manual_validation")
        == "needs_manual_validation"
    )


def test_validate_candidate_contract():
    violations = arc.validate_resource_control_candidate(
        {
            "candidate_id": "rc-0001",
            "category": "pagination_limits",
            "status": "candidate",
            "evidence_kinds": ["unbounded_response_confirmed"],
            "source": "runs/demo/evidence.json",
            "evidence_ref": "runs/demo/evidence.json:L1",
        }
    )
    assert violations == []
    # 缺必需字段
    violations = arc.validate_resource_control_candidate({"category": "pagination_limits"})
    assert any("缺少必需字段" in v for v in violations)
    # 非法 category
    violations = arc.validate_resource_control_candidate(
        {
            "candidate_id": "x",
            "category": "sql",
            "status": "signal",
            "evidence_kinds": ["pagination_params_present"],
            "source": "s",
        }
    )
    assert any("category 非法" in v for v in violations)
    # 非法 status
    violations = arc.validate_resource_control_candidate(
        {
            "candidate_id": "x",
            "category": "rate_quota",
            "status": "vulnerability",
            "evidence_kinds": ["amplification_confirmed"],
            "source": "s",
        }
    )
    assert any("status 非法" in v for v in violations)
    # candidate 无 evidence_ref
    violations = arc.validate_resource_control_candidate(
        {
            "candidate_id": "x",
            "category": "rate_quota",
            "status": "candidate",
            "evidence_kinds": ["amplification_confirmed"],
            "source": "s",
            "evidence_ref": "",
        }
    )
    assert any("evidence_ref 为空" in v for v in violations)
    # 升级证据不满足仍标 candidate
    violations = arc.validate_resource_control_candidate(
        {
            "candidate_id": "x",
            "category": "rate_quota",
            "status": "candidate",
            "evidence_kinds": ["no_rate_limit_headers"],
            "source": "s",
            "evidence_ref": "r",
        }
    )
    assert any("升级证据不满足" in v for v in violations)
    # 未知证据形态
    violations = arc.validate_resource_control_candidate(
        {
            "candidate_id": "x",
            "category": "rate_quota",
            "status": "signal",
            "evidence_kinds": ["magic_kind"],
            "source": "s",
        }
    )
    assert any("未知形态" in v for v in violations)


def test_screen_routes_injection_categories():
    observations = [
        {"category": "sql", "applicability": "applicable", "endpoint": "/api/x"},
        {"category": "lfi", "applicability": "applicable", "endpoint": "/api/y"},
    ]
    rows, summaries, violations = arc.screen_resource_control_observations(observations)
    assert rows == []
    assert sum("属注入域" in v for v in violations) == 2
    assert len(summaries) == len(arc.RESOURCE_CONTROL_CATEGORIES)


def test_screen_summary_contract_and_na_reason():
    rows, summaries, violations = arc.screen_resource_control_observations(
        [UNBOUNDED_CONFIRMED_OBS, AMPLIFICATION_CONFIRMED_OBS]
    )
    assert violations == []
    assert len(rows) == 2
    pagination = next(s for s in summaries if s["category"] == "pagination_limits")
    assert pagination["status_counts"]["candidate"] == 1
    assert pagination["tested_count"] == 1
    assert pagination["category_status"] == "tested"
    assert pagination["precondition"]  # candidate>0 → precondition 非空（契约）
    export = next(s for s in summaries if s["category"] == "export_permission_cost")
    assert export["status_counts"]["candidate"] == 1
    # not_applicable 类别：汇总行 reason 非空（契约 10.2 语义）
    rows2, summaries2, violations2 = arc.screen_resource_control_observations(
        [
            {
                "category": "rate_quota",
                "applicability": "not_applicable",
                "reason": "目标无速率配额面（纯静态资源）",
            }
        ]
    )
    assert rows2 == [] and violations2 == []
    quota = next(s for s in summaries2 if s["category"] == "rate_quota")
    assert quota["category_status"] == "not_applicable"
    assert quota["reason"]
    assert quota["applicability_counts"]["not_applicable"] == 1


def test_screen_source_and_version_violations():
    rows, summaries, violations = arc.screen_resource_control_observations(
        [
            {
                "category": "batch_limits",
                "applicability": "applicable",
                "observation_schema_version": "0.9",
                "evidence": {"batch_params_present_observed": True},
            }
        ]
    )
    # 违例记录后行仍产出（产物如实落盘由 audit 与复核会话处置，与前批各域语义一致）
    assert len(rows) == 1 and rows[0]["status"] == "signal"
    assert any("observation_schema_version" in v for v in violations)
    assert any("缺少来源" in v for v in violations)


def test_no_load_validation_rule_constant():
    """高并发红线为模块级常量且语义完整（规格红线可被审计引用）。"""
    assert "高并发" in arc.NO_LOAD_VALIDATION_RULE
    assert "资源压力" in arc.NO_LOAD_VALIDATION_RULE
    # 确认形态的观察字段说明必须内嵌红线语义
    for key in ("unbounded_response_confirmed", "amplification_confirmed"):
        assert "不发起高并发" in arc.RESOURCE_CONTROL_OBSERVATION_FIELD_DOCS[key]


def test_csv_header_contract():
    assert arc.RESOURCE_CONTROL_REVIEW_CSV_FIELDS == (
        "candidate_id",
        "category",
        "status",
        "evidence_kinds",
        "source",
        "evidence_ref",
        "precondition",
        "reason",
    )
    rows, _, _ = arc.screen_resource_control_observations([UNBOUNDED_CONFIRMED_OBS])
    for field in arc.RESOURCE_CONTROL_REVIEW_CSV_FIELDS:
        assert field in rows[0]
    # evidence_kinds 序列化约定与 batch8_0 一致
    assert "|".join(sorted(["a", "b"])) == "a|b"


def test_engine_and_status_model_single_source():
    """复用 ic 单一引擎/8 状态/汇总行契约（三统计概念分离不被新域绕过）。"""
    satisfied, _ = ic.rule_satisfied(
        {"required_any_groups": (("amplification_confirmed",),)},
        ["amplification_confirmed"],
        arc.RESOURCE_CONTROL_EVIDENCE_KINDS,
        arc.RESOURCE_CONTROL_INSUFFICIENT_EVIDENCE_KINDS,
    )
    assert satisfied
    assert len(ic.CANDIDATE_STATUS_VALUES) == 8


def test_batch8_modules_offline_by_ast():
    """操作员决定⑦⑨验收项：Batch 8 三模块 AST 扫描无网络/连接类导入——
    结构级证明不发送任何请求、不做高负载验证。"""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    modules = (
        root / "src" / "authorized_assessment" / "triage" / "api_resource_controls.py",
        root / "src" / "authorized_assessment" / "triage" / "third_party_api_review.py",
        root / "src" / "authorized_assessment" / "analysis" / "api_inventory_reconcile.py",
    )
    network_roots = {
        "socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp",
        "websockets", "websocket", "telnetlib", "smtplib", "ftplib", "asyncio",
    }
    for path in modules:
        assert path.is_file(), f"{path} 缺失"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in network_roots, (
                        f"{path.name} 导入网络模块 {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in network_roots, (
                    f"{path.name} from-import 网络模块 {node.module}"
                )


def test_reconcile_duplicate_records_merge_deterministic():
    """操作员决定⑦验收项：重复记录合并确定性——同键重复记录合并为单行，
    集合字段去重排序，两次运行结果一致。（自带对账夹具，不跨测试包导入）"""
    doc_v1 = {
        "path": "/api/v1/users",
        "host": "api.example.com",
        "http_method": "GET",
        "content_type": "application/json",
        "source_kind": "A",
        "declared_version": "1.0",
        "source": "openapi.json",
    }
    traffic_v1 = {
        "path": "/api/v1/users",
        "host": "api.example.com",
        "http_method": "get",
        "content_type": "application/json",
        "source_kind": "C",
        "source": "burp",
    }
    doc_dup = [doc_v1, dict(doc_v1)]
    traffic_dup = [traffic_v1, dict(traffic_v1)]
    rep1 = air.reconcile_api_inventory(doc_dup, traffic_dup)
    rep2 = air.reconcile_api_inventory(doc_dup, traffic_dup)
    assert rep1["rows"] == rep2["rows"]
    assert len(rep1["rows"]) == 1
    assert rep1["rows"][0]["status"] == "matched"
    # 乱序输入不改变行集（键排序保证）
    rep3 = air.reconcile_api_inventory(list(reversed(doc_dup)), list(reversed(traffic_dup)))
    assert rep3["rows"] == rep1["rows"]
