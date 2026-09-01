"""tests/test_graphql_inventory.py —— GraphQL 面离线盘点测试（batch7_0，规格 5.2 + 3.1）。

覆盖：面确定性识别标记（端点/正文形态）、盘点行字段与校验违例、status 派生与
pass-through、manifest 汇总计数、not_applicable 语义、完成可证明（tested 必须带
evidence_ref）。纯离线数据变换，不发任何请求。
"""
from __future__ import annotations

from authorized_assessment.analysis.coverage_matrix import COVERAGE_SUBSTATUSES
from authorized_assessment.triage import graphql_inventory as gi


def test_looks_like_graphql_endpoint_markers():
    assert gi.looks_like_graphql(endpoint="https://target.example.com/graphql")
    assert gi.looks_like_graphql(endpoint="/api/gql/v1")
    assert gi.looks_like_graphql(endpoint="/graphiql")


def test_looks_like_graphql_body_markers():
    assert gi.looks_like_graphql(endpoint="/api/search", body_markers=["query { user { id } }"])
    assert gi.looks_like_graphql(body_markers=["__typename"])
    assert gi.looks_like_graphql(body_markers=["mutation "])
    assert gi.looks_like_graphql(body_markers=["OperationName"])


def test_looks_like_graphql_negative():
    assert not gi.looks_like_graphql(endpoint="/api/users", body_markers=['{"id": 1}'])
    assert not gi.looks_like_graphql(endpoint="", body_markers=[])
    assert not gi.looks_like_graphql(endpoint="/api/queryBuilder")


def test_build_inventory_rows_carry_spec_fields():
    manifest = gi.build_graphql_inventory(
        [
            {
                "endpoint": "https://target.example.com/graphql",
                "asset": "web-main",
                "source": "runs/demo/evidence/js/app.bundle.js",
                "evidence_ref": "runs/demo/evidence/js/app.bundle.js:L120",
            }
        ]
    )
    assert manifest["violations"] == []
    assert len(manifest["surfaces"]) == 1
    row = manifest["surfaces"][0]
    for field in ("applicable", "status", "source", "asset", "endpoint_or_surface", "reason", "evidence_ref"):
        assert field in row, field
    assert row["applicable"] == "applicable"
    assert row["endpoint_or_surface"] == "https://target.example.com/graphql"
    # 盘点只证明面存在：未声明 status 时派生 inconclusive（未测），不自动 tested。
    assert row["status"] == "inconclusive"
    assert row["surface_kind"] == "captured_traffic"


def test_build_inventory_summary_counts():
    manifest = gi.build_graphql_inventory(
        [
            {"endpoint": "/graphql", "source": "js_ref", "surface_kind": "js_reference"},
            {"endpoint": "/graphiql", "source": "proxy", "surface_kind": "graphiql_ui"},
            {
                "endpoint": "/legacy-api",
                "applicability": "not_applicable",
                "reason": "确认目标无 GraphQL 面（代理记录无 GraphQL 特征）",
            },
        ]
    )
    assert manifest["violations"] == []
    assert manifest["summary"]["surface_count"] == 3
    assert manifest["summary"]["by_surface_kind"]["js_reference"] == 1
    assert manifest["summary"]["by_surface_kind"]["graphiql_ui"] == 1
    assert manifest["summary"]["by_applicability"] == {
        "applicable": 2,
        "not_applicable": 1,
        "unknown": 0,
    }
    na_row = manifest["surfaces"][2]
    assert na_row["applicable"] == "not_applicable"
    assert na_row["status"] == "not_applicable"
    assert na_row["reason"]


def test_build_inventory_status_passthrough_requires_evidence():
    manifest = gi.build_graphql_inventory(
        [
            {"endpoint": "/graphql", "source": "proxy", "status": "tested"},
            {
                "endpoint": "/api/graphql",
                "source": "proxy",
                "status": "tested",
                "evidence_ref": "runs/demo/evidence/graphql/introspection.json",
            },
        ]
    )
    assert any("evidence_ref 为空" in v for v in manifest["violations"])
    assert manifest["surfaces"][1]["status"] == "tested"
    assert manifest["summary"]["by_status"]["tested"] == 2


def test_build_inventory_row_violations():
    manifest = gi.build_graphql_inventory(
        [
            {"endpoint": "/graphql", "source": "proxy", "surface_kind": "not_a_kind"},
            {"endpoint": "", "body_markers": [], "source": ""},
            {"endpoint": "/graphql", "source": "proxy", "applicability": "maybe"},
            "not-a-mapping",
        ]
    )
    assert any("surface_kind 非法" in v for v in manifest["violations"])
    assert any("缺少 endpoint_or_surface" in v for v in manifest["violations"])
    assert any("applicability 非法" in v for v in manifest["violations"])
    assert any("必须是键值映射" in v for v in manifest["violations"])


def test_build_inventory_empty_is_clean():
    manifest = gi.build_graphql_inventory([])
    assert manifest["surfaces"] == []
    assert manifest["violations"] == []
    assert manifest["summary"]["surface_count"] == 0


def test_inventory_module_constants_match_contract():
    """契约 inventory 节与模块常量同源（validate_run_contracts 的轻量前置）。"""
    import json
    from pathlib import Path

    contract = json.loads(
        (Path(__file__).resolve().parents[1] / "contracts" / "graphql_schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert tuple(contract["inventory"]["surface_kinds"]) == gi.GRAPHQL_SURFACE_KINDS
    assert tuple(contract["inventory"]["row_fields"]) == gi.INVENTORY_ROW_FIELDS
    assert contract["inventory"]["row_fields"][:7] == [
        "applicable",
        "status",
        "source",
        "asset",
        "endpoint_or_surface",
        "reason",
        "evidence_ref",
    ]
    assert set(gi.INVENTORY_ROW_FIELDS[7:]) == {"surface_kind"}


def test_inventory_status_values_from_coverage_substatuses():
    assert all(s in COVERAGE_SUBSTATUSES for s in ("tested", "not_applicable", "inconclusive"))
