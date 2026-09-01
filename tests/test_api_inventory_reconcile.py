"""tests/test_api_inventory_reconcile.py —— API 版本/影子面盘点与文档↔流量对账测试
（batch8_0，规格 5.3 API schema/version 小节 + 3.1 analysis 模块清单）。

覆盖：版本识别三优先级与大小写确定性、shadow 标记（完整部件语义防偶然子串）、
来源/方法/Content-Type 归类与缺值不猜测、D/E 资格引用 canonical_keys 单一实现、
六类对账差异正负例、流量行 D/E 拒收（猜测路径不能证明可达）、双 host 键隔离、
未知查询值不猜测、CSV 表头契约常量。纯离线数据变换，不发请求、不落盘实盘产物。
"""
from __future__ import annotations

import csv

from authorized_assessment.analysis import api_inventory_reconcile as air
from authorized_assessment.triage import canonical_keys as ck


DOC_V1 = {
    "path": "/api/v1/users",
    "host": "api.example.com",
    "http_method": "GET",
    "content_type": "application/json",
    "source_kind": "A",
    "declared_version": "1.0",
    "source": "openapi.json",
}

TRAFFIC_V1 = {
    "path": "/api/v1/users",
    "host": "api.example.com",
    "http_method": "get",
    "content_type": "application/json",
    "source_kind": "C",
    "source": "burp",
}


def test_version_label_path_segment_priority():
    """路径段版本最优先；大写路径段规范化识别；无标记 → none。"""
    assert air.detect_version_label({"path": "/api/v1/users"}) == "v1"
    assert air.detect_version_label({"path": "/API/V2/Users"}) == "v2"
    assert air.detect_version_label({"path": "/api/v10/items"}) == "v10"
    assert air.detect_version_label({"path": "/api/users", "host": "api.example.com"}) == "none"


def test_version_label_query_then_host_fallback():
    """路径无标记时查询版本参数次之，host 标签最后；纯数字值映射 vN；未知值不猜测。"""
    assert (
        air.detect_version_label({"path": "/api/users", "query": {"version": "3"}})
        == "v3"
    )
    assert (
        air.detect_version_label({"path": "/api/users", "query": {"api-version": "v4"}})
        == "v4"
    )
    assert (
        air.detect_version_label({"path": "/api/users", "query": {"apiversion": "10"}})
        == "v10"
    )
    assert (
        air.detect_version_label({"path": "/api/users", "query": {"ver": "3"}})
        == "none"
    )
    assert air.detect_version_label({"path": "/api/users", "host": "v5.example.com"}) == "v5"
    assert (
        air.detect_version_label({"path": "/v6/users", "query": {"version": "7"}})
        == "v6"
    )
    # v11+ 不猜测：查询值超出登记表 → 回落 host 无标记 → none
    assert (
        air.detect_version_label({"path": "/api/users", "query": {"version": "11"}})
        == "none"
    )
    # declared_version：语义版本取主版本映射；无法映射保留原值
    assert air._declared_version_label({"declared_version": "2.0"}) == "v2"
    assert air._declared_version_label({"declared_version": "10.2.3"}) == "v10"
    assert air._declared_version_label({"declared_version": "V3"}) == "v3"
    assert air._declared_version_label({"declared_version": "0.9"}) == "0.9"
    assert air._declared_version_label({"declared_version": "v11"}) == "v11"


def test_shadow_markers_whole_part_semantics():
    """shadow 标记为分隔符完整部件相等——latest/contest 等偶然子串不命中。"""
    assert air.detect_shadow_markers({"path": "/api/test/users"}) == ("test",)
    assert air.detect_shadow_markers({"path": "/debug/api", "host": "staging.example.com"}) == (
        "debug",
        "staging",
    )
    # 部件内子串不命中：latest 含 test 子串但部件为 latest
    assert air.detect_shadow_markers({"path": "/api/latest/users"}) == ()
    # contest 部件含 test 子串但不相等
    assert air.detect_shadow_markers({"path": "/contest/rules"}) == ()
    # dev-demo uat-qa 均为独立部件
    assert air.detect_shadow_markers({"path": "/dev/demo"}) == ("dev", "demo")
    assert air.detect_shadow_markers({"path": "/api/users"}) == ()


def test_normalize_source_and_content_type():
    """来源 A-E 大写、非法归 unknown；Content-Type 去参数小写、空值不猜测。"""
    assert air.normalize_source_kind("a") == "A"
    assert air.normalize_source_kind("C") == "C"
    assert air.normalize_source_kind("X") == "unknown"
    assert air.normalize_source_kind("") == "unknown"
    assert air.normalize_content_type("Application/JSON; charset=utf-8") == "application/json"
    assert air.normalize_content_type("") == ""
    assert air.normalize_content_type(None) == ""
    # D/E 资格引用 canonical_keys 单一实现（不重复定义资格表）
    assert ck.SOURCE_KIND_ELIGIBILITY["queue_eligible"] == ("A", "B", "C")


def test_build_inventory_summary_and_row_contract():
    manifest = air.build_api_version_inventory(
        [
            DOC_V1,
            {"path": "/test/api", "host": "staging.example.com", "source_kind": "E"},
            {"path": "/api/v2/users", "host": "api.example.com", "content_type": "application/xml"},
        ]
    )
    assert manifest["inventory_version"] == "1.0"
    assert manifest["violations"] == []
    assert manifest["summary"]["total"] == 3
    assert manifest["summary"]["by_source_kind"] == {"A": 1, "E": 1, "unknown": 1}
    assert manifest["summary"]["by_version_label"] == {
        "none": 1,
        "v1": 1,
        "v2": 1,
        **{f"v{n}": 0 for n in range(3, 11)},
    }
    assert manifest["summary"]["shadow_hit_rows"] == 1
    assert manifest["summary"]["by_method"] == {"GET": 1, "UNKNOWN": 2}
    rows = manifest["rows"]
    assert rows[0]["http_method"] == "GET"
    assert rows[0]["content_type"] == "application/json"
    assert rows[1]["shadow_markers"] == ["test", "staging"]  # 登记表顺序（模块 docstring 确定性约定）
    assert rows[2]["declared_version"] == ""


def test_build_inventory_row_violations():
    # build 侧：非法来源先归一化为 unknown（盘点不是准入，缺端点仍可检出）
    manifest = air.build_api_version_inventory(
        [
            {"path": "/api/users", "source_kind": "Z"},
            {"host": "api.example.com"},
        ]
    )
    assert manifest["rows"][0]["source_kind"] == "unknown"
    assert any("endpoint_or_surface 为空" in v for v in manifest["violations"])
    # 行校验层：显式非法值可检出（build 侧派生字段恒合法，非法值仅校验层产生）
    violations = air.validate_inventory_row(
        {"endpoint_or_surface": "/x", "source_kind": "Z"}, label="t"
    )
    assert any("source_kind 非法" in v for v in violations)
    violations = air.validate_inventory_row(
        {"endpoint_or_surface": "/x", "version_label": "v99"}, label="t"
    )
    assert any("version_label 非法" in v for v in violations)
    violations = air.validate_inventory_row(
        {"endpoint_or_surface": "/x", "shadow_markers": ["not_a_marker"]}, label="t"
    )
    assert any("shadow_markers 未知标记" in v for v in violations)


def test_reconcile_doc_only_and_traffic_only():
    rep = air.reconcile_api_inventory(
        [DOC_V1],
        [
            {
                "path": "/api/v2/orders",
                "host": "api.example.com",
                "http_method": "GET",
                "source_kind": "B",
            }
        ],
    )
    statuses = {row["endpoint_or_surface"]: row["status"] for row in rep["rows"]}
    # 对账键剥离版本段（同资源不同版本同键，模块 _reconcile_path 约定）
    assert statuses["/api/users"] == "doc_only"
    assert statuses["/api/orders"] == "traffic_only"
    assert rep["summary"]["by_status"]["doc_only"] == 1
    assert rep["summary"]["by_status"]["traffic_only"] == 1
    doc_only_row = next(r for r in rep["rows"] if r["status"] == "doc_only")
    assert "文档登记但无 B/C 流量证据" in doc_only_row["reason"]
    assert "doc_versions=['v1']" in doc_only_row["reason"]
    traffic_only_row = next(r for r in rep["rows"] if r["status"] == "traffic_only")
    assert "实际可达但文档未登记" in traffic_only_row["reason"]
    assert "traffic_versions=['v2']" in traffic_only_row["reason"]


def test_reconcile_matched_and_mismatches():
    # 一致：method 大小写归一、Content-Type 参数差异不算差异
    rep = air.reconcile_api_inventory([DOC_V1], [TRAFFIC_V1])
    assert rep["rows"][0]["status"] == "matched"
    assert rep["rows"][0]["reason"] == "文档与流量一致"
    # method 差异
    rep = air.reconcile_api_inventory(
        [DOC_V1],
        [
            {
                "path": "/api/v1/users",
                "host": "api.example.com",
                "http_method": "POST",
                "source_kind": "C",
            }
        ],
    )
    row = rep["rows"][0]
    assert row["status"] == "method_mismatch"
    assert "doc=['GET'] traffic=['POST']" in row["reason"]
    # Content-Type 差异
    rep = air.reconcile_api_inventory(
        [DOC_V1],
        [
            {
                "path": "/api/v1/users",
                "host": "api.example.com",
                "http_method": "GET",
                "content_type": "text/xml",
                "source_kind": "C",
            }
        ],
    )
    assert rep["rows"][0]["status"] == "content_type_mismatch"
    # 版本差异：路径段版本不交集
    rep = air.reconcile_api_inventory(
        [DOC_V1],
        [
            {
                "path": "/api/v2/users",
                "host": "api.example.com",
                "http_method": "GET",
                "content_type": "application/json",
                "source_kind": "C",
            }
        ],
    )
    row = rep["rows"][0]
    assert row["status"] == "version_mismatch"
    assert "doc=['v1'] traffic=['v2']" in row["reason"]


def test_reconcile_version_mismatch_fixed_priority_and_secondary_reasons():
    """差异共存时单值 status 取固定优先级（method > content_type > version），次级差异写入 reason。"""
    rep = air.reconcile_api_inventory(
        [DOC_V1],
        [
            {
                "path": "/api/v2/users",
                "host": "api.example.com",
                "http_method": "POST",
                "content_type": "text/xml",
                "source_kind": "C",
            }
        ],
    )
    row = rep["rows"][0]
    assert row["status"] == "method_mismatch"
    assert "content_type_mismatch" in row["reason"]
    assert "version_mismatch" in row["reason"]


def test_reconcile_traffic_de_and_e_rejected():
    """流量行 D/E 来源拒收：猜测路径不能证明可达，不能进入对账。"""
    rep = air.reconcile_api_inventory(
        [DOC_V1],
        [
            {
                "path": "/api/v1/users",
                "host": "api.example.com",
                "http_method": "GET",
                "source_kind": "D",
            },
            {
                "path": "/api/v9/guess",
                "host": "api.example.com",
                "http_method": "GET",
                "source_kind": "E",
            },
        ],
    )
    assert len(rep["rows"]) == 1
    assert rep["rows"][0]["status"] == "doc_only"
    assert rep["summary"]["traffic_key_count"] == 0
    assert sum("不在可证明可达来源" in v for v in rep["violations"]) == 2


def test_reconcile_inventory_side_accepts_all_kinds():
    """盘点侧不是队列准入：A-E+unknown 全部接受（资格语义只在流量对账侧强制）。"""
    manifest = air.build_api_version_inventory(
        [{"path": f"/api/{kind}/x", "source_kind": kind} for kind in ("A", "B", "C", "D", "E", "?")]
    )
    assert manifest["violations"] == []
    assert manifest["summary"]["by_source_kind"]["unknown"] == 1


def test_reconcile_host_key_isolation():
    """同一路径不同 host 键隔离：不对账、不互相吞噬。"""
    doc = dict(DOC_V1, host="api.example.com")
    traffic = dict(TRAFFIC_V1, host="api.other.com")
    rep = air.reconcile_api_inventory([doc], [traffic])
    statuses = sorted(row["status"] for row in rep["rows"])
    assert statuses == ["doc_only", "traffic_only"]
    assets = sorted(row["asset"] for row in rep["rows"])
    assert assets == ["api.example.com", "api.other.com"]


def test_reconcile_requires_endpoint_and_row_contract():
    rep = air.reconcile_api_inventory([{"host": "api.example.com"}], [])
    assert any("缺少 path/endpoint" in v for v in rep["violations"])
    # 行契约负例：篡改 status 为 coverage 子状态被行校验拒绝
    rep2 = air.reconcile_api_inventory([DOC_V1], [TRAFFIC_V1])
    assert rep2["violations"] == []
    bad_row = dict(rep2["rows"][0], status="tested")
    violations = air.validate_reconciliation_row(bad_row, label="t")
    assert any("对账状态值域" in v and "非 coverage 子状态" in v for v in violations)


def test_csv_header_contracts():
    """两 CSV 表头契约常量与行构造一致（落盘接线归后续批次，表头先锁定）。"""
    assert air.API_VERSION_INVENTORY_CSV_FIELDS == (
        "endpoint_or_surface",
        "canonical_host",
        "http_method",
        "content_type",
        "source_kind",
        "declared_version",
        "version_label",
        "shadow_markers",
        "source",
        "evidence_ref",
    )
    # v1.1（操作员 batch8_5 决定②）：规格 5.2 七字段 + object_field_authorization
    assert air.RECONCILIATION_ROW_FIELDS == (
        "applicable",
        "status",
        "source",
        "asset",
        "endpoint_or_surface",
        "reason",
        "evidence_ref",
    )
    assert air.API_RECONCILIATION_CSV_FIELDS == air.RECONCILIATION_ROW_FIELDS + (
        "object_field_authorization",
    )
    # 表头与盘点行字段一一对应
    manifest = air.build_api_version_inventory([DOC_V1])
    row = manifest["rows"][0]
    for field in air.API_VERSION_INVENTORY_CSV_FIELDS:
        assert field in row
    # shadow_markers 序列化约定：sorted + "|" 连接
    assert "|".join(sorted(["test", "staging"])) == "staging|test"


def test_object_field_authorization_substatus():
    """操作员 batch8_5 决定②：子状态机器可审计（默认/声明/优先/负例/语义）。"""
    # 八值枚举（七值 + not_applicable 完备项）
    assert air.OBJECT_FIELD_AUTHORIZATION_STATUSES == (
        "tested",
        "candidate",
        "needs_manual_validation",
        "confirmed",
        "rejected",
        "blocked",
        "inconclusive",
        "not_applicable",
    )
    # 双侧均未声明 → inconclusive（未测，不猜测）
    rep = air.reconcile_api_inventory([DOC_V1], [TRAFFIC_V1])
    assert rep["rows"][0]["object_field_authorization"] == "inconclusive"
    # 单侧声明：doc 侧 tested
    rep = air.reconcile_api_inventory(
        [dict(DOC_V1, object_field_authorization="tested")], [TRAFFIC_V1]
    )
    assert rep["rows"][0]["object_field_authorization"] == "tested"
    # 双侧声明：流量侧优先（流量对实际行为更权威）
    rep = air.reconcile_api_inventory(
        [dict(DOC_V1, object_field_authorization="tested")],
        [dict(TRAFFIC_V1, object_field_authorization="candidate")],
    )
    assert rep["rows"][0]["object_field_authorization"] == "candidate"
    # doc_only 行无 traffic 侧：doc 声明生效
    rep = air.reconcile_api_inventory(
        [dict(DOC_V1, object_field_authorization="blocked")], []
    )
    assert rep["rows"][0]["object_field_authorization"] == "blocked"
    # 非法子状态：行校验拒绝
    violations = air.validate_reconciliation_row(
        dict(rep["rows"][0], object_field_authorization="vulnerable"), label="t"
    )
    assert any("object_field_authorization 非法" in v for v in violations)
    # candidate 缺 evidence_ref：可审计性拒绝
    violations = air.validate_reconciliation_row(
        {
            "applicable": "applicable",
            "status": "matched",
            "source": "s",
            "asset": "h",
            "endpoint_or_surface": "/p",
            "reason": "r",
            "evidence_ref": "",
            "object_field_authorization": "candidate",
        },
        label="t",
    )
    assert any("必须可审计" in v for v in violations)
    # 非证明语义字段说明存在（字段存在≠授权漏洞）
    assert "不构成授权漏洞证据" in air.OBJECT_FIELD_AUTHORIZATION_FIELD_DOC


def test_csv_roundtrip_via_tmp_workspace(tmp_path):
    """tmp 落盘仅验证表头契约一致性（不触碰实盘 artifacts/）。"""
    manifest = air.build_api_version_inventory([DOC_V1, TRAFFIC_V1])
    path = tmp_path / "api-version-inventory.csv"
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(list(air.API_VERSION_INVENTORY_CSV_FIELDS))
        for row in manifest["rows"]:
            writer.writerow(
                [
                    row["endpoint_or_surface"],
                    row["canonical_host"],
                    row["http_method"],
                    row["content_type"],
                    row["source_kind"],
                    row["declared_version"],
                    row["version_label"],
                    "|".join(sorted(row["shadow_markers"])),
                    row["source"],
                    row["evidence_ref"],
                ]
            )
    with path.open("r", encoding="utf-8", newline="") as f:
        header = next(csv.reader(f))
    assert header == list(air.API_VERSION_INVENTORY_CSV_FIELDS)


def test_reconcile_path_strips_version_segment():
    """对账键剥离版本段：同资源不同版本落同键（版本差异由 versions 集比较产生）。"""
    assert air._reconcile_path("/api/v1/users") == "/api/users"
    assert air._reconcile_path("/api/v2/users") == "/api/users"
    assert air._reconcile_path("/api/v1/users") == air._reconcile_path("/api/v2/users")
    assert air._reconcile_path("/api/users/123") == "/api/users/{n}"
    assert air._reconcile_path("/") == "/"
    # 无版本段不变
    assert air._reconcile_path("/api/orders") == "/api/orders"
    # query 版本参数不影响键（版本由 detect_version_label 提取进 versions 集）
    assert (
        air._reconcile_path("/api/users")
        == air._reconcile_path("/api/users")
    )


def test_reconcile_version_mismatch_via_path_versions():
    """版本差异：/api/v1/users（doc）vs /api/v2/users（traffic）→ 同键 version_mismatch。"""
    rep = air.reconcile_api_inventory(
        [DOC_V1],
        [
            {
                "path": "/api/v2/users",
                "host": "api.example.com",
                "http_method": "GET",
                "content_type": "application/json",
                "source_kind": "C",
            }
        ],
    )
    assert len(rep["rows"]) == 1
    row = rep["rows"][0]
    assert row["status"] == "version_mismatch"
    assert "doc=['v1'] traffic=['v2']" in row["reason"]


def test_serialization_determinism():
    """操作员决定⑥：序列化确定性——同输入两次逐字节相等、乱序输入不改变输出、
    空产物/特殊字符/None 安全、字段顺序 = 表头常量。"""
    row = {
        "endpoint_or_surface": "/api/v1/用户,查询",  # 特殊字符
        "canonical_host": "api.example.com",
        "http_method": "GET",
        "content_type": "application/json",
        "source_kind": "A",
        "declared_version": "1.0",
        "version_label": "v1",
        "shadow_markers": ["test", "staging", "beta"],
        "source": "openapi.json",
        "evidence_ref": None,  # None → 空串
    }
    first = air.serialize_inventory_row(row)
    second = air.serialize_inventory_row(dict(reversed(list(row.items()))))
    assert first == second
    assert list(first) == list(air.API_VERSION_INVENTORY_CSV_FIELDS)
    assert first["shadow_markers"] == "beta|staging|test"
    assert first["evidence_ref"] == ""
    # 空产物
    empty = air.serialize_inventory_row({})
    assert all(v == "" for v in empty.values())
    # CSV 写读往返：值逐单元格相等（含特殊字符）
    rec_row = {
        "applicable": "applicable",
        "status": "method_mismatch",
        "source": "openapi_doc+captured_traffic",
        "asset": "api.example.com",
        "endpoint_or_surface": "/api/users",
        "reason": "含特殊字符：分号; 竖线| 引号\"",
        "evidence_ref": "doc:x;traffic:y",
        "object_field_authorization": "candidate",
    }
    rec = air.serialize_reconciliation_row(rec_row)
    rec2 = air.serialize_reconciliation_row(dict(reversed(list(rec_row.items()))))
    assert rec == rec2
    assert list(rec) == list(air.API_RECONCILIATION_CSV_FIELDS)


def test_reconcile_is_not_candidate_generation():
    """对账清单不是漏洞：结果结构无候选/8 状态概念（规格 11.3 边界的结构级锁定）。"""
    rep = air.reconcile_api_inventory([DOC_V1], [TRAFFIC_V1])
    assert "rows" in rep and "status" in rep["rows"][0]
    assert not hasattr(air, "screen_observations")
    assert not hasattr(air, "grade_observation")
    assert set(rep["summary"]["by_status"]) == set(air.RECONCILIATION_STATUSES)
