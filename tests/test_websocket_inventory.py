"""tests/test_websocket_inventory.py —— WebSocket 面离线盘点测试（batch7_1，规格 5.2 + 3.1）。

覆盖：确定性识别标记（scheme/端点/正文形态）、scheme 提取、盘点行字段与校验违例、
status 派生与 pass-through、manifest 汇总计数（含 by_scheme）、not_applicable 语义。
纯离线数据变换，不建立任何连接。
"""
from __future__ import annotations

from authorized_assessment.triage import websocket_inventory as wi


def test_looks_like_websocket_scheme_prefix():
    assert wi.looks_like_websocket(endpoint="wss://target.example.com/realtime")
    assert wi.looks_like_websocket(endpoint="ws://target.example.com/ws")


def test_looks_like_websocket_endpoint_markers():
    assert wi.looks_like_websocket(endpoint="/api/socket.io/")
    assert wi.looks_like_websocket(endpoint="/ws/chat")
    assert wi.looks_like_websocket(endpoint="/sockjs/info")
    assert wi.looks_like_websocket(endpoint="/sse/notifications")
    assert not wi.looks_like_websocket(endpoint="/api/stream")  # stream 过于泛化（可能是视频流），不启发式猜测


def test_looks_like_websocket_body_markers():
    assert wi.looks_like_websocket(body_markers=["new WebSocket('wss://x')"])
    assert wi.looks_like_websocket(body_markers=["EventSource('/sse')"])
    assert wi.looks_like_websocket(body_markers=["socket.onmessage = fn"])
    assert wi.looks_like_websocket(body_markers=["text/event-stream"])


def test_looks_like_websocket_negative():
    assert not wi.looks_like_websocket(endpoint="/api/users", body_markers=['{"id": 1}'])
    assert not wi.looks_like_websocket(endpoint="", body_markers=[])


def test_detect_scheme():
    assert wi.detect_scheme("wss://host/path") == "wss"
    assert wi.detect_scheme("WS://host/path") == "ws"
    assert wi.detect_scheme("https://host/ws") == "unknown"
    assert wi.detect_scheme("") == "unknown"


def test_build_inventory_rows_carry_spec_fields():
    manifest = wi.build_websocket_inventory(
        [
            {
                "endpoint": "wss://target.example.com/realtime",
                "asset": "web-main",
                "source": "runs/demo/evidence/js/chat.bundle.js",
                "evidence_ref": "runs/demo/evidence/js/chat.bundle.js:L88",
            }
        ]
    )
    assert manifest["violations"] == []
    row = manifest["surfaces"][0]
    for field in ("applicable", "status", "source", "asset", "endpoint_or_surface", "reason", "evidence_ref"):
        assert field in row, field
    assert row["applicable"] == "applicable"
    assert row["status"] == "inconclusive"  # 盘点只证明面存在
    assert row["scheme"] == "wss"
    assert row["surface_kind"] == "captured_traffic"


def test_build_inventory_summary_counts():
    manifest = wi.build_websocket_inventory(
        [
            {"endpoint": "ws://a.example.com/ws", "source": "proxy"},
            {"endpoint": "wss://a.example.com/rt", "source": "proxy", "surface_kind": "js_reference"},
            {
                "endpoint": "/api/legacy",
                "applicability": "not_applicable",
                "reason": "JS 与代理记录均无 WebSocket/SSE 特征",
            },
        ]
    )
    assert manifest["violations"] == []
    assert manifest["summary"]["surface_count"] == 3
    assert manifest["summary"]["by_scheme"] == {"ws": 1, "wss": 1, "unknown": 1}
    assert manifest["summary"]["by_surface_kind"]["js_reference"] == 1
    assert manifest["summary"]["by_applicability"]["not_applicable"] == 1
    assert manifest["surfaces"][2]["reason"].startswith("JS 与代理记录")


def test_build_inventory_status_passthrough_requires_evidence():
    manifest = wi.build_websocket_inventory(
        [
            {"endpoint": "ws://a.example.com/ws", "source": "proxy", "status": "tested"},
            {
                "endpoint": "wss://a.example.com/rt",
                "source": "proxy",
                "status": "tested",
                "evidence_ref": "runs/demo/evidence/ws/channel.json",
            },
        ]
    )
    assert any("evidence_ref 为空" in v for v in manifest["violations"])
    assert manifest["summary"]["by_status"]["tested"] == 2


def test_build_inventory_row_violations():
    manifest = wi.build_websocket_inventory(
        [
            {"endpoint": "ws://a.example.com/ws", "source": "p", "surface_kind": "ghost_kind"},
            {"endpoint": "ws://a.example.com/ws", "source": "p", "scheme": "http2"},
            {"endpoint": "", "body_markers": [], "source": ""},
            {"endpoint": "ws://a.example.com/ws", "source": "p", "applicability": "maybe"},
            42,
        ]
    )
    assert any("surface_kind 非法" in v for v in manifest["violations"])
    assert any("scheme 非法" in v for v in manifest["violations"])
    assert any("缺少 endpoint_or_surface" in v for v in manifest["violations"])
    assert any("applicability 非法" in v for v in manifest["violations"])
    assert any("必须是键值映射" in v for v in manifest["violations"])


def test_build_inventory_empty_is_clean():
    manifest = wi.build_websocket_inventory([])
    assert manifest["surfaces"] == []
    assert manifest["violations"] == []
    assert manifest["summary"]["surface_count"] == 0


def test_module_constants_shape():
    """盘点行 = 规格 5.2 七字段 + surface_kind + scheme（实现扩展）。"""
    assert wi.INVENTORY_ROW_FIELDS[:7] == (
        "applicable",
        "status",
        "source",
        "asset",
        "endpoint_or_surface",
        "reason",
        "evidence_ref",
    )
    assert set(wi.INVENTORY_ROW_FIELDS[7:]) == {"surface_kind", "scheme"}
