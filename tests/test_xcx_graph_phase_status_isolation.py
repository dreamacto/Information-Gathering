from __future__ import annotations

from authorized_assessment.orchestration.xcx_graph import XCX_CURSOR_FILE, build_xcx_graph, validate_xcx_graph


def test_every_xcx_node_is_bound_to_miniapp_cursor_only():
    graph = build_xcx_graph(created_at="fixed")
    assert all(node.cursor_file == XCX_CURSOR_FILE for node in graph.nodes)
    planning = str(graph.to_planning_dict())
    assert "phase_status.json" not in planning.replace(XCX_CURSOR_FILE, "")
    assert "run_status.json" not in planning


def test_cross_stream_node_and_metadata_are_rejected():
    graph = build_xcx_graph(created_at="fixed").to_dict()
    graph["nodes"][0]["cursor_file"] = "phase_status.json"
    assert any("cursor" in error.lower() or "XCX" in error for error in validate_xcx_graph(graph))


def test_invalid_graph_type_and_missing_nodes_fail_closed():
    assert validate_xcx_graph(None)
    assert validate_xcx_graph({"workflow": "xcx", "nodes": []})
