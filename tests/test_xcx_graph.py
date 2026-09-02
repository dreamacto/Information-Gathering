from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from authorized_assessment.orchestration.xcx_graph import (
    XCX_CURSOR_FILE,
    XCX_PHASES,
    build_xcx_graph,
    validate_xcx_graph,
)

ROOT = Path(__file__).resolve().parents[1]


def load_schema():
    return json.loads((ROOT / "contracts" / "xcx_graph_schema.json").read_text(encoding="utf-8"))


def test_xcx_graph_contract_and_factory_are_aligned():
    schema = load_schema()
    assert schema["$id"] == "xcx_graph_schema"
    assert schema["properties"]["workflow"] == {"const": "xcx"}
    graph = build_xcx_graph(created_at="2026-09-01T00:00:00+00:00")
    errors = list(Draft202012Validator(schema).iter_errors(graph.to_dict()))
    assert errors == []
    assert validate_xcx_graph(graph) == []
    assert {node.cursor_file for node in graph.nodes} == {XCX_CURSOR_FILE}
    assert {node.phase for node in graph.nodes if node.kind == "approval"} == {"approval"}
    assert {node.phase for node in graph.nodes if node.kind == "verifier"} == {"verifier"}


@pytest.mark.parametrize("mutation", ["empty", "wrong_workflow", "wrong_cursor", "unknown_edge", "cycle"])
def test_xcx_graph_rejects_empty_and_illegal_inputs(mutation):
    graph = build_xcx_graph(created_at="fixed").to_dict()
    if mutation == "empty":
        graph["nodes"] = []
    elif mutation == "wrong_workflow":
        graph["workflow"] = "wz"
    elif mutation == "wrong_cursor":
        graph["nodes"][0]["cursor_file"] = "phase_status.json"
    elif mutation == "unknown_edge":
        graph["edges"].append({"edge_id": "edge_bad", "from": "node_missing", "to": graph["nodes"][0]["node_id"], "kind": "depends_on"})
    else:
        first, second = graph["nodes"][:2]
        graph["edges"].append({"edge_id": "edge_cycle", "from": second["node_id"], "to": first["node_id"], "kind": "depends_on"})
    assert validate_xcx_graph(graph)


def test_package_dependency_phases_are_present_in_order():
    graph = build_xcx_graph(created_at="fixed")
    phases = [node.phase for node in graph.nodes if node.phase in XCX_PHASES]
    assert phases.index("package_integrity_update_review") < phases.index("static_analysis")
    package = next(node for node in graph.nodes if node.phase == "package_integrity_update_review")
    package_barrier = next(node for node in graph.nodes if node.phase == "package_integrity_update_review.barrier")
    static = next(node for node in graph.nodes if node.phase == "static_analysis")
    assert any(edge.from_node == package_barrier.node_id and edge.to_node == static.node_id for edge in graph.edges)
    assert package.kind == "task"
    assert package_barrier.join == "barrier"
