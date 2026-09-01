from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def schema():
    return json.loads((ROOT / "contracts" / "graph_schema.json").read_text(encoding="utf-8"))


def validate_graph(graph: dict) -> list[str]:
    errors = []
    if not isinstance(graph, dict) or not graph.get("nodes"):
        return ["nodes must be non-empty"]
    nodes = graph["nodes"]
    ids = [node.get("node_id") for node in nodes]
    if len(ids) != len(set(ids)):
        errors.append("duplicate node_id")
    known = set(ids)
    adjacency = {node_id: [] for node_id in known}
    for edge in graph.get("edges", []):
        if edge.get("from") not in known or edge.get("to") not in known:
            errors.append("edge endpoint missing")
        elif edge["from"] == edge["to"]:
            errors.append("self cycle")
        else:
            adjacency[edge["from"]].append(edge["to"])
    state = {}
    def visit(node):
        if state.get(node) == 1:
            return True
        if state.get(node) == 2:
            return False
        state[node] = 1
        if any(visit(child) for child in adjacency.get(node, [])):
            return True
        state[node] = 2
        return False
    if any(visit(node) for node in known):
        errors.append("graph is cyclic")
    workflow = graph.get("workflow")
    expected = "phase_status.miniapp.json" if workflow == "xcx" else "phase_status.json"
    for node in nodes:
        cursor = node.get("cursor_file")
        if cursor and cursor != expected:
            errors.append("cursor/workflow mismatch")
    return errors


def valid_graph(workflow="wz"):
    cursor = "phase_status.miniapp.json" if workflow == "xcx" else "phase_status.json"
    return {"graph_id": "graph_demo", "assessment_id": "asmt_demo", "workflow": workflow,
            "nodes": [{"node_id": "node_a", "kind": "task", "phase": "scope", "order": 0, "cursor_file": cursor},
                      {"node_id": "node_b", "kind": "verifier", "phase": "scope", "order": 1, "cursor_file": cursor}],
            "edges": [{"edge_id": "edge_a_b", "from": "node_a", "to": "node_b", "kind": "depends_on"}],
            "created_at": "2026-09-01T00:00:00+00:00"}


def test_graph_schema_shape():
    data = schema()
    assert data["contract"] == "graph"
    assert {"graph_id", "assessment_id", "workflow", "nodes", "edges"} <= set(data["required"])
    assert "acyclic" in " ".join(data["invariants"])


def test_valid_graph_and_xcx_cursor_binding():
    assert validate_graph(valid_graph()) == []
    assert validate_graph(valid_graph("xcx")) == []

@pytest.mark.parametrize("mutation,expected", [
    ("duplicate", "duplicate node_id"), ("missing", "edge endpoint missing"),
    ("cycle", "graph is cyclic"), ("cross_cursor", "cursor/workflow mismatch"),
    ("self", "self cycle"),
])
def test_graph_fail_closed(mutation, expected):
    graph = valid_graph()
    if mutation == "duplicate":
        graph["nodes"][1]["node_id"] = "node_a"
    elif mutation == "missing":
        graph["edges"][0]["to"] = "node_missing"
    elif mutation == "cycle":
        graph["edges"].append({"edge_id": "edge_b_a", "from": "node_b", "to": "node_a", "kind": "depends_on"})
    elif mutation == "cross_cursor":
        graph["nodes"][0]["cursor_file"] = "phase_status.miniapp.json"
    else:
        graph["edges"][0]["to"] = "node_a"
    assert expected in validate_graph(graph)


def test_empty_graph_is_blocked():
    assert validate_graph({}) == ["nodes must be non-empty"]
