from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .graph import CURSORS, EDGE_KINDS, GRAPH_VERSION, JOINS, NODE_KINDS, WORKFLOWS, GraphSpec

_ID_RE = re.compile(r"^node_[A-Za-z0-9._-]+$")
_EDGE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _as_dict(graph: GraphSpec | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(graph, GraphSpec):
        data = graph.to_dict()
        data["graph_version"] = graph.graph_version
        return data
    return dict(graph)


def validate_graph(graph: GraphSpec | Mapping[str, Any]) -> list[str]:
    data = _as_dict(graph)
    errors: list[str] = []
    required = ("graph_id", "assessment_id", "workflow", "nodes", "edges", "created_at")
    for field in required:
        if field not in data:
            errors.append(f"missing required field: {field}")
    nodes = data.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return ["nodes must be non-empty"]
    if not isinstance(data.get("workflow"), str) or data.get("workflow") not in WORKFLOWS:
        errors.append("invalid workflow")
    if not isinstance(data.get("graph_id"), str) or not data.get("graph_id", "").startswith("graph_"):
        errors.append("invalid graph_id")
    ids = [node.get("node_id") if isinstance(node, Mapping) else None for node in nodes]
    if len(ids) != len(set(ids)):
        errors.append("duplicate node_id")
    known = {item for item in ids if item is not None}
    expected_cursor = "phase_status.miniapp.json" if data.get("workflow") == "xcx" else "phase_status.json"
    control_kinds = {"scope", "approval", "verifier"}
    seen_controls: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, Mapping):
            errors.append(f"nodes[{index}] must be an object")
            continue
        for field in ("node_id", "kind", "phase", "order"):
            if field not in node:
                errors.append(f"nodes[{index}] missing field: {field}")
        kind = node.get("kind")
        node_id = node.get("node_id")
        if not isinstance(node_id, str) or not _ID_RE.fullmatch(node_id):
            errors.append(f"nodes[{index}].node_id invalid")
        if not isinstance(node.get("phase"), str) or not node.get("phase"):
            errors.append(f"nodes[{index}].phase invalid")
        if kind not in NODE_KINDS:
            errors.append(f"nodes[{index}].kind invalid")
        phase = node.get("phase")
        if phase in control_kinds:
            seen_controls.add(str(phase))
        if not isinstance(node.get("order"), int) or isinstance(node.get("order"), bool) or node.get("order", -1) < 0:
            errors.append(f"nodes[{index}].order invalid")
        if node.get("join") is not None and node.get("join") not in JOINS:
            errors.append(f"nodes[{index}].join invalid")
        if node.get("cursor_file") not in (None, *CURSORS):
            errors.append(f"nodes[{index}].cursor_file invalid")
        if node.get("cursor_file") and node.get("cursor_file") != expected_cursor:
            errors.append("cursor/workflow mismatch")
        if node.get("timeout_seconds") is not None and (not isinstance(node["timeout_seconds"], int) or node["timeout_seconds"] < 1):
            errors.append(f"nodes[{index}].timeout_seconds invalid")
        if node.get("retry_limit") is not None and (not isinstance(node["retry_limit"], int) or node["retry_limit"] < 0):
            errors.append(f"nodes[{index}].retry_limit invalid")
        if node.get("cancellable") is not None and not isinstance(node["cancellable"], bool):
            errors.append(f"nodes[{index}].cancellable invalid")
    edges = data.get("edges", [])
    if not isinstance(edges, list):
        errors.append("edges must be a list")
        edges = []
    adjacency = {node_id: [] for node_id in known}
    edge_keys: set[tuple[str, str, str]] = set()
    for index, edge in enumerate(edges):
        if not isinstance(edge, Mapping):
            errors.append(f"edges[{index}] must be an object")
            continue
        source, target = edge.get("from"), edge.get("to")
        if not isinstance(edge.get("edge_id"), str) or not _EDGE_ID_RE.fullmatch(edge.get("edge_id", "")):
            errors.append(f"edges[{index}].edge_id invalid")
        if not isinstance(source, str) or not isinstance(target, str):
            errors.append(f"edges[{index}] endpoints invalid")
        if source not in known or target not in known:
            errors.append("edge endpoint missing")
            continue
        if source == target:
            errors.append("self cycle")
        key = (str(source), str(target), str(edge.get("kind")))
        if key in edge_keys:
            errors.append("duplicate edge")
        edge_keys.add(key)
        if edge.get("kind") not in EDGE_KINDS:
            errors.append(f"edges[{index}].kind invalid")
        adjacency[source].append(target)
    state: dict[str, int] = {}
    def visit(node: str) -> bool:
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
    version = data.get("graph_version", GRAPH_VERSION)
    if version != GRAPH_VERSION:
        errors.append("unsupported graph version")
    return errors


def assert_valid_graph(graph: GraphSpec | Mapping[str, Any]) -> GraphSpec | Mapping[str, Any]:
    errors = validate_graph(graph)
    if errors:
        raise ValueError("invalid graph: " + "; ".join(errors))
    return graph


validate_or_raise = assert_valid_graph
