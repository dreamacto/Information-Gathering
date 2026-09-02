"""Static WZ orchestration graph with application-mapping fan-out.

This module is deliberately side-effect free.  It adds WZ-specific validation
around the generic graph model without changing the shared graph contract.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .graph import GraphSpec
from .graph_builder import GraphBuilder
from .graph_validation import validate_graph

WZ_WORKFLOW = "wz"
WZ_CURSOR_FILE = "phase_status.json"
APPLICATION_MAPPING_PHASE = "application_mapping"
APPLICATION_MAPPING_RECONCILIATION = "application_mapping_reconciliation"
WZ_APPLICATION_SUBPHASES = (
    "graphql_mapping",
    "websocket_mapping",
    "file_surface_mapping",
    "auth_surface_mapping",
    "webhook_mapping",
)
WZ_SPECIALIST_PHASES = (
    "api_testing",
    "product_triage",
    "input_testing",
    "evidence_review",
)
WZ_TERMINAL_CHAIN = ("approval", "verifier")


def build_wz_specialized_graph(
    graph_id: str = "graph_wz_specialized",
    assessment_id: str = "assessment_wz",
    *,
    created_at: str | None = None,
) -> GraphSpec:
    """Build the deterministic WZ graph used by specialist workers."""
    builder = GraphBuilder(
        graph_id,
        assessment_id,
        WZ_WORKFLOW,
        created_at=created_at,
        cursor_file=WZ_CURSOR_FILE,
    )
    authorization = builder.add_node("authorization", kind="gate")
    scope = builder.add_node("scope", kind="gate")
    preflight = builder.add_node("preflight", kind="checkpoint")
    passive = builder.add_node("passive_discovery")
    active = builder.add_node("active_discovery")
    mapping = builder.add_node(APPLICATION_MAPPING_PHASE, join="barrier")
    builder.add_edge(authorization, scope)
    builder.add_edge(scope, preflight)
    builder.add_edge(preflight, passive)
    builder.add_edge(passive, active)
    builder.add_edge(active, mapping)

    branches = [builder.add_node(phase) for phase in WZ_APPLICATION_SUBPHASES]
    builder.fan_out(mapping, branches)
    reconciliation = builder.add_node(APPLICATION_MAPPING_RECONCILIATION, join="all")
    builder.fan_in(branches, reconciliation, join="all")
    approval = builder.add_node("approval", kind="approval")
    verifier = builder.add_node("verifier", kind="verifier")
    builder.add_edge(reconciliation, approval)
    builder.add_edge(approval, verifier)
    graph = builder.build()
    return graph.with_metadata(
        specialist_phases=list(WZ_SPECIALIST_PHASES),
        application_mapping_subphases=list(WZ_APPLICATION_SUBPHASES),
        cursor_file=WZ_CURSOR_FILE,
        terminal_chain=list(WZ_TERMINAL_CHAIN),
    )


# Friendly aliases used by callers and older orchestration code.
build_wz_graph = build_wz_specialized_graph
wz_graph = build_wz_specialized_graph


def validate_wz_graph(graph: GraphSpec | Mapping[str, Any]) -> list[str]:
    """Return WZ-specific violations; malformed input always fails closed."""
    errors = list(validate_graph(graph))
    data = graph.to_planning_dict() if isinstance(graph, GraphSpec) else dict(graph)
    if data.get("workflow") != WZ_WORKFLOW:
        errors.append("workflow must be 'wz'")
    nodes = data.get("nodes") if isinstance(data.get("nodes"), list) else []
    node_phases = [node.get("phase") for node in nodes if isinstance(node, Mapping)]
    for node in nodes:
        if isinstance(node, Mapping) and node.get("cursor_file") not in (None, WZ_CURSOR_FILE):
            errors.append("WZ graph may only use phase_status.json")
    missing = [phase for phase in WZ_APPLICATION_SUBPHASES if phase not in node_phases]
    if missing:
        errors.append(f"missing application mapping branches: {missing}")
    if APPLICATION_MAPPING_PHASE not in node_phases:
        errors.append("missing application_mapping phase")
    if APPLICATION_MAPPING_RECONCILIATION not in node_phases:
        errors.append("missing application_mapping_reconciliation phase")
    for forbidden in ("phase_status.miniapp.json", "run_status.json"):
        if forbidden in str(data):
            errors.append(f"forbidden cursor in WZ graph: {forbidden}")
    return list(dict.fromkeys(errors))


def assert_valid_wz_graph(graph: GraphSpec | Mapping[str, Any]) -> GraphSpec | Mapping[str, Any]:
    errors = validate_wz_graph(graph)
    if errors:
        raise ValueError("invalid WZ graph: " + "; ".join(errors))
    return graph


def graph_dict(graph: GraphSpec | Mapping[str, Any]) -> dict[str, Any]:
    """Return formal graph JSON, excluding planning-only metadata."""
    if isinstance(graph, GraphSpec):
        return graph.to_dict()
    return dict(graph)


def graph_from_dict(data: Mapping[str, Any]) -> GraphSpec:
    graph = GraphSpec.from_dict(data)
    assert_valid_wz_graph(graph)
    return graph


validate = validate_wz_graph
__all__ = [
    "WZ_WORKFLOW", "WZ_CURSOR_FILE", "WZ_APPLICATION_SUBPHASES", "WZ_SPECIALIST_PHASES",
    "build_wz_specialized_graph", "build_wz_graph", "wz_graph", "validate_wz_graph",
    "assert_valid_wz_graph", "graph_dict", "graph_from_dict",
]
