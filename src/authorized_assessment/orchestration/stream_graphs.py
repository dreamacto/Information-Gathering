from __future__ import annotations

from .graph import GraphSpec
from .graph_builder import GraphBuilder


def _controls(builder: GraphBuilder) -> tuple[str, str, str, str, str]:
    authorization = builder.add_node("authorization", kind="gate")
    scope = builder.add_node("scope", kind="gate")
    preflight = builder.add_node("preflight", kind="checkpoint")
    approval = builder.add_node("approval", kind="approval")
    verifier = builder.add_node("verifier", kind="verifier")
    builder.add_edge(authorization, scope)
    builder.add_edge(scope, preflight)
    return authorization, scope, preflight, approval, verifier


def build_wz_graph(graph_id: str = "graph_wz_static", assessment_id: str = "assessment_wz", *, created_at: str | None = None) -> GraphSpec:
    builder = GraphBuilder(graph_id, assessment_id, "wz", created_at=created_at, cursor_file="phase_status.json")
    authorization, scope, preflight, approval, verifier = _controls(builder)
    passive = builder.add_node("passive_discovery", cursor_file="phase_status.json")
    active = builder.add_node("active_discovery", cursor_file="phase_status.json")
    mapping = builder.add_node("application_mapping", cursor_file="phase_status.json", join="barrier")
    builder.add_edge(preflight, passive)
    builder.add_edge(passive, active)
    builder.add_edge(active, mapping)
    branches = [builder.add_node(name, cursor_file="phase_status.json") for name in ("graphql", "websocket", "file", "auth", "webhook")]
    builder.fan_out(mapping, branches)
    reconcile = builder.add_node("application_mapping_reconciliation", cursor_file="phase_status.json", join="all")
    builder.fan_in(branches, reconcile, join="all")
    builder.add_edge(reconcile, approval)
    builder.add_edge(approval, verifier)
    return builder.build()


def build_xcx_graph(graph_id: str = "graph_xcx_static", assessment_id: str = "assessment_xcx", *, created_at: str | None = None) -> GraphSpec:
    builder = GraphBuilder(graph_id, assessment_id, "xcx", created_at=created_at, cursor_file="phase_status.miniapp.json")
    authorization, scope, preflight, approval, verifier = _controls(builder)
    phases = ["identity", "material_acquisition", "initial_decoding", "package_inventory", "unpack_decompile", "source_reconstruction"]
    chain = builder.sequence(phases)
    builder.add_edge(preflight, chain[0])
    branches = [builder.add_node(name, cursor_file="phase_status.miniapp.json") for name in ("endpoint", "auth_token", "local_data", "crypto", "webview", "cloud", "third_party")]
    builder.fan_out(chain[-1], branches)
    reconciliation = builder.add_node("static_dynamic_reconciliation", cursor_file="phase_status.miniapp.json", join="barrier")
    builder.fan_in(branches, reconciliation, join="barrier")
    builder.add_edge(reconciliation, approval)
    builder.add_edge(approval, verifier)
    return builder.build()


def build_fh_graph(graph_id: str = "graph_fh_static", assessment_id: str = "assessment_fh", *, created_at: str | None = None) -> GraphSpec:
    builder = GraphBuilder(graph_id, assessment_id, "fh", created_at=created_at)
    authorization = builder.add_node("authorization", kind="gate")
    scope = builder.add_node("scope", kind="gate")
    review = builder.add_node("review", kind="task")
    approval = builder.add_node("approval", kind="approval")
    verifier = builder.add_node("verifier", kind="verifier")
    builder.add_edge(authorization, scope)
    builder.add_edge(scope, review)
    builder.add_edge(review, approval)
    builder.add_edge(approval, verifier)
    return builder.build()


wz_graph = build_wz_graph
xcx_graph = build_xcx_graph
fh_graph = build_fh_graph

__all__ = ["build_wz_graph", "build_xcx_graph", "build_fh_graph", "wz_graph", "xcx_graph", "fh_graph"]
