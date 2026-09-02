"""Deterministic, offline orchestration graph for the mini-program (XCX) stream.

The graph is a plan only: constructing it performs no network or filesystem I/O.
Worker implementations are deliberately represented as metadata so this module
remains independent from worker registration and execution.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .graph import GraphSpec
from .graph_builder import GraphBuilder
from .graph_validation import validate_graph

XCX_WORKFLOW = "xcx"
XCX_CURSOR_FILE = "phase_status.miniapp.json"
WORKFLOW = XCX_WORKFLOW
CURSOR_FILE = XCX_CURSOR_FILE

XCX_PHASES = (
    "authorization", "identity", "platform_identification", "material_acquisition",
    "initial_decoding", "preflight", "package_inventory", "package_unpack_decompile",
    "source_reconstruction", "package_integrity_update_review", "static_analysis",
    "endpoint_inventory", "host_classification", "dynamic_setup", "dynamic_mapping",
    "static_dynamic_reconciliation", "platform_login_exchange", "session_token_lifecycle",
    "signature_replay", "backend_web_api_testing", "access_control_testing",
    "input_file_testing", "business_logic_testing", "local_data_exposure",
    "crypto_and_secret_handling", "webview_bridge_links", "cloud_function_testing",
    "cloud_storage_acl_testing", "third_party_platform_boundary", "candidate_validation",
    "evidence", "cleanup", "retest", "reporting",
)
PHASES = XCX_PHASES

XCX_BRANCHES: dict[str, tuple[str, ...]] = {
    "platform_login_exchange": ("login_code_one_time", "login_code_expiry", "appid_binding", "session_key_custody", "openid_authorization_basis"),
    "session_token_lifecycle": ("token_rotation", "token_revocation_logout", "multi_device_login", "stale_token_new_api", "device_user_tenant_binding"),
    "signature_replay": ("nonce_timestamp", "signature_canonicalization", "replay_window", "binding_scope"),
    "package_integrity_update_review": ("package_version_inventory", "manifest_resource_diff", "update_endpoint_environment", "debug_switches", "source_map_exposure", "version_drift", "trusted_update_config"),
    "static_dynamic_reconciliation": ("static_endpoint_base", "dynamic_endpoint_base", "match_status_classification", "hidden_flow_identification", "stale_entry_disposition"),
    "local_data_exposure": ("token_persistence", "logout_cleanup", "local_cache_database", "logs_clipboard_screenshots", "temp_files"),
    "crypto_and_secret_handling": ("hardcoded_secrets", "custom_crypto", "weak_random_key_derivation", "debug_config_env_keys"),
    "webview_bridge_links": ("webview_allowed_domains", "postmessage_origin", "bridge_method_exposure", "custom_scheme", "deep_link_sensitive_params", "external_app_browser_jump", "cookie_token_sharing_boundary"),
    "cloud_function_testing": ("anonymous_invocation", "function_parameter_role_validation", "cloud_env_id_mixing"),
    "cloud_storage_acl_testing": ("cloud_database_rules", "object_storage_acl", "signed_url_binding"),
    "third_party_platform_boundary": ("third_party_service_boundary", "platform_shared_asset_attribution"),
}
PHASE_BRANCHES = XCX_BRANCHES

# Stable binding contract. Consumers may replace these IDs in their registry;
# the graph itself never imports or invokes workers.
XCX_PHASE_WORKERS = {
    phase: (f"worker_xcx_{phase}_code", f"worker_xcx_{phase}_analyst", f"worker_xcx_{phase}_verifier")
    for phase in XCX_PHASES
}
XCX_ROLE_WORKERS = XCX_PHASE_WORKERS


def _branch_node_id(phase: str, branch: str) -> str:
    return f"node_{phase}__branch_{branch}"


def build_xcx_graph(
    graph_id: str = "graph_xcx_static",
    assessment_id: str = "assessment_xcx",
    *,
    created_at: str | None = None,
) -> GraphSpec:
    """Build the complete XCX graph deterministically and without side effects."""
    builder = GraphBuilder(graph_id, assessment_id, XCX_WORKFLOW, created_at=created_at, cursor_file=XCX_CURSOR_FILE)
    authorization = builder.add_node("authorization", kind="gate", order=0)
    scope = builder.add_node("scope", kind="gate", order=1)
    builder.add_edge(authorization, scope)
    previous: str | None = scope
    phase_nodes: dict[str, str] = {}
    branch_joins: dict[str, str] = {}
    for order, phase in enumerate(XCX_PHASES):
        if phase in {"authorization", "scope"}:
            phase_nodes[phase] = authorization if phase == "authorization" else scope
            continue
        kind = "checkpoint" if phase == "preflight" else "task"
        node = builder.add_node(phase, kind=kind, order=order + 2)
        phase_nodes[phase] = node
        if previous is not None:
            builder.add_edge(previous, node)
        previous = node
        branches = XCX_BRANCHES.get(phase, ())
        if branches:
            branch_nodes = [builder.add_node(f"{phase}.{branch}", node_id=_branch_node_id(phase, branch), kind="worker", order=order * 100 + index + 1) for index, branch in enumerate(branches)]
            builder.fan_out(node, branch_nodes, kind="produces")
            join = builder.add_node(f"{phase}.barrier", node_id=f"node_{phase}__barrier", kind="checkpoint", join="barrier", order=order * 100 + len(branches) + 1)
            builder.fan_in(branch_nodes, join, join="barrier")
            branch_joins[phase] = join
            previous = join
    approval = builder.add_node("approval", kind="approval", order=10000)
    verifier = builder.add_node("verifier", kind="verifier", order=10001, terminal=True)
    builder.add_edge(previous, approval)
    builder.add_edge(approval, verifier)
    return builder.build().with_metadata(
        workflow=XCX_WORKFLOW,
        cursor_file=XCX_CURSOR_FILE,
        phases=list(XCX_PHASES),
        branches={phase: list(branches) for phase, branches in XCX_BRANCHES.items()},
        phase_nodes=phase_nodes,
        branch_barriers=branch_joins,
        phase_roles={phase: {"code": workers[0], "analyst": workers[1], "verifier": workers[2]} for phase, workers in XCX_PHASE_WORKERS.items()},
        role_order=["code", "analyst", "verifier"],
    )


xcx_graph = build_xcx_graph


def validate_xcx_graph(graph: GraphSpec | Mapping[str, Any]) -> list[str]:
    """Return XCX-specific violations; malformed or cross-stream graphs fail closed."""
    try:
        errors = list(validate_graph(graph))
        data = graph.to_planning_dict() if isinstance(graph, GraphSpec) else dict(graph)
    except Exception as exc:
        return [f"invalid graph input: {exc}"]
    if data.get("workflow") != XCX_WORKFLOW:
        errors.append("workflow must be 'xcx'")
    nodes = data.get("nodes", [])
    if not isinstance(nodes, list):
        return list(dict.fromkeys(errors + ["nodes must be a list"]))
    phases = {node.get("phase") for node in nodes if isinstance(node, Mapping)}
    for node in nodes:
        if isinstance(node, Mapping) and node.get("cursor_file") not in (None, XCX_CURSOR_FILE):
            errors.append("XCX graph may only use phase_status.miniapp.json")
    missing = [phase for phase in XCX_PHASES if phase not in phases]
    if missing:
        errors.append(f"missing XCX phases: {missing}")
    if "phase_status.json" in str(data) or "run_status.json" in str(data):
        errors.append("forbidden non-XCX cursor in graph")
    return list(dict.fromkeys(errors))


def assert_valid_xcx_graph(graph: GraphSpec | Mapping[str, Any]) -> GraphSpec | Mapping[str, Any]:
    errors = validate_xcx_graph(graph)
    if errors:
        raise ValueError("invalid XCX graph: " + "; ".join(errors))
    return graph


def graph_dict(graph: GraphSpec | Mapping[str, Any]) -> dict[str, Any]:
    return graph.to_dict() if isinstance(graph, GraphSpec) else dict(graph)


def graph_from_dict(data: Mapping[str, Any]) -> GraphSpec:
    graph = GraphSpec.from_dict(data)
    assert_valid_xcx_graph(graph)
    return graph

validate = validate_xcx_graph

__all__ = ["XCX_WORKFLOW", "XCX_CURSOR_FILE", "WORKFLOW", "CURSOR_FILE", "XCX_PHASES", "PHASES", "XCX_BRANCHES", "PHASE_BRANCHES", "XCX_PHASE_WORKERS", "XCX_ROLE_WORKERS", "build_xcx_graph", "xcx_graph", "validate_xcx_graph", "assert_valid_xcx_graph", "graph_dict", "graph_from_dict"]
