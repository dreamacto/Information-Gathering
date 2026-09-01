from authorized_assessment.orchestration.graph import EdgeSpec, GraphSpec, NodeSpec
from authorized_assessment.orchestration.graph_builder import GraphBuilder
from authorized_assessment.orchestration.graph_validation import validate_graph
from authorized_assessment.orchestration.stream_graphs import build_wz_graph, build_xcx_graph


def test_model_roundtrip_and_topological_order():
    graph = GraphSpec("graph_demo", "assessment_demo", "wz", [NodeSpec("node_a", "gate", "authorization", 0), NodeSpec("node_scope", "gate", "scope", 1), NodeSpec("node_approval", "approval", "approval", 2), NodeSpec("node_b", "verifier", "verifier", 3)], [EdgeSpec("edge_a_scope", "node_a", "node_scope"), EdgeSpec("edge_scope_approval", "node_scope", "node_approval"), EdgeSpec("edge_approval_b", "node_approval", "node_b")], "2026-09-01T00:00:00+00:00")
    assert validate_graph(graph) == []
    assert GraphSpec.from_dict(graph.to_dict()).to_dict() == graph.to_dict()
    assert graph.topological_order() == ("node_a", "node_scope", "node_approval", "node_b")


def test_builder_sequence_condition_fanout_and_loop_metadata():
    builder = GraphBuilder("graph_demo", "assessment_demo", "wz", created_at="2026-09-01T00:00:00+00:00", cursor_file="phase_status.json")
    auth = builder.add_node("authorization", kind="gate")
    scope = builder.add_node("scope", kind="gate")
    verifier = builder.add_node("verifier", kind="verifier")
    builder.add_edge(auth, scope)
    builder.condition(scope, verifier, "allowed", branch="true")
    loop = builder.loop("review", max_iterations=2, termination="done")
    assert builder._metadata["loops"][loop]["max_iterations"] == 2
    assert builder._metadata["loops"][loop]["termination"] == "done"
    graph = builder.build()
    assert validate_graph(graph) == []
    assert graph.to_dict()["nodes"][0]["node_id"] == "node_authorization_000"


def test_stream_factories_are_valid_and_cursor_isolated():
    wz = build_wz_graph(created_at="2026-09-01T00:00:00+00:00")
    xcx = build_xcx_graph(created_at="2026-09-01T00:00:00+00:00")
    assert validate_graph(wz) == []
    assert validate_graph(xcx) == []
    assert {node.cursor_file for node in wz.nodes} == {"phase_status.json"}
    assert {node.cursor_file for node in xcx.nodes} == {"phase_status.miniapp.json"}
    mapping = next(node for node in wz.nodes if node.phase == "application_mapping")
    branches = {node.node_id for node in wz.nodes if node.phase in {"graphql", "websocket", "file", "auth", "webhook"}}
    assert {node.node_id for node in wz.successors(mapping.node_id)} == branches
    reconciliation = next(node for node in wz.nodes if node.phase == "application_mapping_reconciliation")
    assert reconciliation.join == "all"
    assert {node.node_id for node in wz.predecessors(reconciliation.node_id)} == branches
    assert "approval" in {node.phase for node in wz.nodes}
    assert "approval" in {node.phase for node in build_xcx_graph().nodes}


def test_invalid_graph_fails_closed():
    graph = {"graph_id": "graph_bad", "assessment_id": "a", "workflow": "wz", "nodes": [{"node_id": "node_a", "kind": "task", "phase": "x", "order": 0, "cursor_file": "phase_status.miniapp.json"}], "edges": [], "created_at": "2026-09-01T00:00:00+00:00"}
    errors = validate_graph(graph)
    assert "cursor/workflow mismatch" in errors


def test_minimal_graph_without_controls_remains_contract_compatible():
    graph = {"graph_id": "graph_bad", "assessment_id": "a", "workflow": "wz", "nodes": [{"node_id": "node_a", "kind": "task", "phase": "task", "order": 0}], "edges": [], "created_at": "2026-09-01T00:00:00+00:00"}
    assert validate_graph(graph) == []


def test_future_graph_version_is_rejected_without_contract_projection():
    graph = GraphSpec("graph_versioned", "assessment", "wz", [NodeSpec("node_a", "gate", "authorization", 0)], [], "2026-09-01T00:00:00+00:00", graph_version="9.0")
    assert "unsupported graph version" in validate_graph(graph)
