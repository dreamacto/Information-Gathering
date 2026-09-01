from authorized_assessment.orchestration.graph_builder import GraphBuilder
from authorized_assessment.orchestration.graph_routes import next_nodes, resolve_route


def _graph():
    b = GraphBuilder("graph_route", "assessment", "wz", created_at="2026-09-01T00:00:00+00:00", cursor_file="phase_status.json")
    auth = b.add_node("authorization", kind="gate")
    scope = b.add_node("scope", kind="gate")
    yes = b.add_node("yes")
    no = b.add_node("no")
    verifier = b.add_node("verifier", kind="verifier")
    b.add_edge(auth, scope)
    b.condition(scope, yes, "allowed", branch="true")
    b.condition(scope, no, "allowed", branch="false")
    b.add_edge(yes, verifier)
    b.add_edge(no, verifier)
    return b.build(), scope, yes, no


def test_condition_routes_true_and_false():
    graph, scope, yes, no = _graph()
    assert next_nodes(graph, scope, {"allowed": True}) == (yes,)
    assert next_nodes(graph, scope, {"allowed": False}) == (no,)


def test_missing_condition_and_blocked_status_fail_closed():
    graph, scope, yes, no = _graph()
    decision = resolve_route(graph, scope, {})
    assert decision.blocked and decision.node_ids == ()
    decision = resolve_route(graph, scope, {"allowed": True}, {scope: "permission_denied"})
    assert decision.blocked


def test_route_is_deterministic():
    graph, scope, *_ = _graph()
    assert resolve_route(graph, scope, {"allowed": True}) == resolve_route(graph, scope, {"allowed": True})
