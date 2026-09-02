import pytest
from authorized_assessment.orchestration.wz_graph import build_wz_specialized_graph, validate_wz_graph
from authorized_assessment.orchestration.wz_routes import resolve_wz_route, validate_artifact_ref
from authorized_assessment.orchestration.worker_context import WorkerContext


def test_wz_routes_reject_fh_xcx_and_gated_states():
    assert resolve_wz_route("graphql_mapping").ready
    assert resolve_wz_route("graphql_mapping", workflow="fh").blocked
    assert resolve_wz_route("graphql_mapping", cursor_file="run_status.json").blocked
    assert resolve_wz_route("graphql_mapping", status="approval_required").blocked
    assert resolve_wz_route("unknown").blocked


def test_wz_graph_contains_no_other_workflow_cursor():
    graph = build_wz_specialized_graph(created_at="fixed")
    assert validate_wz_graph(graph) == []
    assert "run_status.json" not in str(graph.to_planning_dict())
    assert "phase_status.miniapp.json" not in str(graph.to_planning_dict())


def test_context_and_artifacts_cannot_cross_workflow_or_engagement():
    # Shared context supports FH for compatibility; WZ dispatch is what rejects it.
    assert WorkerContext("fh", "review", "run_status.json").workflow == "fh"
    assert resolve_wz_route("review", workflow="fh").blocked
    assert validate_artifact_ref("artifacts/application-map/webhook-inventory.csv", engagement_id="other")
    assert validate_artifact_ref("artifacts/application-map/webhook-inventory.csv") == []
