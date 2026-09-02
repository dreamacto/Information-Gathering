from authorized_assessment.orchestration.phase_verifier import validate_phase_state
from authorized_assessment.orchestration.wz_graph import build_wz_specialized_graph


def state(phase="graphql_mapping", **extra):
    value = {"workflow": "wz", "assessment_id": "assessment_wz", "phase": phase, "status_file": "phase_status.json", "status": "complete", "completed_task_ids": []}
    value.update(extra)
    return value


def test_phase_boundary_requires_current_node_and_prerequisites():
    graph = build_wz_specialized_graph(created_at="fixed")
    errors = validate_phase_state(graph, state())
    assert "phase node not complete" in " ".join(errors)
    errors = validate_phase_state(graph, state(status_file="phase_status.miniapp.json"))
    assert "isolation" in " ".join(errors)


def test_phase_boundary_accepts_completed_mapping_branch_only_when_prerequisites_complete():
    graph = build_wz_specialized_graph(created_at="fixed")
    node = next(n.node_id for n in graph.nodes if n.phase == "graphql_mapping")
    predecessors = [n.node_id for n in graph.predecessors(node)]
    errors = validate_phase_state(graph, state(completed_task_ids=[node] + predecessors))
    assert errors == []
