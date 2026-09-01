from authorized_assessment.orchestration.graph import GraphSpec, NodeSpec, EdgeSpec
from authorized_assessment.orchestration.phase_verifier import validate_phase_state, verify_phase


def graph(workflow="wz"):
    cursor = "phase_status.miniapp.json" if workflow == "xcx" else "phase_status.json"
    return GraphSpec("graph_demo", "asmt_demo", workflow, [
        NodeSpec("node_scope", "task", "scope", 0, cursor_file=cursor),
        NodeSpec("node_verify", "verifier", "verify", 1, cursor_file=cursor),
    ], [EdgeSpec("edge_scope_verify", "node_scope", "node_verify")])


def state(workflow="wz", **extra):
    value = {"workflow": workflow, "assessment_id": "asmt_demo", "phase": "scope", "status": "complete",
             "status_file": "phase_status.miniapp.json" if workflow == "xcx" else "phase_status.json",
             "completed_task_ids": ["node_scope"]}
    value.update(extra)
    return value


def test_valid_wz_phase_state_and_decision():
    assert validate_phase_state(graph(), state()) == []
    assert verify_phase(graph(), state())["status"] == "verified"


def test_xcx_cannot_use_wz_cursor():
    errors = validate_phase_state(graph("xcx"), state("xcx", status_file="phase_status.json"))
    assert "workflow/status_file isolation violation" in errors


def test_phase_requires_graph_node_and_prerequisite():
    errors = validate_phase_state(graph(), state(phase="verify", completed_task_ids=[]))
    assert "phase node not complete: node_verify" in errors
    assert "prerequisite not complete: node_scope" in errors


def test_missing_reference_blocks_when_reference_map_supplied():
    errors = validate_phase_state(graph(), state(result_refs=["result_missing"]), references={})
    assert "missing referenced result: result_missing" in errors


def test_malformed_input_fails_closed():
    assert validate_phase_state({}, state())
    assert "phase_status must be an object" in validate_phase_state(graph(), None)
