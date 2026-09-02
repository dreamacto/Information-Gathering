from authorized_assessment.orchestration.wz_graph import *


def test_specialized_graph_has_five_way_mapping_and_serial_tail():
    graph = build_wz_specialized_graph(created_at="2026-09-02T00:00:00+00:00")
    assert validate_wz_graph(graph) == []
    phases = [node.phase for node in graph.nodes]
    assert [p for p in WZ_APPLICATION_SUBPHASES if p in phases] == list(WZ_APPLICATION_SUBPHASES)
    assert phases[-2:] == ["approval", "verifier"]
    mapping = next(node for node in graph.nodes if node.phase == "application_mapping")
    reconcile = next(node for node in graph.nodes if node.phase == "application_mapping_reconciliation")
    assert mapping.join == "barrier"
    assert reconcile.join == "all"
    assert all(node.cursor_file == "phase_status.json" for node in graph.nodes)


def test_graph_roundtrip_is_deterministic_and_formal_dict_has_no_planning_fields():
    left = build_wz_specialized_graph(created_at="fixed")
    right = build_wz_specialized_graph(created_at="fixed")
    assert left.to_dict() == right.to_dict()
    assert "stream" not in str(left.to_dict())
    assert graph_from_dict(graph_dict(left)).to_dict() == left.to_dict()


def test_invalid_workflow_cursor_and_missing_branch_fail_closed():
    graph = build_wz_specialized_graph(created_at="fixed").to_planning_dict()
    graph["workflow"] = "fh"
    assert validate_wz_graph(graph)
    graph = build_wz_specialized_graph(created_at="fixed").to_planning_dict()
    graph["nodes"] = [n for n in graph["nodes"] if n["phase"] != "webhook_mapping"]
    assert any("missing application mapping" in item for item in validate_wz_graph(graph))
