from __future__ import annotations

from authorized_assessment.orchestration.xcx_graph import XCX_BRANCHES, build_xcx_graph


def test_package_integrity_update_is_a_dependency_barrier_before_static_analysis():
    graph = build_xcx_graph(created_at="fixed")
    package = next(node for node in graph.nodes if node.phase == "package_integrity_update_review")
    branches = [node for node in graph.nodes if node.phase.startswith("package_integrity_update_review.") and node.kind == "worker"]
    barrier = next(node for node in graph.nodes if node.phase == "package_integrity_update_review.barrier")
    static = next(node for node in graph.nodes if node.phase == "static_analysis")
    assert len(branches) == len(XCX_BRANCHES["package_integrity_update_review"])
    assert {edge.to_node for edge in graph.edges if edge.from_node == package.node_id} == {node.node_id for node in branches}
    assert {edge.from_node for edge in graph.edges if edge.to_node == barrier.node_id} == {node.node_id for node in branches}
    assert any(edge.from_node == barrier.node_id and edge.to_node == static.node_id for edge in graph.edges)
    assert barrier.join == "barrier"


def test_each_dependency_phase_has_explicit_barrier_and_no_direct_skip():
    graph = build_xcx_graph(created_at="fixed")
    for phase, branches in XCX_BRANCHES.items():
        phase_node = next(node for node in graph.nodes if node.phase == phase)
        barrier = next(node for node in graph.nodes if node.phase == f"{phase}.barrier")
        branch_nodes = {node.node_id for node in graph.nodes if node.phase.startswith(f"{phase}.") and node.kind == "worker"}
        assert len(branch_nodes) == len(branches)
        assert barrier.join == "barrier"
        assert {edge.to_node for edge in graph.edges if edge.from_node == phase_node.node_id} == branch_nodes
        assert {edge.from_node for edge in graph.edges if edge.to_node == barrier.node_id} == branch_nodes
