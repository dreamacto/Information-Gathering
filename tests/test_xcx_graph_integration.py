from __future__ import annotations

from authorized_assessment.orchestration.graph import GraphSpec
from authorized_assessment.orchestration.worker_output_verifier import verify_worker_outputs
from authorized_assessment.orchestration.worker_result import build_result
from authorized_assessment.orchestration.xcx_graph import build_xcx_graph, graph_from_dict, validate_xcx_graph


def _result(kind: str, result_id: str):
    fields = {"facts": [], "workflow": "xcx", "cursor_file": "phase_status.miniapp.json", "phase": "package_inventory", "artifact_refs": [], "coverage": {}, "not_tested": []}
    if kind == "analyst":
        fields.update({"facts_used": [], "reasoning_summary": "offline", "alternative_explanations": [], "hypotheses": [], "unknowns": [], "next_hints": []})
    gate = {"code_result_id": "result_code", "analyst_result_id": "result_analyst", "verifier_result_id": "result_verifier", "dual_result_satisfied": kind == "verifier"}
    return build_result(result_id=result_id, task_id="task_package_inventory", worker_id=f"worker_xcx_package_inventory_{kind}", worker_type=kind, assessment_id="assessment_xcx", correlation_id="corr_package_inventory", gate=gate, disposition="verified" if kind == "verifier" else None, **fields)


def test_xcx_graph_roundtrip_and_dual_result_integration():
    graph = build_xcx_graph(created_at="2026-09-01T00:00:00+00:00")
    restored = graph_from_dict(graph.to_dict())
    assert isinstance(restored, GraphSpec)
    assert restored.to_dict() == graph.to_dict()
    code = _result("code", "result_code")
    analyst = _result("analyst", "result_analyst")
    verifier = _result("verifier", "result_verifier")
    assert verify_worker_outputs(code, analyst, verifier)["verified"] is True
    assert validate_xcx_graph(restored) == []
