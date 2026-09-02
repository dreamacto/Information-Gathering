from pathlib import Path
from authorized_assessment.orchestration.graph_builder import GraphBuilder
from authorized_assessment.orchestration.supervisor import Supervisor
from authorized_assessment.orchestration.task_envelope import ArtifactRef
from authorized_assessment.orchestration.worker_context import WorkerContext


def test_supervisor_offline_lifecycle_and_cursor(tmp_path: Path):
    b=GraphBuilder("graph_sup","asmt","wz",cursor_file="phase_status.json")
    b.add_node("scope")
    graph=b.build(); ref=ArtifactRef("target.json","a"*64)
    sup=Supervisor(graph, context=WorkerContext("wz","scope","phase_status.json",coverage={"scope":1}), target_ref=ref, context_ref=ref, policy_ref=ref, scope_ref=ref, state_dir=tmp_path, dispatch=lambda node, task, ctx, attempt: {"status":"ok"})
    result=sup.run()
    assert result["lifecycle"] == "completed" and result["status_file"] == "phase_status.json"
    assert (tmp_path/"phase_status.json").exists() and (tmp_path/"events.jsonl").exists()
    assert result["network_requests"] == 0


def test_supervisor_missing_worker_is_fail_closed(tmp_path: Path):
    b=GraphBuilder("graph_sup","asmt","xcx",cursor_file="phase_status.miniapp.json"); b.add_node("scope")
    ref=ArtifactRef("target.json","a"*64)
    sup=Supervisor(b.build(), context=WorkerContext("xcx","scope","phase_status.miniapp.json"), target_ref=ref, context_ref=ref, policy_ref=ref, scope_ref=ref, state_dir=tmp_path)
    assert sup.run()["status"] == "blocked"
