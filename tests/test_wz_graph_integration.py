import threading
from authorized_assessment.orchestration.task_envelope import TaskBudget, build_task, ref
from authorized_assessment.orchestration.worker_context import WorkerContext
from authorized_assessment.orchestration.worker_executor import WorkerExecutor
from authorized_assessment.orchestration.worker_output_verifier import verify_worker_outputs
from authorized_assessment.orchestration.worker_registry import WorkerRegistry
from authorized_assessment.orchestration.worker_result import build_result
from authorized_assessment.orchestration.worker_manifest import build_manifest
from authorized_assessment.orchestration.wz_workers import make_handler

_SHA = "0" * 64


def task(phase="graphql_mapping"):
    return build_task(task_id=f"task_{phase}", assessment_id="assessment_wz", workflow="wz", phase=phase,
                      correlation_id=f"corr_{phase}", idempotency_key=f"idempotency-{phase}-0001",
                      target_ref=ref("artifacts/target.json", _SHA), context_ref=ref("artifacts/context.json", _SHA),
                      policy_ref=ref("artifacts/policy.json", _SHA), scope_ref=ref("artifacts/scope.json", _SHA),
                      budget=TaskBudget(max_seconds=5))


def test_offline_specialist_registry_executor_and_blocked_route():
    registry = WorkerRegistry()
    manifest = build_manifest(worker_id="worker_wz_graphql_mapping", worker_type="code", name="graphql")
    registry.register(manifest, make_handler(manifest.worker_id))
    context = WorkerContext("wz", "graphql_mapping", "phase_status.json", facts=("schema reference",))
    result = WorkerExecutor(registry).execute(task(), context, worker_id=manifest.worker_id)
    assert result["status"] == "ok"
    assert result["workflow"] == "wz"
    blocked = WorkerExecutor(registry).execute(task(), WorkerContext("wz", "graphql_mapping", "phase_status.json", blocked=True), worker_id=manifest.worker_id)
    assert blocked["error_class"] == "blocked"


def test_code_analyst_verifier_chain_and_sensitive_rejection():
    code = build_result(result_id="result_code", task_id="task_graphql_mapping", worker_id="worker_wz_graphql_mapping", worker_type="code", assessment_id="assessment_wz", correlation_id="corr_graphql_mapping", facts=[], workflow="wz", cursor_file="phase_status.json", phase="graphql_mapping", artifact_refs=[], coverage={}, not_tested=[])
    analyst = build_result(result_id="result_analyst", task_id="task_graphql_mapping", worker_id="worker_wz_api", worker_type="analyst", assessment_id="assessment_wz", correlation_id="corr_graphql_mapping", facts=[], workflow="wz", cursor_file="phase_status.json", phase="graphql_mapping", artifact_refs=[], coverage={}, not_tested=[], facts_used=[], reasoning_summary="offline", alternative_explanations=[], hypotheses=[], unknowns=[], next_hints=[])
    verifier = build_result(result_id="result_verifier", task_id="task_graphql_mapping", worker_id="worker_wz_evidence", worker_type="verifier", assessment_id="assessment_wz", correlation_id="corr_graphql_mapping", facts=[], workflow="wz", cursor_file="phase_status.json", phase="graphql_mapping", artifact_refs=[], coverage={}, not_tested=[], disposition="verified", gate={"code_result_id": "result_code", "analyst_result_id": "result_analyst", "verifier_result_id": "result_verifier", "dual_result_satisfied": True})
    assert verify_worker_outputs(code, analyst, verifier)["verified"] is True
