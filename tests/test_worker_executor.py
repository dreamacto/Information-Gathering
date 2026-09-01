import threading, time
from pathlib import Path
from authorized_assessment.orchestration.worker_manifest import build_manifest
from authorized_assessment.orchestration.worker_registry import WorkerRegistry
from authorized_assessment.orchestration.worker_context import WorkerContext
from authorized_assessment.orchestration.task_envelope import ArtifactRef, TaskBudget, build_task, idempotency_key
from authorized_assessment.orchestration.worker_executor import WorkerExecutor
from authorized_assessment.orchestration.worker_result import build_result

def refs():
    r=ArtifactRef("facts/index.json", "a"*64); return r,r,r,r

def task(key=None):
    a,b,c,d=refs(); return build_task(task_id="task_demo", assessment_id="asmt", workflow="wz", phase="scope", correlation_id="corr", idempotency_key=key or idempotency_key("demo"), target_ref=a, context_ref=b, policy_ref=c, scope_ref=d, budget=TaskBudget(2,1))

def ctx(): return WorkerContext("wz","scope","phase_status.json",facts=("safe",))

def test_fake_worker_result_and_replay(tmp_path: Path):
    reg=WorkerRegistry(); m=build_manifest(worker_id="worker_code", worker_type="code", name="fake")
    reg.register(m, lambda c: build_result(result_id="result_demo",task_id="task_demo",worker_id="worker_code",worker_type="code",assessment_id="asmt",correlation_id="corr",facts=["ok"]))
    ex=WorkerExecutor(reg,idempotency_path=tmp_path/"idem.json"); first=ex.execute(task(),ctx(),worker_id="worker_code"); assert first["result_id"]=="result_demo"
    second=ex.execute(task(),ctx(),worker_id="worker_code"); assert second["status"]=="replayed"

def test_blocked_cancelled_and_timeout(tmp_path):
    reg=WorkerRegistry(); reg.register(build_manifest(worker_id="worker_code",worker_type="code",name="fake",timeout_seconds=1), lambda c: time.sleep(2))
    ex=WorkerExecutor(reg)
    assert ex.execute(task(),WorkerContext("wz","scope","phase_status.json",blocked=True),worker_id="worker_code")["error_class"]=="blocked"
    e=threading.Event(); e.set(); assert ex.execute(task("b"*64),ctx(),worker_id="worker_code",cancel_event=e)["error_class"]=="cancelled"
    assert ex.execute(task("c"*64),ctx(),worker_id="worker_code")["error_class"]=="timeout"

def test_unregistered_is_denied():
    assert WorkerExecutor(WorkerRegistry()).execute(task(),ctx(),worker_id="worker_missing")["error_class"]=="permission_denied"
