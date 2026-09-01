"""Offline fake-worker executor with idempotency, timeout and safe failures."""
from __future__ import annotations
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, Mapping

from authorized_assessment.runtime.idempotency import IdempotencyStore
from .worker_context import WorkerContext
from .worker_errors import from_exception, make_error
from .worker_registry import WorkerRegistry
from .worker_result import validate_result
from .task_envelope import TaskEnvelope, validate_envelope

class WorkerExecutor:
    def __init__(self, registry: WorkerRegistry, *, idempotency_path: Path | None = None):
        self.registry=registry
        self.idempotency=IdempotencyStore(idempotency_path) if idempotency_path else None

    def execute(self, task: TaskEnvelope | Mapping[str, Any], context: WorkerContext, *, worker_id: str, cancel_event: threading.Event | None = None) -> dict[str, Any]:
        envelope = task.as_dict() if isinstance(task, TaskEnvelope) else dict(task)
        errors=validate_envelope(envelope)
        if errors: return self._error(envelope, worker_id, "validation", "task envelope rejected", "; ".join(errors))
        if context.blocked: return self._error(envelope, worker_id, "blocked", "worker context is blocked")
        if envelope.get("cancel_requested") or (cancel_event and cancel_event.is_set()): return self._error(envelope, worker_id, "cancelled", "task cancellation requested")
        item=self.registry.get(worker_id)
        if item is None: return self._error(envelope, worker_id, "permission_denied", "worker is not registered")
        manifest, handler=item
        if not manifest.permissions.read_only or manifest.permissions.network not in {"none", "metadata_only"} or any(getattr(manifest.permissions, x) for x in ("write_scope","write_approval","write_cursor","write_confirmed")):
            return self._error(envelope, worker_id, "permission_denied", "worker permissions are not execution-safe")
        key=envelope["idempotency_key"]
        request={"task_id":envelope["task_id"],"worker_id":worker_id,"action":envelope["action"],"context_ref":envelope["context_ref"]}
        if self.idempotency:
            prior=self.idempotency.inspect(key)
            if prior:
                recorded=self.idempotency.record(key, request)
                if recorded.get("status") == "conflict": return self._error(envelope, worker_id, "validation", "idempotency conflict")
                return {"status":"replayed","result_id":prior.get("result_id"),"task_id":envelope["task_id"],"worker_id":worker_id}
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(handler, context)
                result=future.result(timeout=min(manifest.limits.timeout_seconds, envelope["budget"]["max_seconds"]))
        except FutureTimeout:
            return self._error(envelope, worker_id, "timeout", "worker execution timed out")
        except Exception as exc:
            return from_exception(error_id="error_"+envelope["task_id"], task_id=envelope["task_id"], worker_id=worker_id, exc=exc).as_dict()
        if not isinstance(result, Mapping): return self._error(envelope, worker_id, "validation", "worker returned non-object result")
        result=dict(result)
        result_errors=validate_result(result)
        if result_errors: return self._error(envelope, worker_id, "validation", "worker result rejected", "; ".join(result_errors))
        if self.idempotency: self.idempotency.record(key, request, result_id=result.get("result_id"), status="accepted", summary="worker result accepted")
        return result

    @staticmethod
    def _error(envelope, worker_id, error_class, reason, detail=None):
        return make_error(error_id="error_"+str(envelope.get("task_id","unknown")), error_class=error_class, safe_reason=reason, task_id=str(envelope.get("task_id","unknown")), worker_id=worker_id, redacted_detail=detail).as_dict()

execute = WorkerExecutor.execute
