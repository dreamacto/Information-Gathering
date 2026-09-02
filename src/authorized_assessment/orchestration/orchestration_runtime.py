"""Offline orchestration runtime joining graph, workers and recovery controls."""
from __future__ import annotations

import hashlib
import inspect
import json
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

from authorized_assessment.runtime.checkpoint import save_checkpoint
from authorized_assessment.runtime.event_journal import EventJournal
from authorized_assessment.runtime.lease import LocalLeaseStore

from .approval_interrupt import check_approval
from .graph import GraphSpec
from .graph_validation import validate_graph
from .kill_switch import KillSwitch
from .scheduler import NodeState, Scheduler
from .task_envelope import ArtifactRef, TaskBudget, build_task, idempotency_key
from .worker_context import WorkerContext
from .worker_executor import WorkerExecutor
from .worker_output_verifier import verify_worker_outputs

CURSOR_FILES = {"wz": "phase_status.json", "xcx": "phase_status.miniapp.json", "fh": "run_status.json"}


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _ref(value: ArtifactRef | Mapping[str, Any]) -> ArtifactRef:
    if isinstance(value, ArtifactRef):
        return value
    return ArtifactRef(str(value["path"]), str(value["sha256"]))


class OrchestrationRuntime:
    """Control-plane owner of node state, events and workflow cursor writes."""
    def __init__(self, graph: GraphSpec, *, context: WorkerContext, target_ref: ArtifactRef | Mapping[str, Any],
                 context_ref: ArtifactRef | Mapping[str, Any], policy_ref: ArtifactRef | Mapping[str, Any],
                 scope_ref: ArtifactRef | Mapping[str, Any], state_dir: str | Path,
                 dispatch: Callable[..., Mapping[str, Any]] | None = None,
                 worker_executor: WorkerExecutor | None = None, worker_ids: Mapping[str, str] | None = None,
                 policy_snapshot: Mapping[str, Any] | None = None, approvals: Mapping[str, Mapping[str, Any]] | None = None,
                 max_parallel: int = 1, kill_switch: KillSwitch | None = None,
                 lease_store: LocalLeaseStore | None = None, lease_token: str | None = None,
                 owner: str = "supervisor") -> None:
        errors = validate_graph(graph)
        if errors: raise ValueError("invalid graph: " + "; ".join(errors))
        if not isinstance(context, WorkerContext) or context.workflow != graph.workflow:
            raise ValueError("graph/context workflow mismatch")
        if context.cursor_file != CURSOR_FILES[graph.workflow]:
            raise ValueError("workflow/cursor isolation violation")
        self.graph, self.context = graph, context
        self.refs = {"target_ref": _ref(target_ref), "context_ref": _ref(context_ref), "policy_ref": _ref(policy_ref), "scope_ref": _ref(scope_ref)}
        self.state_dir = Path(state_dir); self.state_dir.mkdir(parents=True, exist_ok=True)
        self.event_journal = EventJournal(self.state_dir / "events.jsonl")
        self.checkpoint_path = self.state_dir / context.cursor_file
        self.dispatch_callback = dispatch
        self.worker_executor = worker_executor
        self.worker_ids = dict(worker_ids or {})
        self.policy_snapshot = dict(policy_snapshot or {})
        self.approvals = dict(approvals or {})
        self.kill_switch = kill_switch or KillSwitch()
        self.lease_store, self.lease_token, self.owner = lease_store, lease_token, owner
        self.max_parallel = max_parallel
        self._lock = threading.RLock(); self._sequence = self._load_sequence()
        self._checkpoint_sequence = self._load_checkpoint_sequence()
        self._last_event_id: str | None = None; self._last_result_id: str | None = None
        self._states: dict[str, NodeState] = {}
        self._operator_tasks: list[str] = []
        self._scheduler: Scheduler | None = None

    def _load_sequence(self) -> int:
        try:
            rows = self.event_journal.read()
            return max((int(row["aggregate_sequence"]) for row in rows if row.get("aggregate_id") == self.graph.assessment_id), default=-1) + 1
        except (RuntimeError, ValueError):
            raise RuntimeError("runtime event journal invalid; refusing resume")

    def _load_checkpoint_sequence(self) -> int:
        if not self.checkpoint_path.exists():
            return 0
        try:
            return int(json.loads(self.checkpoint_path.read_text(encoding="utf-8")).get("sequence", -1)) + 1
        except (OSError, ValueError, TypeError):
            raise RuntimeError("existing checkpoint invalid; refusing resume")

    def _event(self, event_type: str, summary: str, *, task_id: str = "task_runtime", result_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            event_id = f"event_{self.graph.assessment_id}_{self._sequence:06d}"
            row = {"event_id": event_id, "event_type": event_type, "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(timespec="seconds"),
                   "producer": "supervisor", "correlation_id": self.graph.assessment_id, "aggregate_id": self.graph.assessment_id,
                   "aggregate_sequence": self._sequence, "status": "accepted", "summary": str(summary)[:2000],
                   "idempotency_key": idempotency_key(event_type, task_id, result_id or "", self._sequence), "task_id": task_id}
            if result_id is not None: row["result_id"] = result_id
            saved = self.event_journal.append(row); self._sequence += 1; self._last_event_id = saved["event_id"]
            return saved

    def _checkpoint(self, status: str, *, task_id: str = "task_runtime", attempt: int = 1, cancel_requested: bool = False) -> dict[str, Any]:
        states = self._states
        data = {"checkpoint_id": f"checkpoint_{self.graph.assessment_id}_{self._sequence:06d}", "assessment_id": self.graph.assessment_id,
                "task_id": task_id, "workflow": self.graph.workflow, "phase": self.graph.nodes_by_id.get(task_id, self.graph.nodes[0]).phase if self.graph.nodes else "runtime",
                "cursor_kind": "task", "status_file": self.context.cursor_file, "sequence": self._checkpoint_sequence,
                "status": status, "completed_task_ids": sorted(k for k, v in states.items() if v.status == "success"),
                "pending_task_ids": sorted(k for k, v in states.items() if v.status == "pending"),
                "blocked_task_ids": sorted(k for k, v in states.items() if v.status == "blocked"),
                "failed_task_ids": sorted(k for k, v in states.items() if v.status in {"failed", "timeout", "timed_out", "permission_denied"}),
                "attempt": max(1, attempt), "last_event_id": self._last_event_id, "last_result_id": self._last_result_id,
                "cancel_requested": bool(cancel_requested or self.kill_switch.is_set()),
                "updated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(timespec="seconds")}
        saved = save_checkpoint(self.checkpoint_path, data)
        self._checkpoint_sequence += 1
        return saved

    def _approval(self, node: Any):
        required = node.kind == "approval" or node.phase in {"approval", "credential_testing", "sqlmap_single_candidate", "write_endpoint"}
        decision = check_approval(approval=self.approvals.get(node.node_id) or self.approvals.get(node.phase), policy_snapshot=self.policy_snapshot,
                                 required=required, assessment_id=self.graph.assessment_id, phase=node.phase,
                                 target_ref=self.refs["target_ref"].__dict__, stop_active=self.kill_switch.is_set(), scope_confirmed=bool(self.policy_snapshot.get("scope_confirmed", True)))
        if not decision.approved:
            self._operator_tasks.append(f"{decision.status}:{node.node_id}:{decision.reason}")
            self._event("approval.requested", decision.reason, task_id=f"task_{node.node_id}")
        return decision

    def _invoke(self, node: Any, attempt: int) -> Mapping[str, Any]:
        task = build_task(task_id=f"task_{node.node_id}", assessment_id=self.graph.assessment_id, workflow=self.graph.workflow,
                          phase=node.phase, action="offline", correlation_id=f"corr_{self.graph.assessment_id}",
                          idempotency_key=idempotency_key(self.graph.assessment_id, node.node_id, attempt),
                          target_ref=self.refs["target_ref"], context_ref=self.refs["context_ref"], policy_ref=self.refs["policy_ref"],
                          scope_ref=self.refs["scope_ref"], budget=TaskBudget(node.timeout_seconds or 60, 0), attempt=attempt,
                          parent_id=None, deadline=None, cancel_requested=self.kill_switch.is_set())
        if self.dispatch_callback is not None:
            try:
                return self.dispatch_callback(node, task, self.context, attempt)
            except TypeError:
                try: return self.dispatch_callback(node, task)
                except TypeError: return self.dispatch_callback(node)
        if self.worker_executor is not None:
            worker_id = self.worker_ids.get(node.node_id) or self.worker_ids.get(node.phase)
            if not worker_id: return {"error_class": "permission_denied", "status": "blocked"}
            return self.worker_executor.execute(task, self.context, worker_id=worker_id, cancel_event=self.kill_switch.child_event())
        return {"error_class": "permission_denied", "status": "blocked"}

    def _transition(self, state: NodeState) -> None:
        self._states[state.node_id] = state
        self._event("task.started" if state.status == "running" else ("task.completed" if state.status == "success" else "task.failed"),
                    f"node {state.node_id} {state.status}", task_id=f"task_{state.node_id}", result_id=(state.result or {}).get("result_id"))
        self._checkpoint("running" if state.status in {"running", "pending"} else ("complete" if state.status == "success" else state.status), task_id=f"task_{state.node_id}", attempt=max(1, state.attempt))

    def run(self) -> dict[str, Any]:
        if self.lease_store is not None:
            if not self.lease_token: raise ValueError("lease token is required")
            acquired = self.lease_store.acquire(self.graph.assessment_id, self.owner, 300, token=self.lease_token)
            if not acquired.get("ok"): return self.snapshot(status="blocked", operator_tasks=["lease_conflict"])
        try:
            self._event("assessment.created", "offline assessment runtime started")
            self._scheduler = Scheduler(self.graph, self._invoke, max_parallel=self._max_parallel(), approval=self._approval,
                                        kill_switch=self.kill_switch, on_transition=self._transition)
            result = self._scheduler.run(context={})
            self._states = result.states; self._operator_tasks.extend(result.operator_tasks)
            final = "cancelled" if result.status == "cancelled" else ("completed" if result.status == "completed" else "blocked")
            self._checkpoint("complete" if final == "completed" else final, cancel_requested=final == "cancelled")
            self._event("verifier.decided", f"runtime disposition {final}")
            return self.snapshot(status=final)
        finally:
            if self.lease_store is not None and self.lease_token:
                self.lease_store.release(self.graph.assessment_id, self.owner, token=self.lease_token)

    def _max_parallel(self) -> int:
        return getattr(self, "max_parallel", 1)

    def request_cancel(self, reason: str = "operator requested stop") -> dict[str, Any]:
        state = self.kill_switch.request(reason)
        self._event("task.cancelled", reason)
        return {"status": "cancel_requested", "reason": state.reason, "generation": state.generation}

    def snapshot(self, *, status: str | None = None, operator_tasks: list[str] | None = None) -> dict[str, Any]:
        states = self._states if self._states else (self._scheduler.states if self._scheduler else {})
        return {"assessment_id": self.graph.assessment_id, "workflow": self.graph.workflow, "status_file": self.context.cursor_file,
                "status": status or ("running" if states else "ready"), "states": {k: {"status": v.status, "attempt": v.attempt, "result_id": (v.result or {}).get("result_id")} for k, v in states.items()},
                "operator_tasks": list(dict.fromkeys(operator_tasks if operator_tasks is not None else self._operator_tasks)),
                "coverage": dict(self.context.coverage), "not_tested": list(self.context.not_tested),
                "artifact_refs": [dict(x) for x in self.context.source_refs], "network_requests": 0,
                "kill_switch": self.kill_switch.is_set(), "handoff_ready": True}

    resume = run

__all__ = ["OrchestrationRuntime"]
