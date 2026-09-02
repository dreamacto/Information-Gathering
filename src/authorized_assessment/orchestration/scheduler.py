"""Deterministic local DAG scheduler for safe worker callbacks."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .graph import GraphSpec
from .graph_barriers import evaluate_barrier
from .graph_validation import validate_graph
from .retry_policy import decide_retry

SUCCESS = frozenset({"success", "succeeded", "ok", "completed", "ready"})
TERMINAL = frozenset({"success", "succeeded", "ok", "completed", "ready", "failed", "blocked", "cancelled", "timeout", "timed_out", "permission_denied"})

@dataclass
class NodeState:
    node_id: str
    status: str = "pending"
    attempt: int = 0
    result: Mapping[str, Any] | None = None
    error: Mapping[str, Any] | None = None

@dataclass
class ScheduleResult:
    status: str
    states: dict[str, NodeState]
    operator_tasks: list[str] = field(default_factory=list)

class Scheduler:
    def __init__(self, graph: GraphSpec, dispatch: Callable[..., Mapping[str, Any]], *, max_parallel: int = 1,
                 approval: Callable[[Any], Any] | None = None, kill_switch: Any = None,
                 on_transition: Callable[[NodeState], None] | None = None) -> None:
        if isinstance(max_parallel, bool) or not isinstance(max_parallel, int) or max_parallel < 1:
            raise ValueError("max_parallel must be >= 1")
        errors = validate_graph(graph)
        if errors: raise ValueError("invalid graph: " + "; ".join(errors))
        self.graph, self.dispatch, self.max_parallel = graph, dispatch, max_parallel
        self.approval, self.kill_switch = approval, kill_switch
        self.on_transition = on_transition
        self.states = {node.node_id: NodeState(node.node_id) for node in graph.nodes}
        self.operator_tasks: list[str] = []

    def _emit(self, state: NodeState) -> None:
        if self.on_transition is not None:
            self.on_transition(state)

    def _status(self, node_id: str) -> str:
        return self.states[node_id].status

    def _ready(self, node_id: str, context: Mapping[str, Any]) -> bool:
        node = self.graph.nodes_by_id[node_id]
        if self._status(node_id) != "pending": return False
        incoming = [edge for edge in self.graph.edges if edge.to_node == node_id]
        if not incoming: return True
        deps = [edge.from_node for edge in incoming if edge.kind != "gates"]
        if deps:
            if node.join:
                decision = evaluate_barrier(node.join, deps, {x: self._status(x) for x in deps})
                if not decision.ready: return False
            elif any(self._status(dep) not in SUCCESS for dep in deps):
                return False
        for edge in incoming:
            if edge.kind == "gates":
                value = context.get(edge.condition) if edge.condition else None
                branch = edge.branch or "true"
                if branch == "true":
                    matched = bool(value)
                elif branch == "false":
                    matched = not bool(value)
                else:
                    matched = value == branch
                if not matched: return False
        return True

    @staticmethod
    def _result_status(result: Mapping[str, Any]) -> str:
        if result.get("error_class"):
            return str(result.get("error_class"))
        return str(result.get("status", "failed")).lower()

    def run(self, *, context: Mapping[str, Any] | None = None) -> ScheduleResult:
        context = dict(context or {})
        running: dict[Any, str] = {}
        with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
            while True:
                if self.kill_switch is not None and self.kill_switch.is_set():
                    for node_id, state in self.states.items():
                        if state.status == "pending":
                            state.status = "cancelled"
                            self._emit(state)
                    self.operator_tasks.append("kill_switch: " + str(self.kill_switch.reason))
                candidates = [n.node_id for n in sorted(self.graph.nodes, key=lambda n: (n.order, n.node_id)) if self._ready(n.node_id, context)]
                while candidates and len(running) < self.max_parallel and not (self.kill_switch and self.kill_switch.is_set()):
                    node_id = candidates.pop(0); state = self.states[node_id]; state.attempt += 1; state.status = "running"; self._emit(state)
                    node = self.graph.nodes_by_id[node_id]
                    if self.approval is not None and node.kind == "approval":
                        decision = self.approval(node)
                        if not getattr(decision, "approved", decision is True):
                            state.status = "blocked"; self.operator_tasks.append("approval_required:" + node_id); self._emit(state); continue
                    try: future = pool.submit(self.dispatch, node, state.attempt)
                    except Exception as exc:
                        state.status, state.error = "failed", {"error_class": "internal", "detail": type(exc).__name__}; self._emit(state); continue
                    running[future] = node_id
                if not running:
                    pending = [s for s in self.states.values() if s.status == "pending"]
                    if pending:
                        for state in pending: state.status = "blocked"
                        self.operator_tasks.extend("dependency_blocked:" + s.node_id for s in pending)
                    break
                done, _ = wait(tuple(running), return_when=FIRST_COMPLETED)
                for future in done:
                    node_id = running.pop(future); state = self.states[node_id]
                    try: result = future.result(); result = dict(result or {})
                    except Exception as exc: result = {"error_class": "internal", "detail": type(exc).__name__}
                    state.result = result; status = self._result_status(result)
                    if status in SUCCESS: state.status = "success"
                    else:
                        state.error = result
                        decision = decide_retry(error=result, attempt=state.attempt, retry_limit=self.graph.nodes_by_id[node_id].retry_limit or 0,
                                                cancel_requested=status in {"cancelled"}, stop_active=bool(self.kill_switch and self.kill_switch.is_set()))
                        state.status = "pending" if decision.retry else decision.status
                        self._emit(state)
                        if not decision.retry: self.operator_tasks.append(f"{decision.status}:{node_id}:{decision.reason}")
        final = "completed" if all(s.status in SUCCESS for s in self.states.values()) else ("cancelled" if any(s.status == "cancelled" for s in self.states.values()) else "blocked")
        return ScheduleResult(final, dict(self.states), list(self.operator_tasks))

schedule = Scheduler
__all__ = ["NodeState", "ScheduleResult", "Scheduler", "schedule"]
