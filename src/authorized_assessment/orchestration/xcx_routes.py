"""Pure, fail-closed routing helpers for the XCX orchestration stream."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .graph import GraphSpec
from .graph_barriers import BarrierDecision, evaluate_barrier
from .graph_routes import RouteDecision, resolve_route
from .xcx_graph import XCX_BRANCHES, XCX_CURSOR_FILE, XCX_PHASE_WORKERS, XCX_PHASES, XCX_WORKFLOW

XCX_PHASE_WORKERS = XCX_PHASE_WORKERS
PHASE_WORKERS = XCX_PHASE_WORKERS
BLOCKING_STATUSES = frozenset({"blocked", "failed", "cancelled", "timeout", "timed_out", "permission_denied", "approval_required"})
TERMINAL_STATUSES = frozenset({"succeeded", "success", "ok", "completed", *BLOCKING_STATUSES})


@dataclass(frozen=True)
class XCXRouteDecision:
    worker_ids: tuple[str, ...] = ()
    node_ids: tuple[str, ...] = ()
    status: str = "ready"
    reason: str | None = None

    @property
    def ready(self) -> bool:
        return self.status == "ready"

    @property
    def blocked(self) -> bool:
        return not self.ready

    def __iter__(self):
        return iter(self.worker_ids or self.node_ids)


def allowed_workers(phase: str) -> tuple[str, ...]:
    return XCX_PHASE_WORKERS.get(str(phase), ())


def phase_branches(phase: str) -> tuple[str, ...]:
    return XCX_BRANCHES.get(str(phase), ())


def resolve_xcx_route(
    phase: str,
    *,
    workflow: str = XCX_WORKFLOW,
    cursor_file: str = XCX_CURSOR_FILE,
    status: str = "ready",
    required_predecessors: tuple[str, ...] = (),
    completed: Mapping[str, str] | None = None,
) -> XCXRouteDecision:
    """Resolve worker dispatch without reading status files or contacting targets."""
    if workflow != XCX_WORKFLOW:
        return XCXRouteDecision(status="blocked", reason="XCX route requires workflow='xcx'")
    if cursor_file != XCX_CURSOR_FILE:
        return XCXRouteDecision(status="blocked", reason="XCX route requires phase_status.miniapp.json")
    if phase not in XCX_PHASES:
        return XCXRouteDecision(status="blocked", reason=f"unknown XCX phase: {phase}")
    if status in BLOCKING_STATUSES:
        return XCXRouteDecision(status="blocked", reason=f"phase status blocks worker dispatch: {status}")
    statuses = completed or {}
    missing = tuple(item for item in required_predecessors if statuses.get(item) not in {"succeeded", "success", "ok", "completed"})
    if missing:
        return XCXRouteDecision(status="blocked", reason=f"predecessors not successful: {', '.join(missing)}")
    return XCXRouteDecision(worker_ids=allowed_workers(phase))


def resolve_route_for_graph(
    graph: GraphSpec,
    node_id: str,
    context: Mapping[str, Any] | None = None,
    completed: Mapping[str, str] | None = None,
) -> RouteDecision:
    """Delegate graph routing to the shared pure resolver, failing closed."""
    try:
        if graph.workflow != XCX_WORKFLOW:
            return RouteDecision(status="blocked", reason="graph workflow is not xcx")
        if any(node.cursor_file not in (None, XCX_CURSOR_FILE) for node in graph.nodes):
            return RouteDecision(status="blocked", reason="graph contains a non-XCX cursor")
        return resolve_route(graph, node_id, context, completed)
    except Exception as exc:
        return RouteDecision(status="blocked", reason=f"route resolution failed: {exc}")


def evaluate_xcx_barrier(join: str, expected: tuple[str, ...], statuses: Mapping[str, str]) -> BarrierDecision:
    """Evaluate a branch barrier using the shared fail-closed barrier semantics."""
    try:
        return evaluate_barrier(join, expected, statuses)
    except Exception as exc:
        return BarrierDecision("blocked", False, f"barrier evaluation failed: {exc}")


def worker_allowed(phase: str, worker_id: str) -> bool:
    return worker_id in allowed_workers(phase)


route = resolve_xcx_route
resolve = resolve_xcx_route
barrier = evaluate_xcx_barrier

__all__ = ["XCXRouteDecision", "XCX_PHASE_WORKERS", "PHASE_WORKERS", "allowed_workers", "phase_branches", "resolve_xcx_route", "resolve_route_for_graph", "evaluate_xcx_barrier", "worker_allowed", "route", "resolve", "barrier"]
