from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .graph import GraphSpec
from .graph_validation import validate_graph

_BLOCKED = {"blocked", "failed", "timeout", "timed_out", "cancelled", "permission_denied"}


@dataclass(frozen=True)
class RouteDecision:
    node_ids: tuple[str, ...] = ()
    status: str = "ready"
    reason: str | None = None

    @property
    def ready(self) -> bool:
        return self.status == "ready"

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def __iter__(self):
        return iter(self.node_ids)

    def __len__(self) -> int:
        return len(self.node_ids)

    def __getitem__(self, index: int) -> str:
        return self.node_ids[index]


def _predicate_value(predicate: str, context: Mapping[str, Any]) -> Any:
    if predicate not in context:
        raise KeyError(f"missing condition context: {predicate}")
    value = context[predicate]
    if not isinstance(value, (bool, str, int, float)) and value is not None:
        raise ValueError(f"unsupported condition value: {predicate}")
    return value


def resolve_route(graph: GraphSpec, node_id: str, context: Mapping[str, Any] | None = None, completed: Mapping[str, str] | None = None) -> RouteDecision:
    errors = validate_graph(graph)
    if errors:
        return RouteDecision(status="blocked", reason="; ".join(errors))
    if node_id not in graph.nodes_by_id:
        return RouteDecision(status="blocked", reason=f"unknown node: {node_id}")
    context = context or {}
    completed = completed or {}
    node_status = completed.get(node_id)
    if node_status in _BLOCKED:
        return RouteDecision(status="blocked", reason=f"current node status: {node_status}")
    candidates = []
    for edge in graph.edges:
        if edge.from_node != node_id:
            continue
        if edge.kind == "gates":
            if not edge.condition:
                return RouteDecision(status="blocked", reason=f"condition missing on {edge.edge_id}")
            try:
                value = _predicate_value(edge.condition, context)
            except (KeyError, ValueError) as exc:
                return RouteDecision(status="blocked", reason=str(exc))
            branch = edge.branch or "true"
            matched = value if branch == "true" else not value if branch == "false" else value == branch
            if not matched:
                continue
        candidates.append(edge.to_node)
    result = tuple(sorted(set(candidates), key=lambda item: (graph.nodes_by_id[item].order, item)))
    return RouteDecision(node_ids=result, status="ready")


def next_nodes(graph: GraphSpec, node_id: str, context: Mapping[str, Any] | None = None, completed: Mapping[str, str] | None = None) -> tuple[str, ...]:
    return resolve_route(graph, node_id, context, completed).node_ids


def route(graph: GraphSpec, node_id: str, context: Mapping[str, Any] | None = None, completed: Mapping[str, str] | None = None) -> RouteDecision:
    return resolve_route(graph, node_id, context, completed)
