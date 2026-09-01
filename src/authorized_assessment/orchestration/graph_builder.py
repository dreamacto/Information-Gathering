from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from .graph import EDGE_KINDS, JOINS, GRAPH_VERSION, EdgeSpec, GraphSpec, NodeSpec
from .graph_validation import assert_valid_graph


class GraphBuilder:
    """Deterministic, side-effect-free builder for static assessment graphs."""

    def __init__(self, graph_id: str, assessment_id: str, workflow: str, *, created_at: str | None = None, graph_version: str = GRAPH_VERSION, cursor_file: str | None = None) -> None:
        self.graph_id = graph_id
        self.assessment_id = assessment_id
        self.workflow = workflow
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.graph_version = graph_version
        self.cursor_file = cursor_file
        self._nodes: list[NodeSpec] = []
        self._edges: list[EdgeSpec] = []
        self._metadata: dict[str, Any] = {"conditions": {}, "loops": {}}
        self._counter = 0

    def _node_id(self, phase: str, node_id: str | None = None) -> str:
        if node_id:
            return node_id if node_id.startswith("node_") else f"node_{node_id}"
        return f"node_{phase}_{len(self._nodes):03d}"

    def _edge_id(self, source: str, target: str, kind: str) -> str:
        self._counter += 1
        return f"edge_{self._counter:04d}_{source.removeprefix('node_')}_{target.removeprefix('node_')}_{kind}"

    def add_node(self, phase: str, *, node_id: str | None = None, kind: str = "task", order: int | None = None, join: str | None = None, cursor_file: str | None = None, timeout_seconds: int | None = None, retry_limit: int | None = None, cancellable: bool | None = None, terminal: bool = False, loop: dict[str, Any] | None = None) -> str:
        node = NodeSpec(node_id=self._node_id(phase, node_id), kind=kind, phase=phase, order=len(self._nodes) if order is None else order, join=join, cursor_file=cursor_file if cursor_file is not None else self.cursor_file, timeout_seconds=timeout_seconds, retry_limit=retry_limit, cancellable=cancellable, stream=self.workflow, terminal=terminal, loop=loop)
        self._nodes.append(node)
        return node.node_id

    def add_edge(self, source: str, target: str, *, kind: str = "depends_on", condition: str | None = None, branch: str | None = None, edge_id: str | None = None) -> str:
        edge = EdgeSpec(edge_id=edge_id or self._edge_id(source, target, kind), from_node=source, to_node=target, kind=kind, condition=condition, branch=branch, stream=self.workflow)
        self._edges.append(edge)
        return edge.edge_id

    def sequence(self, phases: Iterable[str], *, kind: str = "depends_on") -> list[str]:
        ids: list[str] = []
        for phase in phases:
            node_id = phase if phase.startswith("node_") else self.add_node(phase)
            ids.append(node_id)
            if len(ids) > 1:
                self.add_edge(ids[-2], ids[-1], kind=kind)
        return ids

    def condition(self, source: str, target: str, predicate: str | Callable[..., bool], *, branch: str = "true", edge_id: str | None = None) -> str:
        name = predicate if isinstance(predicate, str) else getattr(predicate, "__name__", "predicate")
        self._metadata.setdefault("conditions", {})[name] = {"source": source, "target": target, "branch": branch}
        return self.add_edge(source, target, kind="gates", condition=name, branch=branch, edge_id=edge_id)

    def fan_out(self, source: str, targets: Iterable[str], *, kind: str = "produces") -> list[str]:
        return [self.add_edge(source, target, kind=kind) for target in sorted(targets)]

    def fan_in(self, source_nodes: Iterable[str], target: str, *, join: str = "all") -> str:
        if join not in JOINS:
            raise ValueError(f"invalid join: {join}")
        target_node = next((node for node in self._nodes if node.node_id == target), None)
        if target_node is None:
            raise ValueError(f"unknown fan-in target: {target}")
        self._nodes[self._nodes.index(target_node)] = NodeSpec(**{**target_node.__dict__, "join": join})
        for source in sorted(source_nodes):
            self.add_edge(source, target, kind="joins")
        return target

    def loop(self, phase: str, *, max_iterations: int, termination: str | None = None, until: str | None = None, node_id: str | None = None) -> str:
        if not isinstance(max_iterations, int) or isinstance(max_iterations, bool) or max_iterations < 1:
            raise ValueError("max_iterations must be a positive integer")
        if termination is not None and until is not None:
            raise ValueError("termination and until are mutually exclusive")
        if termination is None and until is None:
            raise ValueError("loop requires termination or until")
        metadata = {"max_iterations": max_iterations, "termination": termination or until}
        node = self.add_node(phase, node_id=node_id, loop=metadata)
        self._metadata.setdefault("loops", {})[node] = metadata
        return node

    def terminal(self, phase: str = "terminal", *, node_id: str | None = None, kind: str = "checkpoint") -> str:
        return self.add_node(phase, node_id=node_id, kind=kind, terminal=True)

    def build(self) -> GraphSpec:
        graph = GraphSpec(self.graph_id, self.assessment_id, self.workflow, tuple(self._nodes), tuple(self._edges), self.created_at, self.graph_version, self._metadata)
        assert_valid_graph(graph)
        return graph

    finalize = build


def build_graph(*args: Any, **kwargs: Any) -> GraphSpec:
    builder = GraphBuilder(*args, **kwargs)
    return builder.build()
