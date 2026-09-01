from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

SCHEMA_VERSION = "1.0"
GRAPH_VERSION = "1.0"
WORKFLOWS = frozenset({"wz", "xcx", "fh"})
NODE_KINDS = frozenset({"task", "worker", "gate", "checkpoint", "approval", "verifier"})
EDGE_KINDS = frozenset({"depends_on", "produces", "gates", "joins"})
JOINS = frozenset({"all", "any", "barrier"})
CURSORS = frozenset({"phase_status.json", "phase_status.miniapp.json"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class NodeSpec:
    node_id: str
    kind: str
    phase: str
    order: int
    join: str | None = None
    cursor_file: str | None = None
    timeout_seconds: int | None = None
    retry_limit: int | None = None
    cancellable: bool | None = None
    # Planning-only metadata; never emitted to the graph contract.
    stream: str | None = None
    terminal: bool = False
    loop: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "node_id": self.node_id,
            "kind": self.kind,
            "phase": self.phase,
            "order": self.order,
        }
        for key in ("join", "cursor_file", "timeout_seconds", "retry_limit", "cancellable"):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        return data

    def to_planning_dict(self) -> dict[str, Any]:
        data = self.to_dict()
        if self.stream is not None:
            data["stream"] = self.stream
        if self.terminal:
            data["terminal"] = True
        if self.loop is not None:
            data["loop"] = dict(self.loop)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NodeSpec":
        allowed = {"node_id", "kind", "phase", "order", "join", "cursor_file", "timeout_seconds", "retry_limit", "cancellable"}
        unknown = set(data) - allowed
        if unknown:
            raise ValueError(f"unknown node fields: {sorted(unknown)}")
        return cls(**{key: data[key] for key in allowed if key in data})


@dataclass(frozen=True)
class EdgeSpec:
    edge_id: str
    from_node: str
    to_node: str
    kind: str = "depends_on"
    condition: str | None = None
    branch: str | None = None
    stream: str | None = None

    @property
    def from_(self) -> str:
        return self.from_node

    @property
    def to(self) -> str:
        return self.to_node

    def to_dict(self) -> dict[str, Any]:
        return {"edge_id": self.edge_id, "from": self.from_node, "to": self.to_node, "kind": self.kind}

    def to_planning_dict(self) -> dict[str, Any]:
        data = self.to_dict()
        if self.condition is not None:
            data["condition"] = self.condition
        if self.branch is not None:
            data["branch"] = self.branch
        if self.stream is not None:
            data["stream"] = self.stream
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EdgeSpec":
        allowed = {"edge_id", "from", "to", "kind"}
        unknown = set(data) - allowed
        if unknown:
            raise ValueError(f"unknown edge fields: {sorted(unknown)}")
        return cls(edge_id=data["edge_id"], from_node=data["from"], to_node=data["to"], kind=data.get("kind", "depends_on"))


@dataclass(frozen=True)
class GraphSpec:
    graph_id: str
    assessment_id: str
    workflow: str
    nodes: tuple[NodeSpec, ...] | list[NodeSpec]
    edges: tuple[EdgeSpec, ...] | list[EdgeSpec] = field(default_factory=tuple)
    created_at: str = field(default_factory=_now)
    graph_version: str = GRAPH_VERSION
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "nodes", tuple(self.nodes))
        object.__setattr__(self, "edges", tuple(self.edges))

    @property
    def nodes_by_id(self) -> dict[str, NodeSpec]:
        return {node.node_id: node for node in self.nodes}

    def successors(self, node_id: str, *, kind: str | None = None) -> tuple[NodeSpec, ...]:
        ids = [edge.to_node for edge in self.edges if edge.from_node == node_id and (kind is None or edge.kind == kind)]
        return tuple(sorted((self.nodes_by_id[item] for item in ids if item in self.nodes_by_id), key=lambda n: (n.order, n.node_id)))

    def predecessors(self, node_id: str, *, kind: str | None = None) -> tuple[NodeSpec, ...]:
        ids = [edge.from_node for edge in self.edges if edge.to_node == node_id and (kind is None or edge.kind == kind)]
        return tuple(sorted((self.nodes_by_id[item] for item in ids if item in self.nodes_by_id), key=lambda n: (n.order, n.node_id)))

    def roots(self) -> tuple[NodeSpec, ...]:
        incoming = {edge.to_node for edge in self.edges}
        return tuple(sorted((n for n in self.nodes if n.node_id not in incoming), key=lambda n: (n.order, n.node_id)))

    def terminals(self) -> tuple[NodeSpec, ...]:
        outgoing = {edge.from_node for edge in self.edges}
        return tuple(sorted((n for n in self.nodes if n.terminal or n.node_id not in outgoing), key=lambda n: (n.order, n.node_id)))

    def topological_order(self) -> tuple[str, ...]:
        incoming = {node.node_id: 0 for node in self.nodes}
        adjacency = {node.node_id: [] for node in self.nodes}
        for edge in self.edges:
            if edge.from_node in adjacency and edge.to_node in incoming:
                adjacency[edge.from_node].append(edge.to_node)
                incoming[edge.to_node] += 1
        ready = sorted((n for n, degree in incoming.items() if degree == 0), key=lambda n: (self.nodes_by_id[n].order, n))
        result: list[str] = []
        while ready:
            node = ready.pop(0)
            result.append(node)
            for child in sorted(adjacency[node], key=lambda n: (self.nodes_by_id[n].order, n)):
                incoming[child] -= 1
                if incoming[child] == 0:
                    ready.append(child)
                    ready.sort(key=lambda n: (self.nodes_by_id[n].order, n))
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "assessment_id": self.assessment_id,
            "workflow": self.workflow,
            "nodes": [node.to_dict() for node in sorted(self.nodes, key=lambda n: (n.order, n.node_id))],
            "edges": [edge.to_dict() for edge in sorted(self.edges, key=lambda e: e.edge_id)],
            "created_at": self.created_at,
        }

    def to_planning_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "assessment_id": self.assessment_id,
            "workflow": self.workflow,
            "graph_version": self.graph_version,
            "nodes": [node.to_planning_dict() for node in sorted(self.nodes, key=lambda n: (n.order, n.node_id))],
            "edges": [edge.to_planning_dict() for edge in sorted(self.edges, key=lambda e: e.edge_id)],
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GraphSpec":
        allowed = {"graph_id", "assessment_id", "workflow", "nodes", "edges", "created_at"}
        unknown = set(data) - allowed
        if unknown:
            raise ValueError(f"unknown graph fields: {sorted(unknown)}")
        return cls(
            graph_id=data["graph_id"], assessment_id=data["assessment_id"], workflow=data["workflow"],
            nodes=tuple(NodeSpec.from_dict(item) for item in data.get("nodes", [])),
            edges=tuple(EdgeSpec.from_dict(item) for item in data.get("edges", [])),
            created_at=data.get("created_at", _now()),
        )

    @classmethod
    def from_planning_dict(cls, data: Mapping[str, Any]) -> "GraphSpec":
        allowed = {"graph_id", "assessment_id", "workflow", "graph_version", "nodes", "edges", "created_at", "metadata"}
        unknown = set(data) - allowed
        if unknown:
            raise ValueError(f"unknown planning graph fields: {sorted(unknown)}")
        nodes = tuple(NodeSpec(
            node_id=item["node_id"], kind=item["kind"], phase=item["phase"], order=item["order"],
            join=item.get("join"), cursor_file=item.get("cursor_file"), timeout_seconds=item.get("timeout_seconds"),
            retry_limit=item.get("retry_limit"), cancellable=item.get("cancellable"), stream=item.get("stream"),
            terminal=item.get("terminal", False), loop=item.get("loop"),
        ) for item in data.get("nodes", []))
        edges = tuple(EdgeSpec(item["edge_id"], item["from"], item["to"], item.get("kind", "depends_on"), item.get("condition"), item.get("branch"), item.get("stream")) for item in data.get("edges", []))
        return cls(data["graph_id"], data["assessment_id"], data["workflow"], nodes, edges, data.get("created_at", _now()), data.get("graph_version", GRAPH_VERSION), data.get("metadata", {}))

    def with_metadata(self, **metadata: Any) -> "GraphSpec":
        merged = dict(self.metadata)
        merged.update(metadata)
        return GraphSpec(self.graph_id, self.assessment_id, self.workflow, self.nodes, self.edges, self.created_at, self.graph_version, merged)


Node = NodeSpec
Edge = EdgeSpec
Graph = GraphSpec
GraphBuilderResult = GraphSpec


def edge_from(edge: EdgeSpec | Mapping[str, Any]) -> str:
    return edge.from_node if isinstance(edge, EdgeSpec) else str(edge.get("from", ""))


def edge_to(edge: EdgeSpec | Mapping[str, Any]) -> str:
    return edge.to_node if isinstance(edge, EdgeSpec) else str(edge.get("to", ""))
