"""Public Supervisor façade for offline graph execution."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Mapping

from .graph import GraphSpec
from .orchestration_runtime import OrchestrationRuntime
from .task_envelope import ArtifactRef
from .worker_context import WorkerContext

class Supervisor:
    """Owns assessment lifecycle and delegates work to the local runtime."""
    def __init__(self, graph: GraphSpec, *, context: WorkerContext,
                 target_ref: ArtifactRef | Mapping[str, Any], context_ref: ArtifactRef | Mapping[str, Any],
                 policy_ref: ArtifactRef | Mapping[str, Any], scope_ref: ArtifactRef | Mapping[str, Any],
                 state_dir: str | Path, **runtime_kwargs: Any) -> None:
        self.runtime = OrchestrationRuntime(graph, context=context, target_ref=target_ref,
                                            context_ref=context_ref, policy_ref=policy_ref,
                                            scope_ref=scope_ref, state_dir=state_dir,
                                            **runtime_kwargs)
        self.lifecycle = "ready"

    def run(self) -> dict[str, Any]:
        self.lifecycle = "running"
        result = self.runtime.run()
        self.lifecycle = result.get("status", "blocked")
        return {**result, "lifecycle": self.lifecycle}

    def request_cancel(self, reason: str = "operator requested stop") -> dict[str, Any]:
        return self.runtime.request_cancel(reason)

    def resume(self) -> dict[str, Any]:
        return self.run()

    def snapshot(self) -> dict[str, Any]:
        return {**self.runtime.snapshot(), "lifecycle": self.lifecycle}

__all__ = ["Supervisor"]
