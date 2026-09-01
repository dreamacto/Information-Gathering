"""Read-only, sanitized worker context."""
from __future__ import annotations
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

CURSOR_FILES = {"wz": "phase_status.json", "xcx": "phase_status.miniapp.json", "fh": "run_status.json"}
_SENSITIVE = ("cookie", "token", "authorization", "password", "secret", "session", "har", "raw", "credential", "api_key")


def _check(node: Any, path: str = "context") -> None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            if any(part in str(key).lower().replace("-", "_") for part in _SENSITIVE): raise ValueError(f"sensitive context field rejected: {path}.{key}")
            _check(value, f"{path}.{key}")
    elif isinstance(node, (list, tuple)):
        for i, value in enumerate(node): _check(value, f"{path}[{i}]")
    elif isinstance(node, str):
        low=node.lower()
        if any(f"{part}=" in low or f"{part}:" in low for part in _SENSITIVE): raise ValueError(f"sensitive context value rejected: {path}")

@dataclass(frozen=True)
class WorkerContext:
    workflow: str
    phase: str
    cursor_file: str
    facts: tuple[str, ...] = ()
    coverage: Mapping[str, Any] = None
    not_tested: tuple[str, ...] = ()
    source_refs: tuple[Mapping[str, str], ...] = ()
    blocked: bool = False

    def __post_init__(self):
        if self.workflow not in CURSOR_FILES: raise ValueError("workflow is invalid")
        if self.cursor_file != CURSOR_FILES[self.workflow]: raise ValueError("workflow/cursor isolation violation")
        if not isinstance(self.phase, str) or not self.phase: raise ValueError("phase must be non-empty")
        _check(self.facts); _check(self.coverage or {}); _check(self.not_tested); _check(self.source_refs)
        object.__setattr__(self, "coverage", MappingProxyType(dict(self.coverage or {})))
        object.__setattr__(self, "facts", tuple(self.facts))
        object.__setattr__(self, "not_tested", tuple(self.not_tested))
        object.__setattr__(self, "source_refs", tuple(dict(x) for x in self.source_refs))

    @classmethod
    def from_snapshot(cls, snapshot: Mapping[str, Any]) -> "WorkerContext":
        if not isinstance(snapshot, Mapping): raise ValueError("snapshot must be an object")
        workflow=snapshot.get("workflow"); phase=snapshot.get("phase")
        return cls(workflow, phase, CURSOR_FILES.get(workflow, ""), tuple(snapshot.get("current_facts", ())), snapshot.get("coverage", {}), tuple(snapshot.get("not_tested", ())), tuple(snapshot.get("source_refs", ())), bool(snapshot.get("active_actions_blocked", False)))

    def as_dict(self) -> dict[str, Any]:
        return {"workflow": self.workflow, "phase": self.phase, "cursor_file": self.cursor_file, "facts": list(self.facts), "coverage": dict(self.coverage), "not_tested": list(self.not_tested), "source_refs": [dict(x) for x in self.source_refs], "blocked": self.blocked}

validate = WorkerContext
