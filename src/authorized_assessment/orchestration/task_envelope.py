"""Safe offline task envelopes containing references, never raw payloads."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

WORKFLOWS = frozenset({"wz", "xcx", "fh"})
ACTIONS = frozenset({"offline", "read_only", "metadata"})
CURSOR_FILES = {"wz": "phase_status.json", "xcx": "phase_status.miniapp.json", "fh": "run_status.json"}
_ID = re.compile(r"^task_[A-Za-z0-9._-]+$")
_SENSITIVE = ("cookie", "token", "password", "secret", "session", "har", "raw")

@dataclass(frozen=True)
class ArtifactRef:
    path: str
    sha256: str
    def as_dict(self): return asdict(self)

@dataclass(frozen=True)
class TaskBudget:
    max_seconds: int = 60
    max_items: int = 0
    def as_dict(self): return asdict(self)

@dataclass(frozen=True)
class TaskEnvelope:
    task_id: str
    assessment_id: str
    workflow: str
    phase: str
    action: str
    correlation_id: str
    idempotency_key: str
    attempt: int
    target_ref: ArtifactRef
    context_ref: ArtifactRef
    policy_ref: ArtifactRef
    scope_ref: ArtifactRef
    budget: TaskBudget
    created_at: str
    parent_id: str | None = None
    approval_ref: ArtifactRef | None = None
    input_artifact_refs: tuple[ArtifactRef, ...] = ()
    deadline: str | None = None
    cancel_requested: bool = False
    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["input_artifact_refs"] = [r.as_dict() for r in self.input_artifact_refs]
        return value


def ref(path: str, sha256: str) -> ArtifactRef:
    candidate = str(path or "")
    if any(part in candidate.lower().replace("-", "_") for part in _SENSITIVE):
        raise ValueError("sensitive artifact path rejected")
    if not re.fullmatch(r"[a-f0-9]{64}", str(sha256 or "")):
        raise ValueError("sha256 must be 64 lowercase hex characters")
    if not candidate:
        raise ValueError("artifact path must be non-empty")
    return ArtifactRef(candidate, sha256)


def validate_envelope(value: Mapping[str, Any] | TaskEnvelope) -> list[str]:
    data = value.as_dict() if isinstance(value, TaskEnvelope) else dict(value) if isinstance(value, Mapping) else None
    if data is None: return ["task envelope must be an object"]
    errors=[]
    for field in ("task_id","assessment_id","phase","correlation_id","idempotency_key","created_at"):
        if not isinstance(data.get(field), str) or not data[field]: errors.append(f"{field} must be non-empty")
    if isinstance(data.get("task_id"), str) and not _ID.fullmatch(data["task_id"]): errors.append("task_id has invalid format")
    if data.get("workflow") not in WORKFLOWS: errors.append("workflow is invalid")
    if data.get("action") not in ACTIONS: errors.append("action is invalid")
    if isinstance(data.get("idempotency_key"), str) and len(data["idempotency_key"]) < 16: errors.append("idempotency_key too short")
    if isinstance(data.get("attempt"), bool) or not isinstance(data.get("attempt"), int) or data.get("attempt", 0) < 1: errors.append("attempt must be >= 1")
    if data.get("workflow") in WORKFLOWS:
        for key in ("scope_ref", "context_ref", "policy_ref", "target_ref"):
            item=data.get(key)
            if not isinstance(item, Mapping): errors.append(f"{key} must be a ref")
            else:
                try: ref(item.get("path"), item.get("sha256"))
                except ValueError as exc: errors.append(f"{key}: {exc}")
        budget=data.get("budget")
        if not isinstance(budget, Mapping) or isinstance(budget.get("max_seconds"), bool) or not isinstance(budget.get("max_seconds"), int) or budget["max_seconds"] < 1 or isinstance(budget.get("max_items"), bool) or not isinstance(budget.get("max_items"), int) or budget["max_items"] < 0: errors.append("budget invalid")
        if data.get("cancel_requested") is not None and not isinstance(data.get("cancel_requested"), bool): errors.append("cancel_requested must be boolean")
    return errors


def build_task(*, task_id: str, assessment_id: str, workflow: str, phase: str, action: str = "offline", correlation_id: str, idempotency_key: str, target_ref: ArtifactRef, context_ref: ArtifactRef, policy_ref: ArtifactRef, scope_ref: ArtifactRef, budget: TaskBudget | None = None, attempt: int = 1, **kwargs: Any) -> TaskEnvelope:
    task = TaskEnvelope(task_id, assessment_id, workflow, phase, action, correlation_id, idempotency_key, attempt, target_ref, context_ref, policy_ref, scope_ref, budget or TaskBudget(), datetime.now(timezone.utc).isoformat(timespec="seconds"), **kwargs)
    errors=validate_envelope(task)
    if errors: raise ValueError("task rejected: "+"; ".join(errors))
    return task


def idempotency_key(*parts: object) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()

validate = validate_envelope
