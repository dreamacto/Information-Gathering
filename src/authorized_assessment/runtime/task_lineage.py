"""Immutable task/attempt/retry lineage helpers."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Mapping

TERMINAL = {"complete", "success", "failed", "cancelled", "blocked"}
RETRYABLE = {"timeout", "transient", "service_unavailable", "failed"}

@dataclass(frozen=True)
class LineageNode:
    task_id: str
    assessment_id: str
    workflow: str
    attempt_no: int = 1
    parent_id: str | None = None
    retry_of: str | None = None
    correlation_id: str | None = None
    status: str = "in_progress"
    error: str | None = None
    def as_dict(self): return asdict(self)

def validate_lineage(nodes: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...]) -> dict[str, Any]:
    seen={}; errors=[]
    for raw in nodes:
        try:
            payload = dict(raw)
            payload.pop("ok", None)
            n=LineageNode(**payload)
        except (TypeError, ValueError) as exc: errors.append(f"invalid:{exc}"); continue
        if not n.task_id or not n.assessment_id or not n.workflow or n.attempt_no < 1: errors.append("invalid_identity")
        if n.task_id in seen: errors.append("duplicate_task")
        if n.parent_id == n.task_id or n.retry_of == n.task_id: errors.append("self_loop")
        if n.parent_id and n.parent_id not in seen: errors.append("missing_parent")
        if n.retry_of and n.retry_of not in seen: errors.append("missing_retry_of")
        for ref in (n.parent_id,n.retry_of):
            if ref and ref in seen and (seen[ref].assessment_id != n.assessment_id or seen[ref].workflow != n.workflow): errors.append("cross_workflow")
        if n.retry_of and n.parent_id and n.parent_id != n.retry_of: errors.append("retry_parent_mismatch")
        if n.retry_of and n.attempt_no != seen[n.retry_of].attempt_no + 1: errors.append("attempt_not_monotonic")
        if n.status in TERMINAL and n.status == "failed" and not n.error: errors.append("failed_requires_error")
        seen[n.task_id]=n
    return {"ok": not errors, "errors": errors}

def create_task(*, task_id: str, assessment_id: str, workflow: str, correlation_id: str | None = None) -> dict[str, Any]:
    n=LineageNode(task_id,assessment_id,workflow,correlation_id=correlation_id); result=n.as_dict(); result["ok"]=True; return result

def next_retry(previous: Mapping[str, Any], *, task_id: str, error: str, correlation_id: str | None = None) -> dict[str, Any]:
    if previous.get("status") not in RETRYABLE: return {"ok":False,"status":"blocked","reason":"retry_not_allowed"}
    if not error or task_id == previous.get("task_id"): return {"ok":False,"status":"rejected","reason":"invalid_retry"}
    n=LineageNode(task_id, previous["assessment_id"], previous["workflow"], int(previous["attempt_no"])+1, previous["task_id"], previous["task_id"], correlation_id or previous.get("correlation_id"), "in_progress", error)
    result=n.as_dict(); result["ok"]=True; return result

build_task = create_task
validate = validate_lineage
