"""Worker result builders with analyst and dual-result gates."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Mapping

STATUSES = frozenset({"ok", "partial", "blocked", "cancelled", "failed", "needs_manual_validation"})
ANALYST_FIELDS = ("facts_used", "reasoning_summary", "alternative_explanations", "hypotheses", "unknowns", "coverage", "not_tested", "next_hints")
_SENSITIVE = ("cookie", "token", "password", "secret", "session", "raw_response", "traceback")


def _safe(value: Any, path: str = "result") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if any(part in str(key).lower() for part in _SENSITIVE): raise ValueError(f"sensitive result field rejected: {path}.{key}")
            _safe(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value): _safe(item, f"{path}[{i}]")


def validate_result(value: Mapping[str, Any]) -> list[str]:
    if not isinstance(value, Mapping): return ["result must be an object"]
    errors=[]
    for field in ("result_id", "task_id", "worker_id", "worker_type", "status", "created_at", "lineage", "gate"):
        if field not in value: errors.append(f"missing required field: {field}")
    if value.get("worker_type") not in {"code", "analyst", "verifier"}: errors.append("worker_type is invalid")
    if value.get("status") not in STATUSES: errors.append("status is invalid")
    if value.get("worker_type") == "analyst": errors.extend(f"missing analyst field: {x}" for x in ANALYST_FIELDS if x not in value)
    if value.get("worker_type") in {"code", "analyst"} and value.get("finding_status") in {"proven", "confirmed"}: errors.append("non-verifier cannot confirm")
    if value.get("disposition") == "verified":
        gate=value.get("gate") or {}
        if value.get("worker_type") != "verifier": errors.append("only verifier may verify")
        if not gate.get("dual_result_satisfied"): errors.append("dual result gate unsatisfied")
    try: _safe(value)
    except ValueError as exc: errors.append(str(exc))
    return errors


def build_result(*, result_id: str, task_id: str, worker_id: str, worker_type: str, status: str = "ok", assessment_id: str, correlation_id: str, code_result_id: str | None = None, analyst_result_id: str | None = None, verifier_result_id: str | None = None, dual_result_satisfied: bool = False, **fields: Any) -> dict[str, Any]:
    result={"result_id":result_id,"task_id":task_id,"worker_id":worker_id,"worker_type":worker_type,"status":status,"created_at":datetime.now(timezone.utc).isoformat(timespec="seconds"),"lineage":{"assessment_id":assessment_id,"correlation_id":correlation_id,"parent_id":fields.pop("parent_id",None)},"gate":{"code_result_id":code_result_id,"analyst_result_id":analyst_result_id,"verifier_result_id":verifier_result_id,"dual_result_satisfied":dual_result_satisfied}}
    result.update(fields); errors=validate_result(result)
    if errors: raise ValueError("result rejected: "+"; ".join(errors))
    return result

validate = validate_result
