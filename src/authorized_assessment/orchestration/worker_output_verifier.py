"""Pure validation and gating for Code/Analyst/Verifier worker outputs."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .worker_result import ANALYST_FIELDS, validate_result

_SENSITIVE = ("cookie", "token", "authorization", "password", "secret", "session", "har", "raw", "credential", "api_key")
_OK = {"ok", "partial"}


def _sensitive(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(any(part in str(k).lower().replace("-", "_") for part in _SENSITIVE) or _sensitive(v) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_sensitive(v) for v in value)
    if isinstance(value, str):
        low = value.lower()
        return any(f"{part}=" in low or f"{part}:" in low for part in _SENSITIVE)
    return False


def _required(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{name} must be an object")
        return
    errors.extend(f"{name}: invalid contract" for _ in validate_result(value))


def _same(left: Mapping[str, Any], right: Mapping[str, Any], field: str) -> bool:
    return left.get(field) == right.get(field)


def validate_worker_outputs(
    code_result: Mapping[str, Any],
    analyst_result: Mapping[str, Any],
    verifier_result: Mapping[str, Any] | None = None,
    *,
    expected_assessment_id: str | None = None,
    expected_task_id: str | None = None,
    expected_correlation_id: str | None = None,
) -> list[str]:
    """Validate a complete worker chain without exposing input values.

    The verifier is optional for pre-verification checks; when supplied it must
    be a verifier result and may only pass with matching Code and Analyst refs.
    """
    errors: list[str] = []
    if _sensitive(code_result) or _sensitive(analyst_result) or (verifier_result is not None and _sensitive(verifier_result)):
        errors.append("sensitive worker output rejected")
    _required(code_result, "code_result", errors)
    _required(analyst_result, "analyst_result", errors)
    if not isinstance(code_result, Mapping) or not isinstance(analyst_result, Mapping):
        return list(dict.fromkeys(errors))
    if code_result.get("worker_type") != "code":
        errors.append("code_result must be a code result")
    if analyst_result.get("worker_type") != "analyst":
        errors.append("analyst_result must be an analyst result")
    for field in ANALYST_FIELDS:
        if field not in analyst_result:
            errors.append(f"analyst_result missing field: {field}")
    for field, expected in (("assessment_id", expected_assessment_id), ("correlation_id", expected_correlation_id)):
        if expected is not None:
            if code_result.get("lineage", {}).get(field) != expected:
                errors.append(f"code_result lineage mismatch: {field}")
            if analyst_result.get("lineage", {}).get(field) != expected:
                errors.append(f"analyst_result lineage mismatch: {field}")
    if expected_task_id is not None:
        if code_result.get("task_id") != expected_task_id or analyst_result.get("task_id") != expected_task_id:
            errors.append("task_id mismatch")
    if not _same(code_result, analyst_result, "task_id"):
        errors.append("code/analyst task_id mismatch")
    c_lineage, a_lineage = code_result.get("lineage", {}), analyst_result.get("lineage", {})
    if not isinstance(c_lineage, Mapping) or not isinstance(a_lineage, Mapping) or any(c_lineage.get(k) != a_lineage.get(k) for k in ("assessment_id", "correlation_id")):
        errors.append("code/analyst lineage mismatch")
    if code_result.get("status") not in _OK:
        errors.append("code result is not successful")
    if analyst_result.get("status") not in _OK:
        errors.append("analyst result is not successful")
    if code_result.get("result_id") == analyst_result.get("result_id"):
        errors.append("code and analyst result IDs must differ")
    if verifier_result is None:
        return list(dict.fromkeys(errors))
    _required(verifier_result, "verifier_result", errors)
    if not isinstance(verifier_result, Mapping):
        return list(dict.fromkeys(errors))
    if verifier_result.get("worker_type") != "verifier":
        errors.append("verifier_result must be a verifier result")
    if verifier_result.get("task_id") != code_result.get("task_id"):
        errors.append("verifier task_id mismatch")
    v_lineage = verifier_result.get("lineage", {})
    if not isinstance(v_lineage, Mapping) or any(v_lineage.get(k) != c_lineage.get(k) for k in ("assessment_id", "correlation_id")):
        errors.append("verifier lineage mismatch")
    gate = verifier_result.get("gate")
    if not isinstance(gate, Mapping):
        errors.append("verifier gate must be an object")
    else:
        if gate.get("code_result_id") != code_result.get("result_id"):
            errors.append("verifier code reference mismatch")
        if gate.get("analyst_result_id") != analyst_result.get("result_id"):
            errors.append("verifier analyst reference mismatch")
        if gate.get("verifier_result_id") != verifier_result.get("result_id"):
            errors.append("verifier self reference mismatch")
        if verifier_result.get("disposition") == "verified" and gate.get("dual_result_satisfied") is not True:
            errors.append("dual result gate unsatisfied")
    if verifier_result.get("disposition") == "verified" and errors:
        errors.append("verified disposition rejected")
    return list(dict.fromkeys(errors))


def verify_worker_outputs(*args: Any, **kwargs: Any) -> dict[str, Any]:
    errors = validate_worker_outputs(*args, **kwargs)
    return {"status": "verified" if not errors else "blocked", "verified": not errors, "errors": errors}


validate = validate_worker_outputs
verify = verify_worker_outputs
