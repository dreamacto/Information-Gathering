"""Offline, fail-closed aggregation for the dual-result verification gate."""
from __future__ import annotations

from typing import Any, Mapping

REQUIRED_GATES = ("phase", "context", "worker", "evidence", "approval", "quality")


def _ok(value: Any) -> bool:
    if isinstance(value, Mapping):
        if value.get("passed") is True or value.get("valid") is True or value.get("status") in {"PASS", "VALID", "verified", "ok"}:
            return True
        if value.get("gate_status") == "PASS" or value.get("quality_status") == "VALID":
            return True
    return value is True


def _walk_sensitive(value: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    forbidden = ("cookie", "credential", "password", "passwd", "secret", "session", "raw_response", "authorization")
    if isinstance(value, Mapping):
        for key, child in value.items():
            p = f"{path}.{key}" if path else str(key)
            if str(key).lower() != "authorization" and any(part in str(key).lower() for part in forbidden):
                hits.append(p)
            hits.extend(_walk_sensitive(child, p))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            hits.extend(_walk_sensitive(child, f"{path}[{index}]"))
    return hits


def _violations(value: Any, prefix: str) -> list[dict[str, str]]:
    if value is None:
        return [{"path": prefix, "code": "missing", "detail": "required gate is missing"}]
    if not _ok(value):
        return [{"path": prefix, "code": "failed", "detail": "gate did not pass"}]
    return []


def validate_verification_input(value: Any) -> list[dict[str, str]]:
    """Return path-addressed violations; never raises for malformed input."""
    if not isinstance(value, Mapping):
        return [{"path": "", "code": "type", "detail": "verification input must be an object"}]
    out: list[dict[str, str]] = []
    for name in REQUIRED_GATES:
        out.extend(_violations(value.get(name), name))
    dual = value.get("dual_result")
    if dual is None:
        dual = value.get("gate", {}).get("dual_result_satisfied") if isinstance(value.get("gate"), Mapping) else None
    if dual is not True:
        out.append({"path": "dual_result" if "dual_result" in value else "gate.dual_result_satisfied", "code": "dual_result_unsatisfied", "detail": "both code and analyst results are required"})
    for field in ("code_result_id", "analyst_result_id"):
        if not str(value.get(field, "")).strip():
            out.append({"path": field, "code": "missing", "detail": "dual result reference is missing"})
    for path in _walk_sensitive(value):
        out.append({"path": path, "code": "sensitive_field", "detail": "sensitive field is forbidden"})
    return out


def aggregate_verification(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Aggregate gate results.  Only an entirely clean input can be verified."""
    data = dict(value or {})
    violations = validate_verification_input(data)
    # Keep caller-supplied nested conflict paths, without flattening or dropping them.
    supplied = data.get("violations", [])
    if isinstance(supplied, list):
        for item in supplied:
            if isinstance(item, Mapping) and item.get("path"):
                violations.append({"path": str(item["path"]), "code": str(item.get("code", "conflict")), "detail": str(item.get("detail", "conflict preserved"))})
    verified = not violations
    return {
        "disposition": "verified" if verified else "needs_manual_validation",
        "verified": verified,
        "dual_result_satisfied": data.get("dual_result") is True or (isinstance(data.get("gate"), Mapping) and data["gate"].get("dual_result_satisfied") is True),
        "gates": {name: _ok(data.get(name)) for name in REQUIRED_GATES},
        "code_result_id": data.get("code_result_id"),
        "analyst_result_id": data.get("analyst_result_id"),
        "violations": violations,
    }


def verify(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return aggregate_verification(value)


def validate(value: Any) -> list[dict[str, str]]:
    return validate_verification_input(value)
