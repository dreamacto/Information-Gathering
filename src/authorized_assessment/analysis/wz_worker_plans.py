"""Pure WZ specialist planning from a complete, sanitized context snapshot."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from authorized_assessment.analysis.coverage_matrix import APPLICATION_MAP_SUBPHASES, COVERAGE_SUBSTATUSES
from authorized_assessment.orchestration.worker_context import WorkerContext

REQUIRED_SNAPSHOT_FIELDS = (
    "cursor",
    "target_model",
    "coverage",
    "candidate_index",
    "ledger_index",
    "phase_summary",
    "artifact_refs",
    "not_tested",
)


def _contains_sensitive(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(any(token in str(key).lower().replace("-", "_") for token in ("cookie", "token", "password", "secret", "session", "har", "raw", "credential")) or _contains_sensitive(item) for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_sensitive(item) for item in value)
    if isinstance(value, str):
        low = value.lower()
        return any(f"{token}=" in low or f"{token}:" in low for token in ("cookie", "token", "password", "secret", "session", "authorization"))
    return False


def _require_snapshot(snapshot: Mapping[str, Any]) -> list[str]:
    if not isinstance(snapshot, Mapping):
        return ["snapshot must be an object"]
    errors = [f"missing snapshot field: {field}" for field in REQUIRED_SNAPSHOT_FIELDS if field not in snapshot]
    if snapshot.get("workflow") != "wz":
        errors.append("snapshot workflow must be 'wz'")
    if snapshot.get("status_file", snapshot.get("cursor_file")) != "phase_status.json":
        errors.append("snapshot must use phase_status.json")
    if _contains_sensitive(snapshot):
        errors.append("sensitive snapshot content rejected")
    cursor = snapshot.get("cursor")
    if not isinstance(cursor, Mapping) or not cursor.get("current_phase"):
        errors.append("cursor must include current_phase")
    return errors


def build_wz_worker_plan(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic plan or raise ValueError on incomplete context."""
    errors = _require_snapshot(snapshot)
    if errors:
        raise ValueError("WZ worker plan rejected: " + "; ".join(errors))
    context = snapshot.get("context")
    if context is not None:
        context = WorkerContext.from_snapshot(context)
        if context.workflow != "wz":
            raise ValueError("WZ worker plan context workflow mismatch")
    coverage = snapshot["coverage"]
    if not isinstance(coverage, Mapping):
        raise ValueError("coverage must be an object")
    substatuses = coverage.get("application_mapping", {}).get("substatuses", {}) if isinstance(coverage.get("application_mapping"), Mapping) else {}
    if substatuses:
        unknown = sorted(set(substatuses) - set(APPLICATION_MAP_SUBPHASES))
        invalid = sorted(set(str(value) for value in substatuses.values()) - (set(COVERAGE_SUBSTATUSES) | {"", "pending"}))
        if unknown or invalid:
            raise ValueError(f"invalid application mapping coverage: unknown={unknown}, invalid={invalid}")
    historical = snapshot.get("historical_inputs", [])
    if not isinstance(historical, list):
        raise ValueError("historical_inputs must be a list")
    for item in historical:
        if not isinstance(item, Mapping) or item.get("classification") not in {"historical_lead", "pending_hypothesis"}:
            raise ValueError("historical input must remain historical_lead or pending_hypothesis")
    branches = []
    for phase in APPLICATION_MAP_SUBPHASES:
        branches.append({
            "phase": phase,
            "status": (substatuses.get(phase) if isinstance(substatuses, Mapping) else None) or "pending",
            "applicability_first": True,
            "worker_mode": "offline_queue_only",
        })
    return {
        "workflow": "wz",
        "cursor_file": "phase_status.json",
        "current_phase": snapshot["cursor"]["current_phase"],
        "fan_out": branches,
        "specialist_phases": ["api_testing", "product_triage", "input_testing", "evidence_review"],
        "serial_gates": ["authorization", "scope", "approval", "verifier"],
        "facts_used": list(snapshot["target_model"].get("current_facts", [])) if isinstance(snapshot["target_model"], Mapping) else [],
        "reasoning_summary": "Use only complete current-engagement summaries; historical inputs remain unverified leads.",
        "alternative_explanations": ["surface absent", "coverage incomplete", "approval or manual evidence unavailable"],
        "hypotheses": [f"review {phase} without active requests" for phase in APPLICATION_MAP_SUBPHASES],
        "unknowns": list(snapshot["not_tested"]),
        "coverage": dict(coverage),
        "not_tested": list(snapshot["not_tested"]),
        "next_hints": ["run Code Worker before Analyst Worker", "fan-in only after all five branches have structured results"],
        "historical_inputs": [{"classification": item["classification"], "ref": item.get("ref", "")} for item in historical],
        "current_coverage_from_history": False,
        "finding_status": "candidate",
    }


plan = build_wz_worker_plan
__all__ = ["REQUIRED_SNAPSHOT_FIELDS", "build_wz_worker_plan", "plan"]
