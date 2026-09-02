"""Pure, deterministic queue-only plans for mini-program review."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from authorized_assessment.orchestration.worker_context import WorkerContext
from authorized_assessment.orchestration.xcx_workers import XCX_BRANCHES

REQUIRED_SNAPSHOT_FIELDS = (
    "cursor", "target_model", "coverage", "candidate_index", "ledger_index",
    "phase_summary", "artifact_refs", "not_tested",
)
_SENSITIVE = ("cookie", "token", "authorization", "password", "secret", "session", "har", "raw", "credential", "api_key")


def _contains_sensitive(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            (str(key) not in XCX_BRANCHES and any(part in str(key).lower().replace("-", "_") for part in _SENSITIVE))
            or _contains_sensitive(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set)):
        return any(_contains_sensitive(item) for item in value)
    if isinstance(value, str):
        low = value.lower()
        return any(f"{part}=" in low or f"{part}:" in low for part in _SENSITIVE)
    return False


def _require_snapshot(snapshot: Mapping[str, Any]) -> list[str]:
    if not isinstance(snapshot, Mapping): return ["snapshot must be an object"]
    errors = [f"missing snapshot field: {field}" for field in REQUIRED_SNAPSHOT_FIELDS if field not in snapshot]
    if snapshot.get("workflow") != "xcx": errors.append("snapshot workflow must be 'xcx'")
    if snapshot.get("status_file", snapshot.get("cursor_file")) != "phase_status.miniapp.json": errors.append("snapshot must use phase_status.miniapp.json")
    if _contains_sensitive(snapshot): errors.append("sensitive snapshot content rejected")
    cursor = snapshot.get("cursor")
    if not isinstance(cursor, Mapping) or not cursor.get("current_phase"): errors.append("cursor must include current_phase")
    return errors


def _artifact_refs(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list): raise ValueError("artifact_refs must be a list")
    refs: list[dict[str, str]] = []
    for ref in value:
        if not isinstance(ref, Mapping) or not ref.get("path"):
            raise ValueError("artifact_refs must contain path-bearing objects")
        refs.append({"path": str(ref["path"]), **({"sha256": str(ref["sha256"])} if ref.get("sha256") else {})})
    return sorted(refs, key=lambda item: (item["path"], item.get("sha256", "")))


def build_xcx_worker_plan(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Build an eight-branch queue-only plan; reject incomplete/unsafe input."""
    errors = _require_snapshot(snapshot)
    if errors: raise ValueError("XCX worker plan rejected: " + "; ".join(errors))
    branches = []
    coverage = snapshot["coverage"]
    if not isinstance(coverage, Mapping): raise ValueError("coverage must be an object")
    current = snapshot["target_model"].get("current_facts", []) if isinstance(snapshot["target_model"], Mapping) else []
    not_tested = snapshot["not_tested"]
    if not isinstance(not_tested, list): raise ValueError("not_tested must be a list")
    refs = _artifact_refs(snapshot["artifact_refs"])
    for phase in XCX_BRANCHES:
        branch_coverage = coverage.get(phase, "pending")
        if isinstance(branch_coverage, Mapping):
            status = branch_coverage.get("status", "pending")
        else: status = branch_coverage or "pending"
        branches.append({
            "phase": phase, "status": str(status), "worker_mode": "offline_queue_only",
            "applicability_first": True, "actions": ["read_local_artifacts", "emit_structured_queue"],
            "facts": [str(item) for item in current], "coverage": branch_coverage,
            "not_tested": list(not_tested), "artifact_refs": refs,
        })
    return {
        "workflow": "xcx", "cursor_file": "phase_status.miniapp.json",
        "current_phase": snapshot["cursor"]["current_phase"], "queue_only": True,
        "network": "none", "fan_out": branches,
        "serial_gates": ["authorization", "scope", "approval", "verifier"],
        "facts": [str(item) for item in current], "coverage": dict(coverage),
        "not_tested": list(not_tested), "artifact_refs": refs,
        "candidate_index": snapshot["candidate_index"], "ledger_index": snapshot["ledger_index"],
        "phase_summary": snapshot["phase_summary"],
        "facts_used": [str(item) for item in current],
        "reasoning_summary": "Only sanitized local mini-program artifacts are considered; no network action is planned.",
        "alternative_explanations": ["surface absent", "artifact incomplete", "feature gated"],
        "hypotheses": [f"review {phase} using local evidence only" for phase in XCX_BRANCHES],
        "unknowns": list(not_tested), "next_hints": ["keep all outputs queue-only", "manual approval required for active validation"],
        "finding_status": "candidate",
    }


plan = build_xcx_worker_plan
__all__ = ["REQUIRED_SNAPSHOT_FIELDS", "build_xcx_worker_plan", "plan"]
