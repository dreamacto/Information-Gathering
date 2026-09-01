"""Offline validation of context snapshots and policy/context joins."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from authorized_assessment.runtime.context_snapshot import validate_context_snapshot, verify_source_hashes
from authorized_assessment.runtime.policy_snapshot import validate_policy_snapshot

WORKFLOW_CURSOR = {"wz": "phase_status.json", "xcx": "phase_status.miniapp.json"}
SENSITIVE = ("cookie", "token", "password", "secret", "session", "authorization", "api_key")
_SENSITIVE_KEY_EXEMPTIONS = frozenset({"authorization_status"})


def _err(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def _sensitive_paths(node: Any, prefix: str = "") -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if str(key).lower() not in _SENSITIVE_KEY_EXEMPTIONS and any(part in str(key).lower() for part in SENSITIVE):
                out.append(path)
            out.extend(_sensitive_paths(value, path))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            out.extend(_sensitive_paths(value, f"{prefix}[{i}]"))
    return out


def verify_context(
    snapshot: Mapping[str, Any] | None,
    policy_snapshot: Mapping[str, Any] | None = None,
    *,
    project_root: str | Path | None = None,
    cursor: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify snapshot contract, policy digest, hashes, layers, and cursor isolation."""
    s = dict(snapshot or {})
    violations = [_err("snapshot_invalid", detail) for detail in validate_context_snapshot(s)]
    if policy_snapshot is not None:
        p = dict(policy_snapshot)
        if validate_policy_snapshot(p):
            violations.append(_err("policy_invalid", "policy snapshot failed validation"))
        digest = s.get("policy_digest") or {}
        for key in ("authorization_status", "active_testing_authorized", "blocked_actions"):
            if key in digest and digest.get(key) != p.get(key):
                violations.append(_err("policy_context_conflict", f"policy digest mismatch for {key}"))
        if s.get("context_conflicts"):
            violations.append(_err("context_conflict", "context conflicts are retained and block verification"))
        if p.get("authorization_status") != "confirmed" or p.get("active_testing_authorized") is not True:
            violations.append(_err("active_actions_blocked", "policy does not authorize active actions"))
    loaded = s.get("loaded_sources") or []
    seen_paths: set[str] = set()
    for item in loaded:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if path in seen_paths:
            violations.append(_err("duplicate_source", "duplicate loaded source path"))
        if isinstance(path, str):
            seen_paths.add(path)
        if item.get("layer") not in ("L0", "L1", "L2", "L3", None):
            violations.append(_err("invalid_layer", "loaded source layer is invalid"))
    workflow = s.get("workflow")
    if workflow in WORKFLOW_CURSOR:
        filename = WORKFLOW_CURSOR[workflow]
        if cursor is not None:
            cursor_name = cursor.get("filename") or cursor.get("path", "").split("/")[-1].split("\\")[-1]
            if cursor_name != filename:
                violations.append(_err("cursor_isolation", f"{workflow} requires {filename}"))
    history_paths = {item.get("path") for item in s.get("historical_inputs", []) if isinstance(item, dict)}
    if history_paths.intersection(set(s.get("current_facts", []))):
        violations.append(_err("history_current_mixed", "historical inputs must not be current facts"))
    for path in _sensitive_paths(s):
        violations.append(_err("sensitive_field", f"sensitive field present at {path}"))
    if project_root is not None and s.get("source_hashes"):
        # Hash verifier returns only path-level identifiers and never file content.
        old_root = None
        try:
            import authorized_assessment.runtime.context_snapshot as cs
            old_root = cs.PROJECT_ROOT
            cs.PROJECT_ROOT = Path(project_root)
            violations.extend(_err("source_hash", detail) for detail in verify_source_hashes(s))
        finally:
            if old_root is not None:
                cs.PROJECT_ROOT = old_root
    return {"valid": not violations, "status": "PASS" if not violations else "REJECTED", "violations": violations, "workflow": workflow, "current_facts_count": len(s.get("current_facts") or []), "historical_inputs_count": len(s.get("historical_inputs") or [])}


def evaluate_context(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return verify_context(*args, **kwargs)

__all__ = ["verify_context", "evaluate_context"]
