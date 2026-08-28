"""Canonical stage metadata and paths for the main runner.

The registry is descriptive only: it does not execute stages or alter their
arguments.  Keep the legacy ``STAGE_SCRIPTS`` mapping and ``stage_script``
helper for compatibility with existing callers.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StageSpec:
    """Static metadata used to classify a runner-launched stage."""

    name: str
    script: str
    category: str
    risk: str
    offline: bool
    authorization_required: bool
    notes: str = ""


_STAGE_SPECS = (
    StageSpec("subdomain_bruteforce", "subdomain_bruteforce_controlled.py", "discovery", "low", False, True),
    StageSpec("tool_fingerprint", "tool_fingerprint_httpx.py", "discovery", "low", False, True),
    StageSpec("api_discovery", "api_discovery.py", "discovery", "low", False, True),
    StageSpec("api_confirm", "api_endpoint_confirm.py", "discovery", "low", False, True),
    StageSpec("sqli_triage", "sqli_triage.py", "triage", "medium", False, True),
    StageSpec("header_sqli_triage", "header_reflection_probe.py", "triage", "medium", False, True),
    StageSpec("xss_triage", "xss_candidate_triage.py", "triage", "medium", False, True),
    StageSpec("shiro_triage", "shiro_triage.py", "triage", "medium", False, True),
    StageSpec("asset_fingerprint_ingest", "asset_fingerprint_ingest.py", "artifacts", "none", True, False),
    StageSpec("authenticated_review", "authenticated_session_review.py", "review", "medium", False, True),
    StageSpec("miniapp_source", "miniapp_endpoint_offline.py", "miniapp", "none", True, False),
    StageSpec("miniapp_manual", "miniapp_manual_search_helper.py", "miniapp", "none", True, False),
    StageSpec("fingerprint_deepening", "fingerprint_deepening.py", "analysis", "none", True, False),
    StageSpec("second_pass_triage", "second_pass_triage.py", "triage", "medium", False, True),
    StageSpec("review_intelligence", "review_intelligence.py", "analysis", "none", True, False),
    StageSpec("wechat_miniapp", "wechat_miniapp_discovery.py", "miniapp", "low", False, True),
    StageSpec("evidence_builder", "evidence_builder.py", "reporting", "none", True, False),
    StageSpec("idor_diff", "idor_triage.py", "triage", "medium", False, True),
)

STAGE_REGISTRY: dict[str, StageSpec] = {spec.name: spec for spec in _STAGE_SPECS}
STAGE_SCRIPTS: dict[str, str] = {name: spec.script for name, spec in STAGE_REGISTRY.items()}


def stage_spec(name: str) -> StageSpec:
    """Return immutable metadata for a registered stage."""
    try:
        return STAGE_REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"unknown runner stage: {name}") from exc


def stage_script(root: Path, name: str) -> Path:
    """Resolve a registered stage script below the repository root."""
    return root / stage_spec(name).script


def stages(*, category: str | None = None, offline: bool | None = None) -> tuple[StageSpec, ...]:
    """List registered stages, optionally filtered by category or offline mode."""
    result = _STAGE_SPECS
    if category is not None:
        result = tuple(spec for spec in result if spec.category == category)
    if offline is not None:
        result = tuple(spec for spec in result if spec.offline is offline)
    return result
