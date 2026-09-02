"""WZ specialist worker routing and safe artifact-scope checks."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .worker_context import CURSOR_FILES

WZ_WORKFLOW = "wz"
WZ_CURSOR_FILE = "phase_status.json"

WZ_PHASE_WORKERS: dict[str, tuple[str, ...]] = {
    "application_mapping": ("worker_wz_application_mapping",),
    "graphql_mapping": ("worker_wz_graphql_mapping",),
    "websocket_mapping": ("worker_wz_websocket_mapping",),
    "file_surface_mapping": ("worker_wz_file_surface_mapping",),
    "auth_surface_mapping": ("worker_wz_auth_surface_mapping",),
    "webhook_mapping": ("worker_wz_webhook_mapping",),
    "application_mapping_reconciliation": ("worker_wz_application_mapping_reconciliation",),
    "api_testing": ("worker_wz_api",),
    "product_triage": ("worker_wz_product",),
    "input_testing": ("worker_wz_input",),
    "evidence_review": ("worker_wz_evidence",),
}

_SPECIALIST_WORKERS = {
    "worker_wz_application_mapping",
    "worker_wz_graphql_mapping",
    "worker_wz_websocket_mapping",
    "worker_wz_file_surface_mapping",
    "worker_wz_auth_surface_mapping",
    "worker_wz_webhook_mapping",
    "worker_wz_application_mapping_reconciliation",
    "worker_wz_api",
    "worker_wz_product",
    "worker_wz_input",
    "worker_wz_evidence",
}

_FORBIDDEN_PARTS = {
    "runs", "postrun_review", "run_status.json", "phase_status.miniapp.json", "evidence/raw",
    "auth_sessions.local.json", "sessions.jsonl", "cookie", "token", "password", "secret",
    "session", "har", "raw", "credential",
}


@dataclass(frozen=True)
class WZRouteDecision:
    worker_ids: tuple[str, ...] = ()
    status: str = "ready"
    reason: str | None = None

    @property
    def ready(self) -> bool:
        return self.status == "ready"

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"


def allowed_workers(phase: str) -> tuple[str, ...]:
    return WZ_PHASE_WORKERS.get(str(phase), ())


def resolve_wz_route(
    phase: str,
    *,
    workflow: str = WZ_WORKFLOW,
    cursor_file: str = WZ_CURSOR_FILE,
    status: str = "ready",
) -> WZRouteDecision:
    if workflow != WZ_WORKFLOW:
        return WZRouteDecision(status="blocked", reason="WZ route requires workflow='wz'")
    if cursor_file != WZ_CURSOR_FILE or CURSOR_FILES.get(workflow) != cursor_file:
        return WZRouteDecision(status="blocked", reason="WZ route requires phase_status.json")
    if status in {"blocked", "failed", "cancelled", "timeout", "permission_denied", "approval_required"}:
        return WZRouteDecision(status="blocked", reason=f"phase status blocks worker dispatch: {status}")
    workers = allowed_workers(phase)
    if not workers:
        return WZRouteDecision(status="blocked", reason=f"no WZ worker route for phase: {phase}")
    return WZRouteDecision(worker_ids=workers)


def worker_allowed(phase: str, worker_id: str) -> bool:
    return worker_id in allowed_workers(phase) and worker_id in _SPECIALIST_WORKERS


def validate_artifact_ref(path: str, *, engagement_id: str | None = None, phase: str | None = None) -> list[str]:
    candidate = str(path or "").replace("\\", "/")
    low = candidate.lower()
    errors: list[str] = []
    if not candidate or candidate.startswith("/") or ":" in candidate[:3]:
        return ["artifact path must be a non-empty relative path"]
    if any(part in low for part in _FORBIDDEN_PARTS):
        errors.append("artifact path is outside WZ safe scope")
    if engagement_id and not candidate.startswith(f"engagements/{engagement_id}/"):
        errors.append("artifact path is outside current engagement")
    if phase and candidate.startswith("artifacts/") and phase not in low and "application-map" not in low:
        errors.append("artifact path is not bound to current phase")
    return errors


def validate_artifact_refs(refs: Any, *, engagement_id: str | None = None, phase: str | None = None) -> list[str]:
    if refs is None:
        return []
    if not isinstance(refs, (list, tuple)):
        return ["artifact_refs must be a list"]
    errors: list[str] = []
    for index, ref in enumerate(refs):
        path = ref.get("path") if isinstance(ref, Mapping) else ref
        errors.extend(f"artifact_refs[{index}]: {error}" for error in validate_artifact_ref(str(path or ""), engagement_id=engagement_id, phase=phase))
    return errors


route = resolve_wz_route
__all__ = ["WZ_PHASE_WORKERS", "WZRouteDecision", "allowed_workers", "resolve_wz_route", "worker_allowed", "validate_artifact_ref", "validate_artifact_refs", "route"]
