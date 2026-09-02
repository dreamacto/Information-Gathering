"""Offline mini-program specialist worker manifests and handlers.

Handlers in this module consume only a sanitized :class:`WorkerContext` and
return queue-only results.  They never open sockets, read credential stores, or
mutate the control plane.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable

from .worker_context import WorkerContext
from .worker_manifest import WorkerManifest, build_manifest
from .worker_output_verifier import validate_worker_outputs as _validate_worker_outputs
from .worker_output_verifier import verify_worker_outputs as _verify_worker_outputs
from .worker_registry import WorkerRegistry
from .worker_result import ANALYST_FIELDS, build_result
from .xcx_graph import XCX_BRANCHES as XCX_PHASE_BRANCHES
from .xcx_graph import XCX_CURSOR_FILE, XCX_PHASES

# The eight specialist queues are the material-oriented fan-out used by the
# worker plan.  Graph control/structural phases use the same worker contract,
# but are not duplicated as plan branches.
XCX_BRANCHES = (
    "endpoint", "auth_token", "local_data", "crypto", "webview", "cloud",
    "third_party", "static_dynamic_reconciliation",
)
XCX_REVIEW_BRANCHES = XCX_BRANCHES

_SENSITIVE = (
    "cookie", "token", "authorization", "password", "secret", "session",
    "har", "raw", "credential", "api_key",
)

# Every graph phase has an explicit Code/Analyst/Verifier binding.  The eight
# review queues additionally expose their short queue names for plan builders.
XCX_PHASE_WORKERS = {
    phase: (
        f"worker_xcx_{phase}_code",
        f"worker_xcx_{phase}_analyst",
        f"worker_xcx_{phase}_verifier",
    )
    for phase in XCX_PHASES
}


def _result_id(worker_id: str, context: WorkerContext) -> str:
    return f"result_{worker_id.removeprefix('worker_')}_{context.phase}"


def _safe(value: Any, path: str = "value") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if any(part in str(key).lower().replace("-", "_") for part in _SENSITIVE):
                raise ValueError(f"sensitive value rejected: {path}.{key}")
            _safe(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple, set)):
        for i, item in enumerate(value):
            _safe(item, f"{path}[{i}]")
    elif isinstance(value, str):
        low = value.lower()
        if any(f"{part}=" in low or f"{part}:" in low for part in _SENSITIVE):
            raise ValueError(f"sensitive value rejected: {path}")


def _phase(context: WorkerContext) -> str:
    if context.phase not in XCX_PHASES:
        raise ValueError(f"unsupported XCX phase: {context.phase}")
    return context.phase


def _base_result(context: WorkerContext, worker_id: str) -> dict[str, Any]:
    phase = _phase(context)
    facts = [str(item) for item in context.facts]
    not_tested = [str(item) for item in context.not_tested]
    refs = [dict(ref) for ref in context.source_refs]
    _safe((facts, context.coverage, not_tested, refs))
    return {
        "workflow": "xcx",
        "cursor_file": XCX_CURSOR_FILE,
        "phase": phase,
        "facts": facts,
        "coverage": dict(context.coverage),
        "not_tested": not_tested,
        "artifact_refs": refs,
        "finding_status": "candidate",
        "operator_hints": ["queue_only", "offline_only", "no_live_requests", "manual_gate_preserved"],
    }


def make_handler(worker_id: str, worker_type: str = "code") -> Callable[[WorkerContext], dict[str, Any]]:
    """Create a deterministic, pure-offline Code, Analyst, or Verifier handler."""
    if worker_type not in {"code", "analyst", "verifier"}:
        raise ValueError("XCX handler type must be code, analyst, or verifier")

    def handler(context: WorkerContext) -> dict[str, Any]:
        if not isinstance(context, WorkerContext) or context.workflow != "xcx" or context.cursor_file != XCX_CURSOR_FILE:
            raise PermissionError("XCX worker requires phase_status.miniapp.json")
        base = _base_result(context, worker_id)
        if worker_type == "analyst":
            base.update({
                "facts_used": list(base["facts"]),
                "reasoning_summary": f"Offline XCX review for {context.phase}; only sanitized local evidence was consumed.",
                "alternative_explanations": ["surface may be absent", "package or artifact may be incomplete"],
                "hypotheses": [f"review {context.phase} from local artifacts only"],
                "unknowns": list(base["not_tested"]),
                "next_hints": ["keep candidate in queue", "require manual approval before any active action"],
            })
        elif worker_type == "verifier":
            # A verifier handler never invents a finding.  The actual dual gate
            # is evaluated by validate_xcx_worker_outputs after both inputs exist.
            base.update({
                "status": "needs_manual_validation",
                "finding_status": "inconclusive",
                "disposition": "needs_manual_validation",
                "operator_hints": ["dual_result_required", "manual_validation_required"],
            })
        return build_result(
            result_id=_result_id(worker_id, context),
            task_id=f"task_{context.phase}",
            worker_id=worker_id,
            worker_type=worker_type,
            assessment_id="assessment_xcx",
            correlation_id=f"corr_{context.phase}",
            **base,
        )

    return handler


def specialist_manifests() -> tuple[WorkerManifest, ...]:
    manifests = []
    for phase, worker_ids in XCX_PHASE_WORKERS.items():
        for worker_id in worker_ids:
            worker_type = worker_id.rsplit("_", 1)[-1]
            manifests.append(build_manifest(
                worker_id=worker_id,
                worker_type=worker_type,
                name=f"XCX {phase} {worker_type} specialist",
                capabilities=[phase, "offline", "queue_only"],
                input_allowlist=["WorkerContext", "structured_facts", "artifact_refs"],
                output_contracts=["xcx_worker_result_schema.json"],
                producer="施工表06",
            ))
    return tuple(manifests)


def register_specialists(registry: WorkerRegistry) -> tuple[WorkerManifest, ...]:
    manifests = specialist_manifests()
    for manifest in manifests:
        registry.register(manifest, make_handler(manifest.worker_id, manifest.worker_type))
    return manifests


def validate_specialist_payload(payload: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ["payload must be an object"]
    if payload.get("workflow") != "xcx" or payload.get("cursor_file") != XCX_CURSOR_FILE:
        errors.append("payload must be XCX-bound to phase_status.miniapp.json")
    if payload.get("phase") not in XCX_PHASES:
        errors.append("payload phase is not an XCX phase")
    refs = payload.get("artifact_refs")
    if not isinstance(refs, list) or any(not isinstance(ref, Mapping) or not ref for ref in refs):
        errors.append("artifact_refs must be a list of non-empty objects")
    if not isinstance(payload.get("facts"), list):
        errors.append("facts must be a list")
    if not isinstance(payload.get("coverage"), Mapping):
        errors.append("coverage must be an object")
    if not isinstance(payload.get("not_tested"), list):
        errors.append("not_tested must be a list")
    try:
        _safe(payload)
    except ValueError as exc:
        errors.append(str(exc))
    return list(dict.fromkeys(errors))


def validate_xcx_worker_outputs(*args: Any, **kwargs: Any) -> list[str]:
    """Verifier-facing dual-result validation helper."""
    return _validate_worker_outputs(*args, **kwargs)


def verify_xcx_worker_outputs(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Return a sanitized verifier gate decision for Code/Analyst results."""
    return _verify_worker_outputs(*args, **kwargs)


__all__ = [
    "ANALYST_FIELDS", "XCX_BRANCHES", "XCX_REVIEW_BRANCHES", "XCX_CURSOR_FILE",
    "XCX_PHASE_WORKERS", "make_handler", "specialist_manifests",
    "register_specialists", "validate_specialist_payload",
    "validate_xcx_worker_outputs", "verify_xcx_worker_outputs",
]
