"""Offline WZ specialist worker manifests and handlers."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable

from authorized_assessment.analysis.coverage_matrix import (
    APPLICATION_MAP_SUBPHASES,
    COVERAGE_SUBSTATUSES,
    validate_application_map_row,
)
from .worker_context import WorkerContext
from .worker_manifest import WorkerManifest, build_manifest
from .worker_registry import WorkerRegistry
from .worker_result import build_result
from .wz_routes import WZ_PHASE_WORKERS, validate_artifact_refs

ANALYST_FIELDS = ("facts_used", "reasoning_summary", "alternative_explanations", "hypotheses", "unknowns", "coverage", "not_tested", "next_hints")


def _result_id(worker_id: str, context: WorkerContext) -> str:
    return f"result_{worker_id.removeprefix('worker_')}_{context.phase}"


def _safe_facts(context: WorkerContext) -> list[str]:
    return [str(item) for item in context.facts]


def make_handler(worker_id: str, worker_type: str = "code") -> Callable[[WorkerContext], dict[str, Any]]:
    """Create a deterministic, offline handler; it never writes control-plane state."""
    def handler(context: WorkerContext) -> dict[str, Any]:
        if context.workflow != "wz" or context.cursor_file != "phase_status.json":
            raise PermissionError("WZ worker requires phase_status.json")
        facts = _safe_facts(context)
        base = {
            "workflow": "wz",
            "cursor_file": "phase_status.json",
            "facts": facts,
            "artifact_refs": [dict(ref) for ref in context.source_refs],
            "phase": context.phase,
            "subphase": context.phase if context.phase in APPLICATION_MAP_SUBPHASES else None,
            "coverage": dict(context.coverage),
            "not_tested": list(context.not_tested),
            "operator_hints": ["queue_only", "no_live_requests", "manual_gate_preserved"],
        }
        if worker_type == "analyst":
            base.update({
                "facts_used": facts,
                "reasoning_summary": f"Offline WZ planning for {context.phase}; no live target evidence consumed.",
                "alternative_explanations": ["surface may be absent", "source may be historical or incomplete"],
                "hypotheses": [f"review {context.phase} using current engagement evidence only"],
                "unknowns": list(context.not_tested),
                "next_hints": ["retain approval and phase cursor under control-plane ownership"],
            })
        return build_result(
            result_id=_result_id(worker_id, context),
            task_id=f"task_{context.phase}",
            worker_id=worker_id,
            worker_type=worker_type,
            assessment_id="assessment_wz",
            correlation_id=f"corr_{context.phase}",
            **base,
        )
    return handler


def specialist_manifests() -> tuple[WorkerManifest, ...]:
    manifests: list[WorkerManifest] = []
    for phase, workers in sorted(WZ_PHASE_WORKERS.items()):
        for worker_id in workers:
            worker_type = "analyst" if worker_id.endswith("_analyst") else "code"
            manifests.append(build_manifest(
                worker_id=worker_id,
                worker_type=worker_type,
                name=f"WZ {phase} specialist",
                capabilities=[phase, "offline", "queue_only"],
                input_allowlist=["WorkerContext", "structured_facts", "source_refs"],
                output_contracts=["wz_worker_result_schema.json", "worker_result_schema.json"],
                producer="施工表05",
            ))
    return tuple(manifests)


def register_specialists(registry: WorkerRegistry) -> tuple[WorkerManifest, ...]:
    manifests = specialist_manifests()
    for manifest in manifests:
        registry.register(manifest, make_handler(manifest.worker_id, manifest.worker_type))
    return manifests


def validate_specialist_payload(payload: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if payload.get("workflow") != "wz" or payload.get("cursor_file") != "phase_status.json":
        errors.append("payload must be WZ-bound to phase_status.json")
    errors.extend(validate_artifact_refs(payload.get("artifact_refs"), phase=payload.get("phase")))
    if payload.get("subphase") in APPLICATION_MAP_SUBPHASES:
        for row in payload.get("facts", ()):
            if isinstance(row, Mapping):
                errors.extend(validate_application_map_row(row, label=str(payload["subphase"])))
    return list(dict.fromkeys(errors))


__all__ = ["ANALYST_FIELDS", "make_handler", "specialist_manifests", "register_specialists", "validate_specialist_payload"]
