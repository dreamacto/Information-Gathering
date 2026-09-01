"""Pure, fail-closed verification of an orchestration phase snapshot.

This module deliberately does not read or write files.  Callers provide the graph,
phase cursor snapshot and (optionally) result references already loaded by a
trusted boundary.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .graph import GraphSpec
from .graph_validation import validate_graph
from .worker_context import CURSOR_FILES


def _data(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, GraphSpec):
        return value.to_dict()
    return value if isinstance(value, Mapping) else None


def _cursor(workflow: Any) -> str | None:
    return CURSOR_FILES.get(workflow)


def validate_phase_state(
    graph: GraphSpec | Mapping[str, Any],
    phase_status: Mapping[str, Any],
    *,
    expected_phase: str | None = None,
    references: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[str]:
    """Return all violations; malformed input is never accepted as valid."""
    errors: list[str] = []
    graph_data = _data(graph)
    if graph_data is None:
        return ["graph must be an object"]
    errors.extend(f"graph: {e}" for e in validate_graph(graph))
    if not isinstance(phase_status, Mapping):
        return errors + ["phase_status must be an object"]
    workflow = graph_data.get("workflow")
    wanted_cursor = _cursor(workflow)
    if wanted_cursor is None:
        errors.append("workflow is invalid")
    for field in ("workflow", "phase", "status"):
        if field not in phase_status:
            errors.append(f"missing phase field: {field}")
    if phase_status.get("workflow") != workflow:
        errors.append("phase workflow mismatch")
    status_cursor = phase_status.get("status_file", phase_status.get("cursor_file"))
    if status_cursor != wanted_cursor:
        errors.append("workflow/status_file isolation violation")
    if phase_status.get("assessment_id") is not None and phase_status.get("assessment_id") != graph_data.get("assessment_id"):
        errors.append("assessment_id mismatch")
    phase = phase_status.get("phase")
    if expected_phase is not None and phase != expected_phase:
        errors.append("phase mismatch")
    nodes = [n for n in graph_data.get("nodes", []) if isinstance(n, Mapping)]
    phase_nodes = [n for n in nodes if n.get("phase") == phase]
    if not phase_nodes:
        errors.append("phase is not present in graph")
    by_id = {n.get("node_id"): n for n in nodes}
    completed = phase_status.get("completed_task_ids", phase_status.get("completed", []))
    if not isinstance(completed, (list, tuple, set)) or not all(isinstance(x, str) and x for x in completed):
        errors.append("completed_task_ids must be a list of strings")
        completed_set: set[str] = set()
    else:
        completed_set = set(completed)
    state = phase_status.get("statuses", {})
    if state is not None and not isinstance(state, Mapping):
        errors.append("statuses must be an object")
        state = {}
    for node in phase_nodes:
        node_id = node.get("node_id")
        if node_id not in completed_set and state.get(node_id) not in {"complete", "completed", "succeeded", "success", "ok"}:
            errors.append(f"phase node not complete: {node_id}")
        for edge in graph_data.get("edges", []):
            if not isinstance(edge, Mapping) or edge.get("to") != node_id:
                continue
            predecessor = edge.get("from")
            pred = by_id.get(predecessor)
            if pred and pred.get("phase") != phase and predecessor not in completed_set and state.get(predecessor) not in {"complete", "completed", "succeeded", "success", "ok"}:
                errors.append(f"prerequisite not complete: {predecessor}")
    refs = phase_status.get("result_refs", phase_status.get("references", []))
    if refs is not None and not isinstance(refs, (list, tuple, Mapping)):
        errors.append("result_refs must be a list or object")
    if references is not None:
        if not isinstance(references, Mapping):
            errors.append("references must be an object")
        elif isinstance(refs, Mapping):
            for key, result_id in refs.items():
                if not isinstance(result_id, str) or result_id not in references:
                    errors.append(f"missing referenced result: {key}")
        elif isinstance(refs, (list, tuple)):
            for result_id in refs:
                if not isinstance(result_id, str) or result_id not in references:
                    errors.append(f"missing referenced result: {result_id}")
    return list(dict.fromkeys(errors))


def verify_phase(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Return a sanitized decision object suitable for a control-plane gate."""
    errors = validate_phase_state(*args, **kwargs)
    return {"status": "verified" if not errors else "blocked", "verified": not errors, "errors": errors}


validate = validate_phase_state
verify = verify_phase
