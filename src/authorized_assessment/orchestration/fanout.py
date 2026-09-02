"""Deterministic fan-out helpers; payloads remain reference-only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Mapping

from .task_envelope import idempotency_key

@dataclass(frozen=True)
class BranchSpec:
    branch_id: str
    parent_id: str
    correlation_id: str
    idempotency_key: str
    target_ref: Mapping[str, str] | None = None


def expand_branches(parent_id: str, branch_ids: Iterable[str], *, correlation_id: str,
                    workflow: str, cursor_file: str, target_refs: Mapping[str, Mapping[str, str]] | None = None) -> tuple[BranchSpec, ...]:
    if not parent_id or not correlation_id:
        raise ValueError("parent_id and correlation_id are required")
    expected = {"wz": "phase_status.json", "xcx": "phase_status.miniapp.json", "fh": "run_status.json"}
    if workflow not in expected or cursor_file != expected[workflow]:
        raise ValueError("workflow/cursor isolation violation")
    ids = tuple(sorted({str(item) for item in branch_ids if str(item)}))
    refs = target_refs or {}
    return tuple(BranchSpec(f"{parent_id}__{item}", parent_id, correlation_id,
                            idempotency_key(parent_id, item, correlation_id), refs.get(item)) for item in ids)

fan_out = expand_branches
__all__ = ["BranchSpec", "expand_branches", "fan_out"]
