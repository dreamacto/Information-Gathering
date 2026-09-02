"""Fan-in aggregation over branch statuses."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Mapping
from .graph_barriers import evaluate_barrier

@dataclass(frozen=True)
class FanInResult:
    status: str
    ready: bool
    reason: str
    successful: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    operator_tasks: tuple[str, ...] = ()


def collect_branches(join: str, expected: Iterable[str], statuses: Mapping[str, str]) -> FanInResult:
    decision = evaluate_barrier(join, expected, statuses)
    tasks: list[str] = []
    if decision.status in {"blocked", "failed", "timeout", "cancelled"}:
        tasks.append(f"manual_review:{decision.reason}")
    return FanInResult(decision.status, decision.ready, decision.reason,
                       decision.successful, decision.missing, decision.failed, tuple(tasks))

fan_in = collect_branches
__all__ = ["FanInResult", "collect_branches", "fan_in"]
