from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

TERMINAL_STATUSES = frozenset({"succeeded", "failed", "blocked", "cancelled", "timeout", "timed_out", "permission_denied"})
SUCCESS_STATUSES = frozenset({"succeeded", "success", "ok", "completed"})


@dataclass(frozen=True)
class BarrierDecision:
    status: str
    ready: bool
    reason: str
    successful: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()

    @property
    def blocked(self) -> bool:
        return not self.ready


def evaluate_barrier(join: str, expected: Iterable[str], statuses: Mapping[str, str]) -> BarrierDecision:
    expected_ids = tuple(sorted(str(item) for item in expected))
    observed_ids = tuple(str(item) for item in statuses)
    duplicates = len(observed_ids) != len(set(observed_ids))
    if join not in {"all", "any", "barrier"}:
        return BarrierDecision("blocked", False, f"invalid join: {join}")
    if duplicates:
        return BarrierDecision("blocked", False, "duplicate status")
    missing = tuple(item for item in expected_ids if item not in statuses)
    failed = tuple(item for item in expected_ids if item in statuses and statuses[item] not in SUCCESS_STATUSES and statuses[item] in TERMINAL_STATUSES)
    unknown = tuple(item for item in expected_ids if item in statuses and statuses[item] not in SUCCESS_STATUSES and statuses[item] not in TERMINAL_STATUSES)
    successful = tuple(item for item in expected_ids if item in statuses and statuses[item] in SUCCESS_STATUSES)
    if unknown:
        return BarrierDecision("blocked", False, "non-terminal status", successful, missing, failed)
    if any(statuses.get(item) in {"timeout", "timed_out"} for item in expected_ids):
        return BarrierDecision("timeout", False, "timeout observed", successful, missing, failed)
    if any(statuses.get(item) == "cancelled" for item in expected_ids):
        return BarrierDecision("cancelled", False, "cancelled branch", successful, missing, failed)
    if any(statuses.get(item) == "permission_denied" for item in expected_ids):
        return BarrierDecision("blocked", False, "permission denied", successful, missing, failed)
    if join == "any":
        if successful:
            return BarrierDecision("ready", True, "one branch succeeded", successful, missing, failed)
        if not missing and failed:
            return BarrierDecision("failed", False, "all branches failed", successful, missing, failed)
        return BarrierDecision("blocked", False, "waiting for one successful branch", successful, missing, failed)
    if failed:
        return BarrierDecision("failed", False, "failed branch", successful, missing, failed)
    if missing:
        return BarrierDecision("blocked", False, "missing branches", successful, missing, failed)
    return BarrierDecision("ready", True, "all branches reached success", successful, missing, failed)


def barrier_ready(join: str, expected: Iterable[str], statuses: Mapping[str, str]) -> bool:
    return evaluate_barrier(join, expected, statuses).ready


def evaluate(join: str, expected: Iterable[str], statuses: Mapping[str, str]) -> BarrierDecision:
    return evaluate_barrier(join, expected, statuses)
