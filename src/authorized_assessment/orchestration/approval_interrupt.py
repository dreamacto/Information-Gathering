"""Approval interrupt adapter for the two-key, fail-closed gate."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping

from .approval_verifier import verify_approval

@dataclass(frozen=True)
class ApprovalDecision:
    status: str
    approved: bool
    approval_required: bool
    reason: str
    violations: tuple[dict[str, str], ...] = ()

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"


def check_approval(*, approval: Mapping[str, Any] | None, policy_snapshot: Mapping[str, Any] | None,
                   required: bool = False, assessment_id: str | None = None,
                   phase: str | None = None, target_ref: Mapping[str, Any] | None = None,
                   seen_approval_ids: set[str] | None = None, stop_active: bool = False,
                   scope_confirmed: bool = True) -> ApprovalDecision:
    if not required:
        return ApprovalDecision("not_required", True, False, "approval not required")
    if approval is None:
        return ApprovalDecision("approval_required", False, True, "approval record is required")
    result = verify_approval(approval, policy_snapshot, assessment_id=assessment_id,
                             phase=phase, target_ref=target_ref,
                             seen_approval_ids=seen_approval_ids,
                             stop_active=stop_active, scope_confirmed=scope_confirmed)
    violations = tuple(result.get("violations", ()))
    if result.get("valid"):
        return ApprovalDecision("approved", True, False, "two-key approval accepted", violations)
    return ApprovalDecision("blocked", False, False, "approval rejected", violations)


def approval_gate(*args: Any, **kwargs: Any) -> ApprovalDecision:
    return check_approval(*args, **kwargs)

__all__ = ["ApprovalDecision", "check_approval", "approval_gate"]
