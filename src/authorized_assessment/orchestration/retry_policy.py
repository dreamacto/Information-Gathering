"""Fail-closed retry decisions for local orchestration."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping

from .worker_errors import is_retryable

TERMINAL = frozenset({"failed", "blocked", "cancelled", "timeout"})

@dataclass(frozen=True)
class RetryDecision:
    action: str
    retry: bool
    status: str
    reason: str
    next_attempt: int | None = None

    @property
    def terminal(self) -> bool:
        return not self.retry


def decide_retry(*, error: Mapping[str, Any] | None = None, error_class: str | None = None,
                 attempt: int = 1, retry_limit: int = 0, cancel_requested: bool = False,
                 stop_active: bool = False) -> RetryDecision:
    """Return a conservative retry decision; never retries control-plane stops."""
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        return RetryDecision("blocked", False, "blocked", "invalid attempt")
    if isinstance(retry_limit, bool) or not isinstance(retry_limit, int) or retry_limit < 0:
        return RetryDecision("blocked", False, "blocked", "invalid retry limit")
    if cancel_requested or stop_active:
        reason = "cancellation requested" if cancel_requested else "kill switch active"
        return RetryDecision("blocked", False, "cancelled", reason)
    klass = error_class or (str(error.get("error_class")) if isinstance(error, Mapping) else "")
    if not klass:
        return RetryDecision("failed", False, "failed", "missing error class")
    if not is_retryable(klass):
        status = "cancelled" if klass == "cancelled" else ("blocked" if klass in {"blocked", "permission_denied", "scope_conflict"} else "failed")
        return RetryDecision("blocked" if status == "blocked" else "failed", False, status, f"error is not retryable: {klass}")
    if attempt > retry_limit:
        return RetryDecision("failed", False, "failed", "retry limit exhausted")
    return RetryDecision("retry", True, "pending", f"retryable error: {klass}", attempt + 1)


def should_retry(*args: Any, **kwargs: Any) -> bool:
    return decide_retry(*args, **kwargs).retry


def retry_decision(*args: Any, **kwargs: Any) -> RetryDecision:
    return decide_retry(*args, **kwargs)

__all__ = ["RetryDecision", "decide_retry", "retry_decision", "should_retry"]
