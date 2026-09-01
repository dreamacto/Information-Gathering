"""Safe structured worker errors and retry policy."""
from __future__ import annotations
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

ERROR_CLASSES = frozenset({"validation", "timeout", "cancelled", "permission_denied", "blocked", "scope_conflict", "transport", "dependency", "internal"})
NON_RETRYABLE = frozenset({"permission_denied", "blocked", "scope_conflict", "cancelled"})
_SENSITIVE = re.compile(r"(?i)(traceback|cookie|token|password|secret|authorization|raw[_ ]?response|\b(?:python|bash|cmd|powershell)\b)")

@dataclass(frozen=True)
class WorkerError:
    error_id: str
    error_class: str
    retryable: bool
    safe_reason: str
    task_id: str
    worker_id: str
    created_at: str
    event_id: str | None = None
    result_id: str | None = None
    redacted_detail: str | None = None
    operator_action: str | None = None
    def as_dict(self): return asdict(self)


def is_retryable(error_class: str) -> bool:
    return error_class in ERROR_CLASSES and error_class not in NON_RETRYABLE and error_class not in {"validation", "internal"}


def make_error(*, error_id: str, error_class: str, safe_reason: str, task_id: str, worker_id: str, redacted_detail: str | None = None, operator_action: str | None = None, event_id: str | None = None, result_id: str | None = None) -> WorkerError:
    if error_class not in ERROR_CLASSES: raise ValueError("invalid error class")
    for label, value in (("safe_reason", safe_reason), ("redacted_detail", redacted_detail), ("operator_action", operator_action)):
        if value is not None and (not isinstance(value, str) or _SENSITIVE.search(value)): raise ValueError(f"unsafe {label}")
    if not isinstance(error_id, str) or not error_id.startswith("error_"): raise ValueError("invalid error id")
    return WorkerError(error_id, error_class, is_retryable(error_class), safe_reason, task_id, worker_id, datetime.now(timezone.utc).isoformat(timespec="seconds"), event_id, result_id, redacted_detail, operator_action)


def from_exception(*, error_id: str, task_id: str, worker_id: str, exc: BaseException) -> WorkerError:
    return make_error(error_id=error_id, error_class="internal", safe_reason="worker execution failed", task_id=task_id, worker_id=worker_id, redacted_detail=type(exc).__name__)

validate = make_error
