"""Offline append-only event journal with deterministic, safe replay."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

EVENT_TYPES = frozenset({
    "assessment.created", "task.created", "task.started", "task.completed",
    "worker.started", "worker.resulted", "checkpoint.saved", "approval.requested",
    "approval.decided", "verifier.decided", "metric.recorded", "task.cancelled",
    "task.failed",
})
STATUSES = frozenset({"accepted", "replayed", "rejected", "blocked"})
_ID = re.compile(r"^event_[A-Za-z0-9._-]+$")
_SENSITIVE = ("cookie", "token", "authorization", "session", "password", "passwd", "secret", "api_key", "apikey", "credential", "har", "raw_response", "response_body")
_SENSITIVE_VALUE = re.compile(r"(?i)(?:bearer\s+|basic\s+)[A-Za-z0-9+/=_-]+|(?:cookie|token|password|secret|authorization)\s*[:=]\s*\S+")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe(node: Any, path: str = "payload") -> None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            name = str(key).lower().replace("-", "_")
            if any(part in name for part in _SENSITIVE):
                raise ValueError(f"sensitive field rejected: {path}.{key}")
            _safe(value, f"{path}.{key}")
    elif isinstance(node, (list, tuple)):
        for i, value in enumerate(node):
            _safe(value, f"{path}[{i}]")
    elif isinstance(node, str) and _SENSITIVE_VALUE.search(node):
        raise ValueError(f"sensitive value rejected: {path}")


def validate_event(event: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(event, dict):
        return ["event must be a JSON object"]
    required = ("event_id", "event_type", "created_at", "producer", "correlation_id", "aggregate_id", "aggregate_sequence", "status", "summary")
    errors.extend(f"missing required field: {x}" for x in required if x not in event)
    if not isinstance(event.get("event_id"), str) or not _ID.fullmatch(event.get("event_id", "")):
        errors.append("event_id has invalid format")
    if event.get("event_type") not in EVENT_TYPES: errors.append("event_type is invalid")
    if not isinstance(event.get("aggregate_sequence"), int) or isinstance(event.get("aggregate_sequence"), bool) or event.get("aggregate_sequence", -1) < 0:
        errors.append("aggregate_sequence must be a non-negative integer")
    if event.get("status") not in STATUSES: errors.append("status is invalid")
    if not isinstance(event.get("summary"), str) or len(event.get("summary", "")) > 2000: errors.append("summary must be a string of at most 2000 characters")
    for key in ("producer", "correlation_id", "aggregate_id"):
        if not isinstance(event.get(key), str) or not event.get(key): errors.append(f"{key} must be a non-empty string")
    try: _safe(event)
    except ValueError as exc: errors.append(str(exc))
    return errors


class EventJournal:
    """A local JSONL journal. It never performs network or write-side replay."""
    def __init__(self, path: Path):
        self.path = Path(path)

    def read(self) -> list[dict[str, Any]]:
        try:
            if not self.path.exists(): return []
            rows = []
            with self.path.open("r", encoding="utf-8") as fh:
                for number, line in enumerate(fh, 1):
                    if not line.strip(): continue
                    row = json.loads(line)
                    errors = validate_event(row)
                    if errors: raise ValueError(f"invalid event at line {number}: {'; '.join(errors)}")
                    rows.append(row)
            self._check_order(rows)
            return rows
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"journal read failed closed: {self.path}") from exc

    @staticmethod
    def _check_order(rows: Iterable[dict[str, Any]]) -> None:
        seen_ids: set[str] = set(); keys: dict[tuple[str, str], int] = {}; idem: dict[str, str] = {}
        for row in rows:
            if row["event_id"] in seen_ids: raise ValueError("duplicate event_id")
            seen_ids.add(row["event_id"])
            key = row["aggregate_id"]
            previous = keys.get(key, -1)
            if row["aggregate_sequence"] <= previous: raise ValueError("aggregate sequence is not monotonic")
            keys[key] = row["aggregate_sequence"]
            if row.get("idempotency_key"):
                old = idem.setdefault(row["idempotency_key"], row["event_id"])
                if old != row["event_id"]: raise ValueError("idempotency key collision")

    def append(self, event: Mapping[str, Any]) -> dict[str, Any]:
        candidate = dict(event)
        errors = validate_event(candidate)
        if errors: raise ValueError("event rejected: " + "; ".join(errors))
        rows = self.read()
        idem = candidate.get("idempotency_key")
        if idem:
            for old in rows:
                if old.get("idempotency_key") == idem:
                    if {k: old.get(k) for k in candidate} != candidate: raise ValueError("idempotency key collision")
                    return {**old, "status": "replayed"}
        prior = [r["aggregate_sequence"] for r in rows if r["aggregate_id"] == candidate["aggregate_id"] and r["correlation_id"] == candidate["correlation_id"]]
        if candidate["aggregate_sequence"] != (max(prior, default=-1) + 1): raise ValueError("aggregate sequence must be next monotonic value")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                fh.flush(); os.fsync(fh.fileno())
        except OSError as exc: raise RuntimeError("journal append failed closed") from exc
        return candidate

    def replay(self, handler: Callable[[dict[str, Any]], Any] | None = None) -> list[dict[str, Any]]:
        rows = self.read(); result = []
        for row in rows:
            safe = dict(row); safe["status"] = "replayed"
            if handler is not None: handler(dict(safe))
            result.append(safe)
        return result


def append_event(path: Path, event: Mapping[str, Any]) -> dict[str, Any]:
    return EventJournal(path).append(event)
