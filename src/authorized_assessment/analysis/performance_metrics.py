"""Offline metric-event construction and aggregation.

The module deliberately handles metadata only.  Target, credential, session and
raw response values are rejected; target identity is represented by a SHA-256
reference in ``dimensions.target_ref_hash``.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import math
from typing import Any, Iterable, Mapping

UNITS = frozenset(("count", "ratio", "seconds", "boolean", "text"))
QUALITY = frozenset(("VALID", "PARTIAL", "INCONCLUSIVE", "FAILED", "BLOCKED", "UNKNOWN"))
_DIMENSIONS = frozenset(("assessment_id", "workflow", "phase", "target_ref_hash"))
_FORBIDDEN = ("target", "credential", "cookie", "password", "passwd", "secret", "session", "raw", "authorization", "token")


def _iso(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _sensitive_paths(value: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            p = f"{path}.{key}" if path else str(key)
            key_text = str(key).lower()
            # target_ref_hash is the explicitly permitted target representation.
            if key_text != "target_ref_hash" and any(fragment in key_text for fragment in _FORBIDDEN):
                hits.append(p)
            hits.extend(_sensitive_paths(child, p))
    elif isinstance(value, (list, tuple)):
        for i, child in enumerate(value):
            hits.extend(_sensitive_paths(child, f"{path}[{i}]"))
    return hits


def validate_metric_event(event: Any) -> list[str]:
    """Validate the dependency-free subset of ``metric_event_schema.json``."""
    if not isinstance(event, Mapping):
        return ["metric event must be an object"]
    errors: list[str] = []
    required = ("metric_event_id", "metric_name", "value", "unit", "dimensions", "window", "source_refs", "quality_status", "created_at")
    errors.extend(f"missing required field: {name}" for name in required if name not in event)
    if errors:
        return errors
    if not isinstance(event["metric_event_id"], str) or not event["metric_event_id"].startswith("metric_"):
        errors.append("metric_event_id is invalid")
    if not isinstance(event["metric_name"], str) or not event["metric_name"].strip():
        errors.append("metric_name must be a non-empty string")
    if event["unit"] not in UNITS:
        errors.append("unit is invalid")
    if event["quality_status"] not in QUALITY:
        errors.append("quality_status is invalid")
    dimensions = event["dimensions"]
    if not isinstance(dimensions, Mapping):
        errors.append("dimensions must be an object")
    else:
        unknown = set(dimensions) - _DIMENSIONS
        errors.extend(f"dimensions has unsupported field: {key}" for key in sorted(unknown))
        if "target_ref_hash" in dimensions and not _hash(dimensions["target_ref_hash"]):
            errors.append("target_ref_hash must be a lowercase SHA-256 hex digest")
    window = event["window"]
    if not isinstance(window, Mapping) or not _iso(window.get("start")) or not _iso(window.get("end")):
        errors.append("window.start and window.end must be ISO date-times")
    elif datetime.fromisoformat(window["start"].replace("Z", "+00:00")) > datetime.fromisoformat(window["end"].replace("Z", "+00:00")):
        errors.append("window.start must not be after window.end")
    refs = event["source_refs"]
    if not isinstance(refs, list):
        errors.append("source_refs must be a list")
    else:
        for i, ref in enumerate(refs):
            if not isinstance(ref, Mapping) or not isinstance(ref.get("path"), str) or not _hash(ref.get("sha256")):
                errors.append(f"source_refs[{i}] must contain path and lowercase sha256")
    if not _iso(event["created_at"]):
        errors.append("created_at must be an ISO date-time")
    if "dedup_key" in event and event["dedup_key"] is not None and not isinstance(event["dedup_key"], str):
        errors.append("dedup_key must be a string or null")
    if "retry_of" in event and event["retry_of"] is not None and not isinstance(event["retry_of"], str):
        errors.append("retry_of must be a string or null")
    for path in _sensitive_paths(event):
        errors.append(f"sensitive field is forbidden: {path}")
    return errors


def build_metric_event(*, metric_event_id: str, metric_name: str, value: Any, unit: str,
                       dimensions: Mapping[str, Any] | None = None,
                       window: Mapping[str, str], source_refs: Iterable[Mapping[str, str]] = (),
                       quality_status: str = "UNKNOWN", created_at: str | None = None,
                       dedup_key: str | None = None, retry_of: str | None = None,
                       coverage_status: str | None = None) -> dict[str, Any]:
    """Build and validate one schema-shaped metric event."""
    event = {"metric_event_id": metric_event_id, "metric_name": metric_name, "value": value,
             "unit": unit, "dimensions": dict(dimensions or {}), "window": dict(window),
             "source_refs": [dict(ref) for ref in source_refs], "quality_status": quality_status,
             "created_at": created_at or datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if dedup_key is not None: event["dedup_key"] = dedup_key
    if retry_of is not None: event["retry_of"] = retry_of
    if coverage_status is not None: event["coverage_status"] = coverage_status
    errors = validate_metric_event(event)
    if errors: raise ValueError("metric event rejected: " + "; ".join(errors))
    return event


def deduplicate_events(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate by dedup_key, keeping the latest created attempt."""
    chosen: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for raw in events:
        event = dict(raw)
        key = event.get("dedup_key") or event.get("metric_event_id")
        if key not in chosen: order.append(key)
        if key not in chosen or str(event.get("created_at", "")) >= str(chosen[key].get("created_at", "")):
            chosen[key] = event
    return [chosen[key] for key in order]


def _number(value: Any) -> float | None:
    if isinstance(value, bool): return float(value)
    if isinstance(value, (int, float)) and math.isfinite(value): return float(value)
    try:
        result = float(value)
        return result if math.isfinite(result) else None
    except (TypeError, ValueError): return None


def aggregate_metrics(events: Iterable[Mapping[str, Any]], *, deduplicate: bool = True) -> dict[str, Any]:
    """Aggregate counts, ratios, latency and explicit unknowns by metric name."""
    rows = deduplicate_events(events) if deduplicate else [dict(e) for e in events]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows: groups[str(row.get("metric_name", ""))].append(row)
    result: dict[str, Any] = {"events_seen": len(rows), "metrics": {}, "unknown_events": 0}
    for name, items in sorted(groups.items()):
        by_unit: dict[str, list[float]] = defaultdict(list)
        for item in items:
            number = _number(item.get("value"))
            if number is not None:
                by_unit[str(item.get("unit"))].append(number)
        nums = [number for values in by_unit.values() for number in values]
        unknown = sum(1 for x in items if x.get("quality_status") == "UNKNOWN" or _number(x.get("value")) is None)
        data: dict[str, Any] = {"count": len(items), "unknown": unknown, "quality_statuses": sorted({str(x.get("quality_status")) for x in items})}
        if nums:
            data.update({"sum": round(sum(nums), 6), "min": min(nums), "max": max(nums), "average": round(sum(nums) / len(nums), 6)})
        ratios = by_unit.get("ratio", [])
        latencies = by_unit.get("seconds", [])
        if ratios: data["ratio"] = round(sum(ratios) / len(ratios), 6)
        if latencies: data["latency_seconds"] = round(sum(latencies) / len(latencies), 6)
        result["metrics"][name] = data
        result["unknown_events"] += unknown
    return result


def aggregate_metric_events(events: Iterable[Mapping[str, Any]], **kwargs: Any) -> dict[str, Any]:
    return aggregate_metrics(events, **kwargs)


def make_metric_event(**kwargs: Any) -> dict[str, Any]:
    return build_metric_event(**kwargs)


def validate(event: Any) -> list[str]:
    return validate_metric_event(event)
