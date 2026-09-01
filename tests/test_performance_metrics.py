import hashlib

import pytest

from authorized_assessment.analysis.performance_metrics import (
    aggregate_metrics,
    build_metric_event,
    deduplicate_events,
    validate_metric_event,
)

H = "a" * 64
W = {"start": "2026-09-01T00:00:00+00:00", "end": "2026-09-01T01:00:00+00:00"}
R = [{"path": "metrics.json", "sha256": H}]


def event(i, value, *, quality="VALID", unit="count", dedup_key=None, created_at=None):
    return build_metric_event(metric_event_id=f"metric_{i}", metric_name="requests", value=value, unit=unit,
                              dimensions={"assessment_id": "a1"}, window=W, source_refs=R,
                              quality_status=quality, dedup_key=dedup_key, created_at=created_at)


def test_build_and_validate_schema_shaped_event():
    row = event("1", 3)
    assert validate_metric_event(row) == []
    assert row["unit"] == "count"


def test_invalid_target_and_sensitive_fields_fail_closed():
    row = event("2", 1)
    row["dimensions"]["target"] = "example.invalid"
    errors = validate_metric_event(row)
    assert errors
    with pytest.raises(ValueError):
        build_metric_event(metric_event_id="metric_bad", metric_name="x", value=1, unit="count",
                           dimensions={"target": "plain-target"}, window=W, source_refs=R)


def test_dedup_keeps_latest_attempt():
    old = event("old", 1, dedup_key="same", created_at="2026-09-01T00:00:00+00:00")
    new = event("new", 2, dedup_key="same", created_at="2026-09-01T00:01:00+00:00")
    assert deduplicate_events([old, new]) == [new]


def test_aggregate_ratio_latency_and_unknown():
    rows = [event("a", 0.5, unit="ratio"), event("b", 1.0, unit="ratio"),
            event("c", 2, unit="seconds"), event("d", "N/A", quality="UNKNOWN")]
    result = aggregate_metrics(rows)
    assert result["events_seen"] == 4
    assert result["unknown_events"] == 1
    assert result["metrics"]["requests"]["ratio"] == 0.75
    assert result["metrics"]["requests"]["latency_seconds"] == 2.0
