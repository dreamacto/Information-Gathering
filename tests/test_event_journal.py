from __future__ import annotations

import json
from pathlib import Path

import pytest

from authorized_assessment.runtime.event_journal import EventJournal, validate_event


def event(seq=0, **extra):
    value = {"event_id": f"event_demo_{seq}", "event_type": "task.started", "created_at": "2026-09-01T00:00:00+00:00", "producer": "test", "correlation_id": "corr", "aggregate_id": "task", "aggregate_sequence": seq, "status": "accepted", "summary": "safe"}
    value.update(extra)
    return value


def test_append_jsonl_sequence_and_idempotent_replay(tmp_path: Path):
    journal = EventJournal(tmp_path / "events.jsonl")
    assert journal.append(event()) ["aggregate_sequence"] == 0
    assert journal.append(event(1, idempotency_key="k1"))["aggregate_sequence"] == 1
    replay = journal.append(event(1, status="accepted", idempotency_key="k1"))
    assert replay["status"] == "replayed"
    assert len(journal.read()) == 2
    assert len((tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()) == 2


def test_event_rejects_sensitive_fields_values_and_bad_sequence(tmp_path: Path):
    journal = EventJournal(tmp_path / "events.jsonl")
    with pytest.raises(ValueError): journal.append(event(cookie="session=abc"))
    with pytest.raises(ValueError): journal.append(event(summary="Authorization: Bearer abc"))
    journal.append(event())
    with pytest.raises(ValueError): journal.append(event(2))
    assert validate_event({"event_id": "bad"})


def test_replay_calls_local_handler_only(tmp_path: Path):
    journal = EventJournal(tmp_path / "events.jsonl")
    journal.append(event())
    received = []
    result = journal.replay(received.append)
    assert result[0]["status"] == "replayed"
    assert received == result
