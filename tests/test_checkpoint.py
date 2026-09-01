from __future__ import annotations

import json
from pathlib import Path

import pytest

from authorized_assessment.runtime.checkpoint import load_checkpoint, save_checkpoint, validate_checkpoint


def checkpoint(seq=0, workflow="wz", **extra):
    value = {"checkpoint_id": "checkpoint_demo", "assessment_id": "asmt", "task_id": "task", "workflow": workflow, "phase": "scope", "cursor_kind": "phase", "status_file": "phase_status.miniapp.json" if workflow == "xcx" else "phase_status.json", "sequence": seq, "status": "running", "updated_at": "2026-09-01T00:00:00+00:00", "completed_task_ids": [], "pending_task_ids": ["task"], "blocked_task_ids": [], "failed_task_ids": [], "attempt": 1, "last_event_id": None, "last_result_id": None, "cancel_requested": False}
    value.update(extra)
    return value


def test_atomic_monotonic_save_and_load(tmp_path: Path):
    path = tmp_path / "phase_status.json"
    save_checkpoint(path, checkpoint())
    assert load_checkpoint(path)["sequence"] == 0
    save_checkpoint(path, checkpoint(1, status="complete"))
    assert load_checkpoint(path)["status"] == "complete"
    with pytest.raises(ValueError): save_checkpoint(path, checkpoint(1))
    with pytest.raises(ValueError): save_checkpoint(path, checkpoint(0))


def test_wz_xcx_status_file_isolation_and_path_match(tmp_path: Path):
    with pytest.raises(ValueError): save_checkpoint(tmp_path / "phase_status.json", checkpoint(workflow="xcx"))
    with pytest.raises(ValueError): save_checkpoint(tmp_path / "phase_status.miniapp.json", checkpoint(workflow="wz"))
    path = tmp_path / "phase_status.miniapp.json"
    save_checkpoint(path, checkpoint(workflow="xcx"))
    assert load_checkpoint(path)["workflow"] == "xcx"


def test_checkpoint_rejects_sensitive_and_invalid_input(tmp_path: Path):
    with pytest.raises(ValueError): save_checkpoint(tmp_path / "phase_status.json", checkpoint(cookie="x"))
    with pytest.raises(ValueError): save_checkpoint(tmp_path / "phase_status.json", checkpoint(sequence=True))
    assert validate_checkpoint({"workflow": "xcx", "status_file": "phase_status.json"})


def test_invalid_existing_checkpoint_fails_closed(tmp_path: Path):
    path = tmp_path / "phase_status.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(RuntimeError): save_checkpoint(path, checkpoint())


def test_fh_checkpoint_uses_run_status_file():
    value = checkpoint(workflow="fh", status_file="run_status.json", cursor_kind="recovery", status="blocked")
    assert validate_checkpoint(value) == []
