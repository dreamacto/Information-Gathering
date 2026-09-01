"""报告生命周期五态统一测试（实施规格 684-694 行；batch1_2）。

覆盖：accepted_report 退场、五态可标记、契约层与模块常量无漂移。
"""
from __future__ import annotations

import json
from pathlib import Path

import run_lifecycle

ROOT = Path(__file__).resolve().parents[1]


def test_accepted_report_is_no_longer_a_manual_state():
    assert "accepted_report" not in run_lifecycle.MANUAL_STATES


def test_five_report_lifecycle_states_are_manual_marks():
    assert set(run_lifecycle.REPORT_LIFECYCLE_STATES) <= run_lifecycle.MANUAL_STATES
    assert len(run_lifecycle.REPORT_LIFECYCLE_STATES) == 5


def test_report_states_can_be_marked_and_derived(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    manual_path = run_dir / "run_lifecycle.manual.json"
    manual_path.write_text(
        json.dumps({"states": ["report_generated", "report_reviewed"]}), encoding="utf-8"
    )
    info = run_lifecycle.derive(run_dir)
    assert "report_generated" in info["states"]
    assert "report_reviewed" in info["states"]
    assert "accepted_report" not in info["states"]


def test_mark_argument_choices_track_manual_states():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--mark", choices=sorted(run_lifecycle.MANUAL_STATES))
    args, _ = parser.parse_known_args(["--mark", "report_superseded"])
    assert args.mark == "report_superseded"
    try:
        parser.parse_known_args(["--mark", "accepted_report"])
        raised = False
    except SystemExit:
        raised = True
    assert raised, "accepted_report must be rejected by CLI choices"


def test_workflow_schema_registers_state_models_without_drift():
    schema = json.loads((ROOT / "contracts" / "workflow_schema.json").read_text(encoding="utf-8"))
    assert schema["report_lifecycle_states"] == list(run_lifecycle.REPORT_LIFECYCLE_STATES)
    quality_schema = json.loads(
        (ROOT / "contracts" / "run_quality_schema.json").read_text(encoding="utf-8")
    )
    assert schema["quality_status_states"] == list(quality_schema["quality_status_states"])


def test_manual_state_vocabulary_has_no_legacy_report_state():
    legacy = {"accepted_report", "report_done", "report_final"}
    assert not (legacy & run_lifecycle.MANUAL_STATES)
