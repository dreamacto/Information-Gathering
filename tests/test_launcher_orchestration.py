from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from authorized_assessment.orchestration import one_click_workflow as one_click
from authorized_assessment.orchestration import parallel_flow_runner as parallel


def _one_click_args(**overrides):
    values = dict(
        targets=Path("targets.txt"), mode="full", delay=3.0, limit=0,
        weak_max_targets=10, weak_max_pairs=5, sqli_limit=50,
        xss_limit=80, shiro_limit=30, second_pass_sql_limit=10,
        second_pass_xss_limit=20, second_pass_api_limit=20,
        header_sqli_limit=20, header_sqli_login_data=None,
        no_weak=True, no_xss=True, no_second_pass=True,
        no_review_intelligence=True, no_fingerprint_deepening=True,
        no_subdomain=True, no_tool_fingerprint=True, no_katana=True,
        miniapp_search_pack=False,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


def test_legacy_namespace_and_runner_command_remain_compatible():
    args = _one_click_args()
    command = one_click.runner_command(args)
    assert "--orchestration-mode" not in command
    assert "--probe" in command
    assert command[command.index("--label") + 1] == "one_click_full_weak"


def test_one_click_old_business_mode_is_independent_from_orchestration_mode():
    args = _one_click_args(mode="subdomains", orchestration_mode="graph_shadow")
    command = one_click.runner_command(args)
    assert "--subdomain-bruteforce" not in command
    assert "--orchestration-mode" in command
    assert command[command.index("--orchestration-mode") + 1] == "graph_shadow"
    assert command[command.index("--label") + 1] == "one_click_subdomains"


def test_one_click_shadow_gate_stops_before_subprocess(monkeypatch, capsys):
    args = _one_click_args(orchestration_mode="graph_shadow")
    monkeypatch.setattr(one_click, "parse_args", lambda: args)
    monkeypatch.setattr(one_click, "setup_console", lambda: None)
    called = []
    monkeypatch.setattr(one_click.subprocess, "Popen", lambda *a, **k: called.append((a, k)))
    assert one_click.main() == 0
    assert called == []
    payload = json.loads(capsys.readouterr().out)
    assert payload["orchestration_mode"] == "graph_shadow"
    assert payload["gate"]["status"] == "shadow"


def test_one_click_readonly_gate_stops_before_subprocess(monkeypatch):
    args = _one_click_args(orchestration_mode="graph_readonly")
    monkeypatch.setattr(one_click, "parse_args", lambda: args)
    monkeypatch.setattr(one_click, "setup_console", lambda: None)
    called = []
    monkeypatch.setattr(one_click.subprocess, "Popen", lambda *a, **k: called.append(1))
    assert one_click.main() == 3
    assert called == []


def test_parallel_plan_contains_mode_snapshot_without_launching(tmp_path, monkeypatch, capsys):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://a.example\nhttps://b.example\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "gov_exercise_runner.py").write_text("# offline fixture\n", encoding="utf-8")
    args = argparse.Namespace(
        targets=targets, workspace=workspace, runner_python=Path("python"),
        batch_size=300, batch_count=1, auto_batch=False, max_parallel=1,
        group_mode="host", label="test", delay=3.0, profile="readonly",
        max_runner_targets=500, stop_on_failure=False, plan_only=True,
        orchestration_mode="graph_readonly", poll_interval=0.01, runner_args=[],
    )
    monkeypatch.setattr(parallel, "parse_args", lambda: args)
    monkeypatch.setattr(parallel, "write_batch_files", parallel.write_batch_files)
    monkeypatch.setattr(parallel.subprocess, "Popen", lambda *a, **k: pytest.fail("plan-only launched subprocess"))
    assert parallel.main() == 0
    output = capsys.readouterr().out
    assert "graph_readonly" in output
    plans = list(workspace.glob("parallel_flow_batches_*/parallel_plan.json"))
    assert len(plans) == 1
    manifest = json.loads(plans[0].read_text(encoding="utf-8"))
    assert manifest["orchestration_mode"] == "graph_readonly"
    assert manifest["orchestration_snapshot_hash"]
    assert "--orchestration-mode" in manifest["runner_args"]


def test_parallel_shadow_does_not_launch_even_without_plan_only(tmp_path, monkeypatch, capsys):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://a.example\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "gov_exercise_runner.py").write_text("# offline fixture\n", encoding="utf-8")
    args = argparse.Namespace(
        targets=targets, workspace=workspace, runner_python=Path("python"),
        batch_size=300, batch_count=1, auto_batch=False, max_parallel=1,
        group_mode="host", label="test", delay=3.0, profile="readonly",
        max_runner_targets=500, stop_on_failure=False, plan_only=False,
        orchestration_mode="graph_shadow", poll_interval=0.01, runner_args=[],
    )
    monkeypatch.setattr(parallel, "parse_args", lambda: args)
    monkeypatch.setattr(parallel.subprocess, "Popen", lambda *a, **k: pytest.fail("shadow launched subprocess"))
    assert parallel.main() == 0
    assert "graph_shadow" in capsys.readouterr().out


def test_parallel_gate_rejection_returns_nonzero_without_process(tmp_path, monkeypatch):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://a.example\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "gov_exercise_runner.py").write_text("# offline fixture\n", encoding="utf-8")
    args = argparse.Namespace(
        targets=targets, workspace=workspace, runner_python=Path("python"),
        batch_size=300, batch_count=1, auto_batch=False, max_parallel=1,
        group_mode="host", label="test", delay=3.0, profile="readonly",
        max_runner_targets=500, stop_on_failure=False, plan_only=False,
        orchestration_mode="graph_active_approved", poll_interval=0.01, runner_args=[],
    )
    monkeypatch.setattr(parallel, "parse_args", lambda: args)
    monkeypatch.setattr(parallel.subprocess, "Popen", lambda *a, **k: pytest.fail("rejected mode launched subprocess"))
    assert parallel.main() == 3
