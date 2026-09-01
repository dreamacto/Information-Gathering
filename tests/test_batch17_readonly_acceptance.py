"""Batch 17 read-only acceptance checks for the completed implementation."""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str, root: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def test_final_acceptance_entrypoints_and_progress_are_present():
    assert (ROOT / "scripts" / "verify_offline.py").is_file()
    assert (ROOT / "scripts" / "maintenance" / "validate_run_contracts.py").is_file()
    assert (ROOT / "scripts" / "maintenance" / "validate_finding_quality.py").is_file()
    progress = json.loads((ROOT / "implementation_progress.json").read_text(encoding="utf-8"))
    assert progress["overall_status"] in {"PASS", "PARTIAL", "FAIL", "BLOCKED"}
    batches = progress["batch_results"]
    assert [item["batch"] for item in batches] == [f"batch_{i}" for i in range(18)]
    assert all(item["status"] == "passed" for item in batches)
    assert progress["pending_items"] == []
    assert progress["blocked_items"] == []
    assert progress["overall_status"] == "PASS"


def test_validators_have_successful_machine_readable_output():
    for script in (
        "scripts/maintenance/validate_run_contracts.py",
        "scripts/maintenance/validate_finding_quality.py",
    ):
        plain = _run(script)
        assert plain.returncode == 0, plain.stdout + plain.stderr
        report = _run(script, "--json")
        assert report.returncode == 0, report.stdout + report.stderr
        payload = json.loads(report.stdout)
        assert payload["ok"] is True
        assert payload["violations"] == []


def test_offline_verifier_has_successful_json_output():
    result = _run("scripts/verify_offline.py", "--compile-only", "--json")
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    checks = {item["name"]: item for item in payload["checks"]}
    assert {"compile", "skill-drift", "doc-drift"} <= checks.keys()
    assert all(checks[name]["ok"] is True for name in ("compile", "skill-drift", "doc-drift"))


def test_final_acceptance_prompt_uses_real_paths_and_full_batch_table():
    prompt = (ROOT / "prompts" / "全部Batch完成后_统一只读检查.md").read_text(encoding="utf-8")
    assert "scripts/verify_offline.py" in prompt
    assert "tests/test_batch17_readonly_acceptance.py" in prompt
    for number in range(18):
        assert f"Batch {number}" in prompt
    assert "unique_test_paths" in prompt
    assert "cross_batch_reuse_count" in prompt
    assert "replacement_confidence" in prompt
    assert "partial" in prompt
    assert "不要修改代码" in prompt or "不得修改代码" in prompt
    assert "不要删除、移动、覆盖或清理任何成果" in prompt or "不得删除、移动、覆盖或清理任何成果" in prompt


def test_batch17_test_is_read_only_and_does_not_use_network_or_destructive_calls():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not (imported & {"requests", "urllib", "socket", "httpx"})
    calls = [
        node.func
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    ]
    destructive = {
        (node.value.id if isinstance(node.value, ast.Name) else None, node.attr)
        for node in calls
        if isinstance(node, ast.Attribute)
    }
    assert ("shutil", "rmtree") not in destructive
    assert ("os", "remove") not in destructive
