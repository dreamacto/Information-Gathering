"""Shared subprocess adapter for runner stages.

This module only standardizes local process execution and artifact logging. It
never chooses a stage, changes arguments, or performs network activity itself.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Sequence


def run_sync_stage(
    command: Sequence[str],
    *,
    cwd: Path,
    run_dir: Path,
    stage: str,
    error_artifact: str | None = None,
) -> subprocess.CompletedProcess:
    """Run one stage with the runner's legacy log names and error contract."""
    run_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / f"{stage}.out.log"
    stderr_path = run_dir / f"{stage}.err.log"
    with stdout_path.open("w", encoding="utf-8", errors="ignore") as stdout, stderr_path.open(
        "w", encoding="utf-8", errors="ignore"
    ) as stderr:
        process = subprocess.run(list(command), cwd=str(cwd), stdout=stdout, stderr=stderr)
    if process.returncode != 0 and error_artifact:
        from exercise_runtime import append_jsonl, now_iso

        append_jsonl(
            run_dir / error_artifact,
            {"checked_at": now_iso(), "returncode": process.returncode, "cmd": list(command)},
        )
    return process


def run_fake_worker_stage(executor, task, context, *, worker_id):
    """Run a registered offline worker without changing legacy subprocess behavior."""
    return executor.execute(task, context, worker_id=worker_id)
