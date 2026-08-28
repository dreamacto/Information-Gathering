#!/usr/bin/env python3
"""Group-aware parallel launcher for gov_exercise_runner.py.

This script is an outer scheduler. It keeps each target group in one batch so
parallel workers do not hit the same root domain at the same time.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import argparse
import csv
import datetime as dt
import hashlib
import heapq
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


BASE_DIR = _ROOT
SECOND_LEVEL_SUFFIXES = {
    "ac.cn",
    "com.cn",
    "edu.cn",
    "gov.cn",
    "mil.cn",
    "net.cn",
    "org.cn",
}


@dataclass(frozen=True)
class TargetLine:
    raw: str
    url_part: str
    label: str
    host: str
    group_key: str


@dataclass
class TargetGroup:
    key: str
    lines: list[TargetLine] = field(default_factory=list)


@dataclass
class BatchPlan:
    index: int
    groups: list[TargetGroup] = field(default_factory=list)

    @property
    def count(self) -> int:
        return sum(len(group.lines) for group in self.groups)

    @property
    def group_keys(self) -> list[str]:
        return [group.key for group in self.groups]


@dataclass
class RunningBatch:
    plan: BatchPlan
    process: subprocess.Popen
    stdout_path: Path
    stderr_path: Path
    started_at: str
    command: list[str]


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def safe_label(value: str, limit: int = 48) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())[:limit].strip("._-")
    return cleaned or "batch"


def host_of(value: str) -> str:
    raw = value.strip().split("|", 1)[0].strip()
    if not raw or raw.startswith("#"):
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        return (urlparse(raw).hostname or "").strip(".").lower()
    except Exception:
        return ""


def registered_parent(host: str) -> str:
    host = host.strip(".").lower()
    if not host:
        return "unknown"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return host
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host
    suffix2 = ".".join(parts[-2:])
    if suffix2 in SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parse_target_line(line: str, group_mode: str) -> TargetLine | None:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    url_part, _, label = raw.partition("|")
    url_part = url_part.strip()
    label = label.strip()
    host = host_of(url_part)
    if group_mode == "host":
        group_key = host or hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:12]
    elif group_mode == "label":
        group_key = label or registered_parent(host)
    else:
        group_key = registered_parent(host)
    return TargetLine(raw=raw, url_part=url_part, label=label, host=host, group_key=group_key)


def load_target_lines(path: Path, group_mode: str) -> list[TargetLine]:
    targets: list[TargetLine] = []
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                url = str(row.get("url") or row.get("target") or row.get("host") or "").strip()
                if not url:
                    continue
                label = str(row.get("name") or row.get("label") or row.get("organization") or "").strip()
                raw = f"{url}|{label}" if label else url
                target = parse_target_line(raw, group_mode)
                if target:
                    targets.append(target)
        return targets
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        target = parse_target_line(line, group_mode)
        if target:
            targets.append(target)
    return targets


def group_targets(targets: list[TargetLine]) -> list[TargetGroup]:
    grouped: dict[str, TargetGroup] = {}
    for target in targets:
        grouped.setdefault(target.group_key, TargetGroup(key=target.group_key)).lines.append(target)
    return sorted(grouped.values(), key=lambda group: (-len(group.lines), group.key))


def ceil_div(value: int, divisor: int) -> int:
    return (value + max(1, divisor) - 1) // max(1, divisor)


def choose_batch_count(total_targets: int, args: argparse.Namespace) -> int:
    min_for_runner_limit = ceil_div(total_targets, args.max_runner_targets)
    if args.batch_count > 0:
        return max(1, args.batch_count, min_for_runner_limit)
    if not args.auto_batch:
        return max(1, ceil_div(total_targets, args.batch_size), min_for_runner_limit)

    target_size = 200 if total_targets <= 600 else 300
    count = max(1, ceil_div(total_targets, target_size), min_for_runner_limit)

    # For larger inputs, a 4-worker run benefits from 4 balanced batches
    # instead of 3 larger batches, while still keeping every batch below the
    # runner target cap.
    if total_targets > 600 and args.max_parallel >= 4:
        parallel_sized_count = min(args.max_parallel, total_targets)
        if ceil_div(total_targets, parallel_sized_count) <= args.max_runner_targets:
            count = max(count, parallel_sized_count)
    return count


def build_batches(groups: list[TargetGroup], batch_count: int) -> list[BatchPlan]:
    batches = [BatchPlan(index=i + 1) for i in range(batch_count)]
    heap: list[tuple[int, int]] = [(0, idx) for idx in range(batch_count)]
    heapq.heapify(heap)
    for group in groups:
        count, idx = heapq.heappop(heap)
        batches[idx].groups.append(group)
        heapq.heappush(heap, (count + len(group.lines), idx))
    return [batch for batch in batches if batch.count > 0]


def default_runner_args(profile: str) -> list[str]:
    if profile == "conservative":
        return [
            "--probe",
            "--fingerprint",
            "--tool-fingerprint",
            "--api-discovery",
            "--api-use-katana",
            "--miniapp-search-pack",
            "--wechat-miniapp",
        ]
    if profile == "full-readonly":
        return [
            "--probe",
            "--fingerprint",
            "--tool-fingerprint",
            "--high-value-paths",
            "--api-discovery",
            "--api-confirm",
            "--api-use-katana",
            "--xss-triage",
            "--xss-reflect-check",
        ]
    return [
        "--probe",
        "--fingerprint",
        "--tool-fingerprint",
        "--high-value-paths",
        "--api-discovery",
        "--api-confirm",
        "--api-use-katana",
    ]


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_batch_files(batch_dir: Path, batches: list[BatchPlan]) -> None:
    batch_dir.mkdir(parents=True, exist_ok=True)
    for batch in batches:
        batch_file = batch_dir / f"batch_{batch.index:03d}.txt"
        lines = [target.raw for group in batch.groups for target in group.lines]
        batch_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def plan_to_dict(batch_dir: Path, batch: BatchPlan) -> dict:
    return {
        "batch": batch.index,
        "count": batch.count,
        "group_count": len(batch.groups),
        "groups": [
            {
                "key": group.key,
                "count": len(group.lines),
                "hosts_sample": sorted({target.host for target in group.lines if target.host})[:8],
            }
            for group in batch.groups
        ],
        "batch_file": str(batch_dir / f"batch_{batch.index:03d}.txt"),
    }


def build_command(
    runner_python: Path,
    workspace: Path,
    batch_dir: Path,
    batch: BatchPlan,
    label: str,
    delay: float,
    runner_args: list[str],
) -> list[str]:
    command = [
        str(runner_python),
        str(workspace / "gov_exercise_runner.py"),
        "--targets",
        str(batch_dir / f"batch_{batch.index:03d}.txt"),
        "--label",
        f"{safe_label(label)}_b{batch.index:03d}",
        "--delay",
        str(delay),
    ]
    command.extend(runner_args)
    return command


def running_group_keys(running: list[RunningBatch]) -> set[str]:
    keys: set[str] = set()
    for item in running:
        keys.update(item.plan.group_keys)
    return keys


def write_status(
    path: Path,
    state: str,
    batch_dir: Path,
    batches: list[BatchPlan],
    running: list[RunningBatch],
    finished: list[dict],
    failures: list[dict],
    extra: dict | None = None,
) -> None:
    data = {
        "state": state,
        "updated_at": now_iso(),
        "batch_dir": str(batch_dir),
        "batch_count": len(batches),
        "total_targets": sum(batch.count for batch in batches),
        "running": [
            {
                "batch": item.plan.index,
                "pid": item.process.pid,
                "count": item.plan.count,
                "groups": item.plan.group_keys,
                "stdout": str(item.stdout_path),
                "stderr": str(item.stderr_path),
                "started_at": item.started_at,
            }
            for item in running
        ],
        "finished": finished,
        "failures": failures,
    }
    if extra:
        data.update(extra)
    write_json(path, data)


def launch_ready_batches(
    pending: list[BatchPlan],
    running: list[RunningBatch],
    finished: list[dict],
    failures: list[dict],
    args: argparse.Namespace,
    batch_dir: Path,
    runner_args: list[str],
) -> None:
    active_keys = running_group_keys(running)
    launched_any = True
    while len(running) < args.max_parallel and pending and launched_any:
        launched_any = False
        for idx, batch in enumerate(list(pending)):
            if active_keys.intersection(batch.group_keys):
                continue
            stdout_path = batch_dir / f"batch_{batch.index:03d}.out.log"
            stderr_path = batch_dir / f"batch_{batch.index:03d}.err.log"
            command = build_command(
                args.runner_python,
                args.workspace,
                batch_dir,
                batch,
                args.label,
                args.delay,
                runner_args,
            )
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(
                    command,
                    cwd=str(args.workspace),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    close_fds=True,
                )
            running.append(
                RunningBatch(
                    plan=batch,
                    process=process,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    started_at=now_iso(),
                    command=command,
                )
            )
            active_keys.update(batch.group_keys)
            del pending[idx]
            launched_any = True
            break


def run_scheduler(args: argparse.Namespace, batch_dir: Path, batches: list[BatchPlan], runner_args: list[str]) -> int:
    pending = list(batches)
    running: list[RunningBatch] = []
    finished: list[dict] = []
    failures: list[dict] = []
    status_path = batch_dir / "parallel_status.json"
    started_at = now_iso()
    write_status(status_path, "starting", batch_dir, batches, running, finished, failures, {"started_at": started_at})

    while pending or running:
        launch_ready_batches(pending, running, finished, failures, args, batch_dir, runner_args)
        write_status(
            status_path,
            "running",
            batch_dir,
            batches,
            running,
            finished,
            failures,
            {"pending": [batch.index for batch in pending], "started_at": started_at},
        )
        for item in list(running):
            returncode = item.process.poll()
            if returncode is None:
                continue
            running.remove(item)
            record = {
                "batch": item.plan.index,
                "pid": item.process.pid,
                "returncode": returncode,
                "count": item.plan.count,
                "groups": item.plan.group_keys,
                "stdout": str(item.stdout_path),
                "stderr": str(item.stderr_path),
                "started_at": item.started_at,
                "finished_at": now_iso(),
                "command": item.command,
            }
            finished.append(record)
            if returncode != 0:
                failures.append(record)
                if args.stop_on_failure:
                    pending.clear()
        if pending or running:
            time.sleep(max(1.0, args.poll_interval))

    final_state = "failed" if failures else "completed"
    write_status(
        status_path,
        final_state,
        batch_dir,
        batches,
        running,
        finished,
        failures,
        {"started_at": started_at, "finished_at": now_iso()},
    )
    return 1 if failures else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Group-aware parallel gov_exercise_runner launcher")
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, default=BASE_DIR)
    parser.add_argument("--runner-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--batch-size", type=int, default=300)
    parser.add_argument("--batch-count", type=int, default=0)
    parser.add_argument("--auto-batch", action="store_true", help="Choose batch count from the target count automatically")
    parser.add_argument("--max-parallel", type=int, default=3)
    parser.add_argument("--group-mode", choices=["root-domain", "host", "label"], default="root-domain")
    parser.add_argument("--label", default="parallel_flow")
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--profile", choices=["conservative", "readonly", "full-readonly"], default="readonly")
    parser.add_argument("--max-runner-targets", type=int, default=500)
    parser.add_argument("--stop-on-failure", action="store_true")
    parser.add_argument("--plan-only", action="store_true", help="Write plan files but do not launch runners")
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument(
        "runner_args",
        nargs=argparse.REMAINDER,
        help="Optional exact gov_exercise_runner args after --; overrides --profile stage args",
    )
    return parser.parse_args()


def normalize_runner_args(args: argparse.Namespace) -> list[str]:
    runner_args = list(args.runner_args or [])
    if runner_args and runner_args[0] == "--":
        runner_args = runner_args[1:]
    return runner_args or default_runner_args(args.profile)


def main() -> int:
    args = parse_args()
    args.targets = args.targets.expanduser().resolve()
    args.workspace = args.workspace.expanduser().resolve()
    args.runner_python = args.runner_python.expanduser().resolve()
    if not args.targets.exists():
        raise SystemExit(f"Targets file does not exist: {args.targets}")
    if not (args.workspace / "gov_exercise_runner.py").exists():
        raise SystemExit(f"gov_exercise_runner.py not found in workspace: {args.workspace}")
    if args.max_parallel < 1:
        raise SystemExit("--max-parallel must be >= 1")

    runner_args = normalize_runner_args(args)
    targets = load_target_lines(args.targets, args.group_mode)
    if not targets:
        raise SystemExit(f"No targets loaded from {args.targets}")
    groups = group_targets(targets)
    batch_count = choose_batch_count(len(targets), args)
    batches = build_batches(groups, batch_count)
    oversize_batches = [batch for batch in batches if batch.count > args.max_runner_targets]
    if oversize_batches:
        details = ", ".join(f"batch_{batch.index:03d}={batch.count}" for batch in oversize_batches)
        raise SystemExit(
            f"Batch exceeds gov_exercise_runner max target limit ({args.max_runner_targets}): {details}. "
            "Use a larger --batch-count, --group-mode host, or raise the runner config after confirming scope."
        )

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_dir = args.workspace / f"parallel_flow_batches_{stamp}"
    write_batch_files(batch_dir, batches)
    manifest = {
        "created_at": now_iso(),
        "source": str(args.targets),
        "workspace": str(args.workspace),
        "group_mode": args.group_mode,
        "target_count": len(targets),
        "group_count": len(groups),
        "auto_batch": args.auto_batch,
        "batch_size_requested": args.batch_size,
        "batch_count_requested": args.batch_count,
        "batch_count": len(batches),
        "max_parallel": args.max_parallel,
        "delay_per_runner": args.delay,
        "profile": args.profile,
        "runner_args": runner_args,
        "same_group_parallel_policy": "never",
        "batches": [plan_to_dict(batch_dir, batch) for batch in batches],
    }
    write_json(batch_dir / "parallel_plan.json", manifest)

    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    if args.plan_only:
        print(f"[plan-only] Wrote plan to {batch_dir}")
        return 0
    return run_scheduler(args, batch_dir, batches, runner_args)


if __name__ == "__main__":
    raise SystemExit(main())
