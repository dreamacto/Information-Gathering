#!/usr/bin/env python3
"""Launch Butian URL discovery and optional high-confidence scanning in background."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from exercise_runtime import now_iso

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Start Butian academy URL pipeline in the background")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--provider", choices=["bing", "duckduckgo"], default="bing")
    parser.add_argument("--delay", type=float, default=2.5)
    parser.add_argument("--jitter", type=float, default=0.8)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--max-results", type=int, default=8)
    parser.add_argument("--max-queries", type=int, default=3)
    parser.add_argument("--query-delay", type=float, default=0.8)
    parser.add_argument("--min-score", type=int, default=82)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--gov-delay", type=float, default=3.0)
    parser.add_argument("--no-gov", action="store_true", help="Only discover URL candidates; do not run gov_exercise_runner")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    run_dir = args.run_dir
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "butian_background_pipeline.log"
    script = Path.cwd() / "butian_url_discovery.py"
    command = [
        sys.executable,
        str(script),
        "--run-dir",
        str(run_dir),
        "--provider",
        args.provider,
        "--delay",
        str(args.delay),
        "--jitter",
        str(args.jitter),
        "--timeout",
        str(args.timeout),
        "--max-results",
        str(args.max_results),
        "--max-queries",
        str(args.max_queries),
        "--query-delay",
        str(args.query_delay),
        "--min-score",
        str(args.min_score),
        "--gov-delay",
        str(args.gov_delay),
        "--python-exe",
        sys.executable,
    ]
    if args.limit:
        command.extend(["--limit", str(args.limit)])
    if not args.no_gov:
        command.append("--run-gov-on-high-confidence")

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    log_handle = log_path.open("a", encoding="utf-8", errors="replace")
    log_handle.write("\n=== launch " + now_iso() + " ===\n")
    log_handle.write("command: " + json.dumps(command, ensure_ascii=False) + "\n")
    log_handle.flush()
    proc = subprocess.Popen(
        command,
        cwd=Path.cwd(),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
        close_fds=False,
    )
    pid_info = {
        "started_at": now_iso(),
        "pid": proc.pid,
        "run_dir": str(run_dir),
        "log": str(log_path),
        "command": command,
        "gov_enabled": not args.no_gov,
    }
    pid_path = run_dir / "butian_background_pipeline.pid.json"
    pid_path.write_text(json.dumps(pid_info, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(pid_info, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
