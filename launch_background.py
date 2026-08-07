import argparse
import json
import os
import subprocess
import sys
from datetime import datetime


def _abs(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Launch a detached background process and write a PID file."
    )
    parser.add_argument("--pid-file", required=True)
    parser.add_argument("--stdout", required=True)
    parser.add_argument("--stderr", required=True)
    parser.add_argument("--cwd", default=os.getcwd())
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("missing command after --")

    cwd = _abs(args.cwd)
    pid_file = _abs(args.pid_file)
    stdout_path = _abs(args.stdout)
    stderr_path = _abs(args.stderr)

    for path in (pid_file, stdout_path, stderr_path):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    creationflags = 0
    if os.name == "nt":
        creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
        creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0)

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    with open(stdout_path, "ab", buffering=0) as stdout, open(
        stderr_path, "ab", buffering=0
    ) as stderr:
        stdout.write(f"\n=== launched at {started_at} ===\n".encode("utf-8"))
        stderr.write(f"\n=== launched at {started_at} ===\n".encode("utf-8"))
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            creationflags=creationflags,
            close_fds=True,
        )

    info = {
        "pid": process.pid,
        "started_at": started_at,
        "cwd": cwd,
        "stdout": stdout_path,
        "stderr": stderr_path,
        "command": command,
    }
    with open(pid_file, "w", encoding="utf-8") as handle:
        json.dump(info, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps(info, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
