import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path


def split_lines(path: Path, batch_size: int) -> list[list[str]]:
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]
    return [lines[i : i + batch_size] for i in range(0, len(lines), batch_size)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--runner-python", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=400)
    parser.add_argument("--delay", default="5")
    parser.add_argument("--api-discovery", action="store_true")
    parser.add_argument("--api-confirm", action="store_true")
    parser.add_argument("--api-use-katana", action="store_true")
    parser.add_argument("--api-max-js", type=int, default=20)
    parser.add_argument("--api-confirm-max-per-target", type=int, default=8)
    parser.add_argument("--api-confirm-threshold", type=int, default=5)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_dir = args.workspace / f"extra_subdomain_batches_{stamp}"
    batch_dir.mkdir(parents=True, exist_ok=True)
    status_path = args.workspace / "extra_subdomain_batch_status.json"

    batches = split_lines(args.targets, args.batch_size)
    status = {
        "state": "started",
        "source": str(args.targets),
        "batch_dir": str(batch_dir),
        "batch_size": args.batch_size,
        "batch_count": len(batches),
        "started_at": dt.datetime.now().isoformat(timespec="seconds"),
        "batches": [],
    }
    status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")

    for idx, batch in enumerate(batches, start=1):
        batch_file = batch_dir / f"batch_{idx:03d}.txt"
        batch_file.write_text("\n".join(batch) + "\n", encoding="utf-8")
        label = f"extra_subdomains_b{idx:03d}_{stamp}"
        stdout = batch_dir / f"batch_{idx:03d}.out.log"
        stderr = batch_dir / f"batch_{idx:03d}.err.log"
        cmd = [
            str(args.runner_python),
            str(args.workspace / "gov_exercise_runner.py"),
            "--targets",
            str(batch_file),
            "--probe",
            "--fingerprint",
            "--high-value-paths",
            "--delay",
            str(args.delay),
            "--label",
            label,
        ]
        if args.api_discovery:
            cmd.extend(["--api-discovery", "--api-max-js", str(args.api_max_js)])
        if args.api_confirm:
            cmd.extend([
                "--api-confirm",
                "--api-confirm-max-per-target",
                str(args.api_confirm_max_per_target),
                "--api-confirm-threshold",
                str(args.api_confirm_threshold),
            ])
        if args.api_use_katana:
            cmd.append("--api-use-katana")
        if args.force:
            cmd.append("--force")

        status["state"] = "running_batch"
        status["current_batch"] = idx
        status["current_batch_file"] = str(batch_file)
        status["updated_at"] = dt.datetime.now().isoformat(timespec="seconds")
        status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")

        with stdout.open("w", encoding="utf-8", errors="ignore") as out, stderr.open(
            "w", encoding="utf-8", errors="ignore"
        ) as err:
            proc = subprocess.run(cmd, cwd=str(args.workspace), stdout=out, stderr=err)

        status["batches"].append(
            {
                "batch": idx,
                "count": len(batch),
                "batch_file": str(batch_file),
                "label": label,
                "returncode": proc.returncode,
                "stdout": str(stdout),
                "stderr": str(stderr),
                "finished_at": dt.datetime.now().isoformat(timespec="seconds"),
            }
        )
        status["updated_at"] = dt.datetime.now().isoformat(timespec="seconds")
        status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
        if proc.returncode != 0:
            status["state"] = "failed"
            status["failed_batch"] = idx
            status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
            return proc.returncode

    status["state"] = "complete"
    status["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
    status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
