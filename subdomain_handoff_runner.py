import argparse
import csv
import datetime as dt
import ipaddress
import json
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse


def is_process_running(pid: int) -> bool:
    proc = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    return str(pid) in proc.stdout


def normalize_host(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path
    value = value.split("|", 1)[0].strip()
    value = value.split("/", 1)[0].strip()
    value = value.rsplit("@", 1)[-1]
    if ":" in value and not value.startswith("["):
        value = value.split(":", 1)[0]
    return value.strip(".").lower()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def read_original_hosts(paths: list[Path]) -> set[str]:
    hosts: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            host = normalize_host(line)
            if host:
                hosts.add(host)
    return hosts


def collect_subdomains(out_dir: Path) -> set[str]:
    hosts: set[str] = set()
    for csv_path in out_dir.rglob("*.csv"):
        with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                host = normalize_host(row.get("subdomain") or row.get("url") or "")
                if host and "." in host and not is_ip(host):
                    hosts.add(host)
    return hosts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wait-pid", type=int, required=True)
    parser.add_argument("--oneforall-dir", type=Path, required=True)
    parser.add_argument("--combined-targets", type=Path, required=True)
    parser.add_argument("--seed-domains", type=Path, required=True)
    parser.add_argument("--runner-python", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--delay", default="5")
    args = parser.parse_args()

    log_path = args.workspace / "subdomain_handoff_status.json"
    while is_process_running(args.wait_pid):
        log_path.write_text(
            json.dumps(
                {
                    "state": "waiting_oneforall",
                    "wait_pid": args.wait_pid,
                    "updated_at": dt.datetime.now().isoformat(timespec="seconds"),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        time.sleep(30)

    original_hosts = read_original_hosts([args.combined_targets, args.seed_domains])
    collected = collect_subdomains(args.oneforall_dir)
    extras = sorted(h for h in collected if h not in original_hosts)

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    extra_file = args.workspace / f"extra_subdomains_for_scan_{stamp}.txt"
    pending_file = args.workspace / f"extra_subdomains_pending_apply_{stamp}.txt"
    extra_file.write_text("\n".join(extras) + ("\n" if extras else ""), encoding="utf-8")
    pending_file.write_text("\n".join(extras) + ("\n" if extras else ""), encoding="utf-8")

    if not extras:
        log_path.write_text(
            json.dumps(
                {
                    "state": "no_extra_subdomains",
                    "oneforall_dir": str(args.oneforall_dir),
                    "extra_file": str(extra_file),
                    "updated_at": dt.datetime.now().isoformat(timespec="seconds"),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return 0

    stdout = args.workspace / f"background_extra_subdomains_full_{stamp}.out.log"
    stderr = args.workspace / f"background_extra_subdomains_full_{stamp}.err.log"
    cmd = [
        str(args.runner_python),
        str(args.workspace / "gov_exercise_runner.py"),
        "--targets",
        str(extra_file),
        "--probe",
        "--fingerprint",
        "--high-value-paths",
        "--delay",
        str(args.delay),
        "--label",
        f"extra_subdomains_full_{stamp}",
    ]
    with stdout.open("w", encoding="utf-8", errors="ignore") as out, stderr.open(
        "w", encoding="utf-8", errors="ignore"
    ) as err:
        proc = subprocess.Popen(cmd, cwd=str(args.workspace), stdout=out, stderr=err)

    log_path.write_text(
        json.dumps(
            {
                "state": "started_extra_subdomain_scan",
                "extra_count": len(extras),
                "extra_file": str(extra_file),
                "pending_file": str(pending_file),
                "scan_pid": proc.pid,
                "stdout": str(stdout),
                "stderr": str(stderr),
                "updated_at": dt.datetime.now().isoformat(timespec="seconds"),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
