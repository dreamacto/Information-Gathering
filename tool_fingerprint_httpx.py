#!/usr/bin/env python3
"""Rate-controlled external fingerprinting with ProjectDiscovery httpx.

The runner already has a lightweight built-in classifier.  This stage adds a
tool-backed fingerprint pass while keeping traffic bounded by executing one
target at a time and sleeping between targets.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from exercise_runtime import DEFAULT_CONFIG, collect_runtime_inventory, load_targets, now_iso, read_json


try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def resolve_httpx(config_path: Path) -> str:
    direct = shutil.which("httpx.exe") or shutil.which("httpx")
    if direct:
        return direct
    try:
        runtime = collect_runtime_inventory(read_json(config_path))
    except Exception:
        return ""
    return str((runtime.get("tools") or {}).get("httpx") or "")


def load_probe_urls(run_dir: Path, fallback_targets: Path) -> list[str]:
    urls: list[str] = []
    probe_path = run_dir / "probe_results.jsonl"
    if probe_path.exists():
        for line in probe_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("ok") and row.get("url"):
                urls.append(str(row["url"]).rstrip("/"))
    if not urls:
        urls.extend(t.url.rstrip("/") for t in load_targets(fallback_targets))
    return sorted(set(filter(None, urls)))


def run_httpx_one(httpx: str, url: str, timeout: int) -> tuple[list[dict], dict]:
    base_cmd = [
        httpx,
        "-u",
        url,
        "-json",
        "-silent",
        "-title",
        "-sc",
        "-server",
        "-cl",
        "-fr",
        "-timeout",
        str(timeout),
        "-retries",
        "0",
        "-t",
        "1",
        "-rl",
        "1",
    ]
    tech_cmd = base_cmd[:4] + ["-td"] + base_cmd[4:]
    for mode, cmd in (("tech_detect", tech_cmd), ("basic", base_cmd)):
        started = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(20, timeout + 15),
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return [], {
                "checked_at": now_iso(),
                "url": url,
                "mode": mode,
                "error": str(exc)[:300],
            }
        if proc.returncode != 0 and mode == "tech_detect":
            continue
        rows: list[dict] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                data = {"input": url, "raw": line[:500]}
            rows.append(data)
        meta = {
            "checked_at": now_iso(),
            "url": url,
            "mode": mode,
            "returncode": proc.returncode,
            "duration_seconds": round(time.time() - started, 3),
            "stderr_sample": proc.stderr[:500],
        }
        return rows, meta
    return [], {"checked_at": now_iso(), "url": url, "error": "httpx_failed"}


def normalize_record(url: str, row: dict, meta: dict) -> dict:
    tech = row.get("tech") or row.get("technologies") or row.get("webtech") or []
    if isinstance(tech, str):
        tech = [item.strip() for item in tech.split(",") if item.strip()]
    return {
        "checked_at": meta.get("checked_at") or now_iso(),
        "input_url": url,
        "url": row.get("url") or row.get("input") or url,
        "host": row.get("host") or row.get("webserver") or "",
        "status_code": row.get("status_code") or row.get("status-code") or row.get("status"),
        "title": row.get("title") or "",
        "server": row.get("webserver") or row.get("server") or "",
        "content_length": row.get("content_length") or row.get("content-length") or row.get("cl"),
        "technologies": tech,
        "cdn": row.get("cdn") or row.get("cdn_name") or "",
        "method": "httpx_rate_controlled",
        "mode": meta.get("mode", ""),
        "response_body_persisted": False,
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = ["input_url", "url", "status_code", "title", "server", "content_length", "technologies", "cdn", "mode"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            data = dict(row)
            if isinstance(data.get("technologies"), list):
                data["technologies"] = ";".join(str(item) for item in data["technologies"])
            writer.writerow({key: data.get(key, "") for key in fieldnames})


def main() -> int:
    parser = argparse.ArgumentParser(description="Rate-controlled httpx fingerprinting")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--delay", type=float, default=2.0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    httpx = resolve_httpx(args.config)
    out_jsonl = args.run_dir / "tool_fingerprints.jsonl"
    out_csv = args.run_dir / "tool_fingerprints.csv"
    errors_jsonl = args.run_dir / "tool_fingerprint_errors.jsonl"
    manifest_path = args.run_dir / "tool_fingerprint_manifest.json"
    for path in (out_jsonl, errors_jsonl):
        path.write_text("", encoding="utf-8")
    urls = load_probe_urls(args.run_dir, args.targets)
    if args.limit:
        urls = urls[: args.limit]
    normalized_rows: list[dict] = []
    if not httpx:
        append_jsonl(errors_jsonl, {"checked_at": now_iso(), "error": "httpx_not_found"})
    else:
        for url in urls:
            rows, meta = run_httpx_one(httpx, url, args.timeout)
            if meta.get("error") or meta.get("returncode") not in (0, None):
                append_jsonl(errors_jsonl, meta)
            for row in rows:
                normalized = normalize_record(url, row, meta)
                normalized_rows.append(normalized)
                append_jsonl(out_jsonl, normalized)
            time.sleep(max(0.0, args.delay))

    write_csv(out_csv, normalized_rows)
    manifest = {
        "created_at": now_iso(),
        "tool": "httpx",
        "tool_path": httpx,
        "target_count": len(urls),
        "result_count": len(normalized_rows),
        "delay": args.delay,
        "timeout": args.timeout,
        "response_body_persisted": False,
        "outputs": {
            "jsonl": str(out_jsonl),
            "csv": str(out_csv),
            "errors": str(errors_jsonl),
        },
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
