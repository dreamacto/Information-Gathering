#!/usr/bin/env python3
"""Low-impact Apache Shiro triage for authorized run directories.

This stage identifies targets that are worth a manual ShiroAttack2 check. It
does not brute force keys, send serialized payloads, execute commands, upload
files, or install memory shells.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from api_discovery import append_jsonl, now_iso, title_of


USER_AGENT = "Authorized-Shiro-Triage/1.0"
SHIRO_HINT_RE = re.compile(r"(apache shiro|org\.apache\.shiro|shiro)", re.I)
REMEMBER_ME_RE = re.compile(r"rememberme\s*=", re.I)
DELETE_ME_RE = re.compile(r"rememberme\s*=\s*deleteme", re.I)


@dataclass
class HeaderFetch:
    url: str
    status: int = 0
    final_url: str = ""
    elapsed_seconds: float = 0.0
    content_type: str = ""
    content_length: str = ""
    sample_sha256: str = ""
    text: str = ""
    headers_raw: str = ""
    set_cookies: list[str] = field(default_factory=list)
    error: str = ""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_header_blocks(raw: str) -> tuple[dict[str, str], list[str]]:
    blocks = [block for block in raw.replace("\r\n", "\n").split("\n\n") if block.strip()]
    headers: dict[str, str] = {}
    set_cookies: list[str] = []
    for block in blocks:
        for line in block.splitlines()[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key == "set-cookie":
                set_cookies.append(value)
            headers[key] = value
    return headers, set_cookies


def fetch_headers(url: str, run_dir: Path, timeout: int, cookie: str = "") -> HeaderFetch:
    curl = shutil.which("curl.exe") or shutil.which("curl")
    result = HeaderFetch(url=url, final_url=url)
    if not curl:
        result.error = "curl_not_found"
        return result
    tmp_dir = run_dir / ".shiro_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False) as body_f, tempfile.NamedTemporaryFile(
        dir=tmp_dir, delete=False
    ) as header_f:
        body_path = Path(body_f.name)
        header_path = Path(header_f.name)
    cmd = [
        curl,
        "-k",
        "-L",
        "--silent",
        "--show-error",
        "--max-time",
        str(timeout),
        "--connect-timeout",
        str(min(4, timeout)),
        "--range",
        "0-262143",
        "-A",
        USER_AGENT,
        "-D",
        str(header_path),
        "-o",
        str(body_path),
        "-w",
        "%{http_code} %{url_effective} %{time_total}",
    ]
    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3, check=False)
        parts = proc.stdout.strip().split(" ", 2)
        result.status = int(parts[0]) if parts and parts[0].isdigit() else 0
        result.final_url = parts[1] if len(parts) > 1 else url
        result.elapsed_seconds = float(parts[2]) if len(parts) > 2 else 0.0
        body = body_path.read_bytes() if body_path.exists() else b""
        result.headers_raw = header_path.read_text(encoding="utf-8", errors="ignore") if header_path.exists() else ""
        headers, set_cookies = parse_header_blocks(result.headers_raw)
        result.set_cookies = set_cookies
        result.content_type = headers.get("content-type", "")
        result.content_length = headers.get("content-length", "")
        result.sample_sha256 = sha256(body[:65536])
        result.text = body.decode("utf-8", errors="ignore")
        if proc.returncode != 0:
            result.error = proc.stderr.strip()[:300]
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)[:300]
    finally:
        for path in (body_path, header_path):
            try:
                path.unlink()
            except OSError:
                pass
    return result


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def load_seed_urls(run_dir: Path, include_all: bool, force: bool) -> list[str]:
    seeds: set[str] = set()
    priority_files = ["cat_java.txt", "cat_login.txt", "cat_oa.txt"]
    for name in priority_files:
        path = run_dir / name
        if path.exists():
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                value = line.strip()
                if value.startswith(("http://", "https://")):
                    seeds.add(value.rstrip("/"))
    for row in read_jsonl(run_dir / "fingerprints.jsonl"):
        cats = set(row.get("categories") or [])
        if cats.intersection({"java", "login", "oa"}) and row.get("url"):
            seeds.add(str(row["url"]).rstrip("/"))
    if include_all or not seeds:
        targets = run_dir / "targets.csv"
        if targets.exists():
            with targets.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
                for row in csv.DictReader(handle):
                    url = str(row.get("url") or "").strip()
                    if url.startswith(("http://", "https://")):
                        seeds.add(url.rstrip("/"))
    if not force:
        completed = {str(row.get("url") or "").rstrip("/") for row in read_jsonl(run_dir / "shiro_triage_results.jsonl")}
        seeds = {url for url in seeds if url not in completed}
    return sorted(seeds)


def compact_fetch(result: HeaderFetch) -> dict:
    return {
        "status": result.status,
        "final_url": result.final_url,
        "content_type": result.content_type,
        "content_length": result.content_length,
        "sample_sha256": result.sample_sha256,
        "title": title_of(result.text),
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "set_cookie_names": sorted({cookie.split("=", 1)[0].strip() for cookie in result.set_cookies if cookie}),
        "error": result.error,
    }


def analyze_target(url: str, run_dir: Path, timeout: int, delay: float) -> dict:
    baseline = fetch_headers(url, run_dir, timeout)
    if delay > 0:
        time.sleep(delay)
    invalid_cookie = fetch_headers(url, run_dir, timeout, cookie="rememberMe=1")

    baseline_cookie_blob = "\n".join(baseline.set_cookies)
    invalid_cookie_blob = "\n".join(invalid_cookie.set_cookies)
    header_blob = baseline.headers_raw + "\n" + invalid_cookie.headers_raw
    body_blob = baseline.text[:20000] + "\n" + invalid_cookie.text[:20000]

    signals: list[str] = []
    confidence = "none"
    manual_check = False
    if DELETE_ME_RE.search(invalid_cookie_blob):
        signals.append("invalid_rememberme_deleted")
        confidence = "high"
        manual_check = True
    if REMEMBER_ME_RE.search(baseline_cookie_blob):
        signals.append("rememberme_set_cookie_present")
        confidence = "medium" if confidence == "none" else confidence
        manual_check = True
    if SHIRO_HINT_RE.search(header_blob) or SHIRO_HINT_RE.search(body_blob):
        signals.append("shiro_keyword")
        confidence = "medium" if confidence == "none" else confidence
        manual_check = True

    return {
        "checked_at": now_iso(),
        "url": url,
        "host": urlparse(url).netloc,
        "signals": sorted(set(signals)),
        "confidence": confidence,
        "manual_check_recommended": manual_check,
        "notes": "Triage only. It does not brute force Shiro keys or send serialized payloads.",
        "baseline": compact_fetch(baseline),
        "invalid_rememberme_probe": compact_fetch(invalid_cookie),
    }


def refresh_outputs(run_dir: Path) -> None:
    candidates = [row for row in read_jsonl(run_dir / "shiro_candidates.jsonl") if row.get("url")]
    detected = sorted({row["url"] for row in candidates if row.get("confidence") in {"medium", "high"}})
    (run_dir / "shiro_detected.txt").write_text("\n".join(detected) + ("\n" if detected else ""), encoding="utf-8")
    queue_path = run_dir / "shiro_manual_queue.csv"
    with queue_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["url", "host", "confidence", "signals", "recommended_action"])
        writer.writeheader()
        for row in candidates:
            writer.writerow({
                "url": row.get("url", ""),
                "host": row.get("host", ""),
                "confidence": row.get("confidence", ""),
                "signals": ",".join(row.get("signals") or []),
                "recommended_action": "Open ShiroAttack2 manually for authorized single-target key/rememberMe verification only.",
            })


def main() -> int:
    parser = argparse.ArgumentParser(description="Low-impact Apache Shiro triage")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--include-all", action="store_true", help="Test all scoped targets instead of Java/login/OA seeds only")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    seeds = load_seed_urls(args.run_dir, args.include_all, args.force)
    if args.limit:
        seeds = seeds[:args.limit]
    manifest = {
        "created_at": now_iso(),
        "seed_count": len(seeds),
        "delay": args.delay,
        "timeout": args.timeout,
        "include_all": bool(args.include_all),
        "request_budget_per_target": 2,
        "disabled_actions": ["key_bruteforce", "serialized_payloads", "command_execution", "memory_shell", "file_upload"],
    }
    (args.run_dir / "shiro_triage_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for url in seeds:
        record = analyze_target(url, args.run_dir, args.timeout, args.delay)
        append_jsonl(args.run_dir / "shiro_triage_results.jsonl", record)
        if record.get("manual_check_recommended"):
            append_jsonl(args.run_dir / "shiro_candidates.jsonl", record)
        refresh_outputs(args.run_dir)
        if args.delay > 0:
            time.sleep(args.delay)
    refresh_outputs(args.run_dir)
    print(json.dumps({"tested": len(seeds), "run_dir": str(args.run_dir)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
