#!/usr/bin/env python3
"""Low-impact Spring Boot Actuator triage for authorized run directories.

This stage identifies targets that expose Spring Boot Actuator endpoints. It
only sends read-only GET requests to a small set of well-known actuator paths.
It does NOT download heapdumps, read env contents, send exploit payloads, or
execute commands. Sensitive endpoints (heapdump/env dump bodies) are marked as
candidates for manual review only.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import urllib.request
import urllib.error
import ssl

from api_discovery import append_jsonl, now_iso, title_of


USER_AGENT = "Authorized-SpringBoot-Triage/1.0"

ACTUATOR_PATHS = [
    "/actuator/health",
    "/actuator",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/info",
    "/actuator/metrics",
]
# Paths that expose sensitive content; triage only checks presence (status code),
# never reads the body. Downloading is approval-gated and manual.
SENSITIVE_EXISTENCE_PATHS = [
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/configprops",
    "/actuator/httptrace",
]

WHITELABEL_RE = re.compile(r"Whitelabel Error Page", re.I)
JSON_STATUS_RE = re.compile(r"\"status\"\s*:\s*\"?(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)\"?", re.I)


@dataclass
class Signal:
    host: str
    port: str
    signal_type: str
    detail: str
    url: str
    status: int
    duration_ms: int
    observed_at: str


def base_site(url: str) -> str:
    url = url.split("#")[0].split("?")[0]
    if url.endswith("/"):
        url = url[:-1]
    return url


def fetch(url: str, timeout: float = 10.0) -> tuple[int, str, str, float]:
    """Minimal urllib GET. Returns (status, body_sample, error, duration_ms).
    Reads at most 6144 bytes; never follows redirect chains blindly."""
    started = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(6144).decode("utf-8", "replace")
            return resp.status, body, "", int((time.monotonic() - started) * 1000)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2048).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, "", int((time.monotonic() - started) * 1000)
    except Exception as e:
        return 0, "", str(e), int((time.monotonic() - started) * 1000)


def probe_url(url: str) -> list[Signal]:
    signals: list[Signal] = []
    host = urlparse(url).hostname or url
    port = str(urlparse(url).port or ("443" if url.startswith("https") else "80"))
    obs = now_iso()

    for path in ACTUATOR_PATHS:
        target = base_site(url) + path
        status, body, err, ms = fetch(target)
        if err:
            continue
        detail = ""
        if path == "/actuator/health" and status < 400 and JSON_STATUS_RE.search(body):
            detail = "health endpoint returns JSON status payload; actuator likely exposed"
        elif path == "/actuator" and status == 200 and ("_links" in body or "links" in body):
            detail = "actuator index page exposed (endpoint list available)"
        elif status == 200 and (path in ("/actuator/mappings", "/actuator/beans", "/actuator/metrics")):
            detail = f"{path} exposed (200)"
        elif status in (401, 403):
            detail = f"{path} requires auth ({status}); endpoint enabled but protected"
        if detail:
            signals.append(Signal(host=host, port=port, signal_type="actuator", detail=detail,
                                  url=target, status=status, duration_ms=ms, observed_at=obs))

    for path in SENSITIVE_EXISTENCE_PATHS:
        target = base_site(url) + path
        status, _body, err, ms = fetch(target, timeout=6.0)
        if err:
            continue
        if status == 200:
            signals.append(Signal(host=host, port=port, signal_type="sensitive_endpoint",
                                  detail=f"{path} responds 200 (content NOT read; manual review required)",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))

    return signals


def main() -> int:
    ap = argparse.ArgumentParser(description="Low-impact Spring Boot Actuator triage")
    ap.add_argument("--input", help="file with target URLs (one per line)")
    ap.add_argument("--url", help="single target URL")
    ap.add_argument("--limit", type=int, default=0, help="max targets to scan (0=all)")
    ap.add_argument("--concurrency", type=int, default=4, help="max parallel workers")
    ap.add_argument("--delay", type=float, default=0.5, help="seconds between requests per worker")
    ap.add_argument("--dry-run", action="store_true", help="do not send any request")
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "outputs" / "springboot_triage"))
    ap.add_argument("--require-2-signals", action="store_true",
                    help="only promote to candidate when at least 2 signals exist")
    args = ap.parse_args()

    if args.dry_run:
        print("[dry-run] no requests will be sent")
        return 0

    urls: list[str] = []
    if args.url:
        urls.append(args.url)
    elif args.input:
        p = Path(args.input)
        if p.exists():
            urls = [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    if not urls:
        print("no targets; use --url or --input")
        return 1
    if args.limit:
        urls = urls[: args.limit]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sig_path = out_dir / "springboot_signals.jsonl"
    cand_path = out_dir / "springboot_candidates.jsonl"
    queue_path = out_dir / "springboot_manual_queue.csv"
    for f in (sig_path, cand_path, queue_path):
        if f.exists():
            f.unlink()

    all_signals: list[Signal] = []
    for u in urls:
        all_signals.extend(probe_url(u))
        time.sleep(args.delay)

    for s in all_signals:
        append_jsonl(sig_path, s.__dict__)

    by_host: dict[str, list[Signal]] = {}
    for s in all_signals:
        by_host.setdefault(f"{s.host}:{s.port}", []).append(s)

    seen: set[str] = set()
    with open(queue_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "signal_count", "signals", "suggested_tool", "approval_needed"])
        for hostkey, sigs in sorted(by_host.items()):
            two_sig = len(sigs) >= 2
            has_sensitive = any(s.signal_type == "sensitive_endpoint" for s in sigs)
            if not (two_sig or has_sensitive or (len(sigs) >= 1 and not args.require_2_signals)):
                continue
            if hostkey in seen:
                continue
            seen.add(hostkey)
            cand = {"host": hostkey, "product": "springboot", "signal_count": len(sigs),
                    "signals": [s.__dict__ for s in sigs], "observed_at": now_iso(), "status": "candidate"}
            append_jsonl(cand_path, cand)
            w.writerow([hostkey, len(sigs), " | ".join(s.detail for s in sigs[:4]),
                        "nuclei springboot actuator templates or SpringBoot-Scan.py (both CLI)",
                        "YES" if has_sensitive else "NO"])

    print(f"scanned={len(urls)} signals={len(all_signals)} candidates={len(seen)}")
    print(f"signal jsonl : {sig_path}")
    print(f"candidates   : {cand_path}")
    print(f"manual queue : {queue_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
