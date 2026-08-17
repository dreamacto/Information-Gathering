#!/usr/bin/env python3
"""Low-impact Nacos triage for authorized run directories.

This stage identifies targets that run Nacos and checks whether management
APIs are reachable without authentication. It only sends read-only GET requests
to well-known Nacos paths and records status codes; it never reads configuration
bodies, never creates accounts, never forges JWT tokens. Config retrieval, auth
bypass, and account creation are approval-gated and manual.
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


USER_AGENT = "Authorized-Nacos-Triage/1.0"

NACOS_PATHS = [
    "/nacos/index.html",
    "/nacos/",
    "/nacos/v1/console/server/state",
    "/nacos/v1/console/health/readiness",
    "/nacos/v1/auth/users",
    "/nacos/v1/cs/configs?dataId=&group=&pageNo=1&pageSize=1",
]
# Paths that would expose sensitive data on 200; triage marks them as candidates
# but never reads the response body beyond the first bytes needed for status.
SENSITIVE_PATHS = ["/nacos/v1/auth/users", "/nacos/v1/cs/configs"]

NACOS_PAGE_RE = re.compile(r"nacos|namespace|配置管理|服务管理", re.I)
NACOS_JSON_RE = re.compile(r"\"(?:code|username|data|namespaceId|serverIdentity)\"", re.I)


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


def fetch(url: str, timeout: float = 10.0, read_body: bool = True) -> tuple[int, str, str, float]:
    started = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(6144 if read_body else 64)
            body = raw.decode("utf-8", "replace")
            return resp.status, body, "", int((time.monotonic() - started) * 1000)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(64).decode("utf-8", "replace")
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
    base = base_site(url)

    for path in NACOS_PATHS:
        sensitive = any(p in path for p in SENSITIVE_PATHS)
        status, body, err, ms = fetch(base + path, read_body=not sensitive)
        if err or status == 0:
            continue
        if path in ("/nacos/index.html", "/nacos/"):
            if status == 200 and (NACOS_PAGE_RE.search(body)):
                signals.append(Signal(host=host, port=port, signal_type="nacos_page",
                                      detail=f"{path} looks like Nacos console page ({status})",
                                      url=base + path, status=status, duration_ms=ms, observed_at=obs))
            continue
        if status in (200, 401, 403):
            detail = f"{path} responds {status}"
            if status == 200 and sensitive:
                detail = f"{path} responds 200 WITHOUT auth - sensitive data reachable (manual review, do NOT fetch config bodies)"
                signals.append(Signal(host=host, port=port, signal_type="nacos_unauth",
                                      detail=detail, url=base + path, status=status,
                                      duration_ms=ms, observed_at=obs))
                continue
            if status == 200 and not sensitive and NACOS_JSON_RE.search(body):
                detail = f"{path} responds 200 with Nacos-like JSON (server/state or health OK)"
            signals.append(Signal(host=host, port=port, signal_type="nacos_api",
                                  detail=detail, url=base + path, status=status,
                                  duration_ms=ms, observed_at=obs))

    return signals


def main() -> int:
    ap = argparse.ArgumentParser(description="Low-impact Nacos triage")
    ap.add_argument("--input", help="file with target URLs (one per line)")
    ap.add_argument("--url", help="single target URL")
    ap.add_argument("--limit", type=int, default=0, help="max targets to scan (0=all)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--dry-run", action="store_true", help="do not send any request")
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "outputs" / "nacos_triage"))
    ap.add_argument("--require-2-signals", action="store_true")
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
    sig_path = out_dir / "nacos_signals.jsonl"
    cand_path = out_dir / "nacos_candidates.jsonl"
    queue_path = out_dir / "nacos_manual_queue.csv"
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
            if args.require_2_signals and len(sigs) < 2:
                continue
            if hostkey in seen:
                continue
            seen.add(hostkey)
            high = any(s.signal_type == "nacos_unauth" for s in sigs)
            cand = {"host": hostkey, "product": "nacos", "signal_count": len(sigs),
                    "signals": [s.__dict__ for s in sigs], "observed_at": now_iso(), "status": "candidate"}
            append_jsonl(cand_path, cand)
            w.writerow([hostkey, len(sigs), " | ".join(s.detail for s in sigs[:4]),
                        "nuclei nacos templates (auth-bypass/default-login/info-leak)",
                        "YES" if high else "NO"])

    print(f"scanned={len(urls)} signals={len(all_signals)} candidates={len(seen)}")
    print(f"signal jsonl : {sig_path}")
    print(f"candidates   : {cand_path}")
    print(f"manual queue : {queue_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
