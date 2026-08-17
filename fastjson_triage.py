#!/usr/bin/env python3
"""Low-impact Fastjson triage for authorized run directories.

This stage identifies targets that likely use Fastjson as their JSON parser.
It only sends GET requests and one harmless POST with an empty JSON body
({"probe":"triage"}) to a small set of likely JSON endpoints. It does NOT send
@type payloads, JNDI/LDAP callbacks, DNSLog probes, or any exploit payload.
All RCE validation is approval-gated and manual.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import urllib.request
import urllib.error
import ssl

from api_discovery import append_jsonl, now_iso, title_of


USER_AGENT = "Authorized-Fastjson-Triage/1.0"

JSON_ENDPOINTS = [
    "/api",
    "/api/",
    "/api/json",
    "/api/user/list",
    "/api/system/info",
    "/login",
    "/user/login",
    "/admin/login",
    "/api/v1/auth/login",
    "/api/v1/user/info",
]

FASTJSON_RE = re.compile(r"com\.alibaba\.fastjson|fastjson", re.I)
JACKSON_RE = re.compile(r"com\.fasterxml\.jackson|jackson", re.I)
SWAGGER_RE = re.compile(r"swagger|knife4j|docs\.json", re.I)


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


def fetch(url: str, method: str = "GET", body: str | None = None,
          headers: dict | None = None, timeout: float = 10.0) -> tuple[int, str, str, float]:
    started = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        hdrs = {"User-Agent": USER_AGENT}
        if body is not None:
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        data = body.encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(6144)
            return resp.status, raw.decode("utf-8", "replace"), "", int((time.monotonic() - started) * 1000)
    except urllib.error.HTTPError as e:
        try:
            body_txt = e.read(2048).decode("utf-8", "replace")
        except Exception:
            body_txt = ""
        return e.code, body_txt, "", int((time.monotonic() - started) * 1000)
    except Exception as e:
        return 0, "", str(e), int((time.monotonic() - started) * 1000)


def is_json_response(status: int, body: str) -> bool:
    if status >= 400:
        return False
    stripped = body.strip()
    return stripped.startswith("{") or stripped.startswith("[")


def probe_url(url: str) -> list[Signal]:
    signals: list[Signal] = []
    host = urlparse(url).hostname or url
    port = str(urlparse(url).port or ("443" if url.startswith("https") else "80"))
    obs = now_iso()
    base = base_site(url)

    for path in JSON_ENDPOINTS:
        target = base + path
        status, body, err, ms = fetch(target, method="GET")
        if err or status == 404:
            continue
        if FASTJSON_RE.search(body):
            signals.append(Signal(host=host, port=port, signal_type="fastjson_marker",
                                  detail=f"{path} error body mentions fastjson",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))
        if is_json_response(status, body):
            signals.append(Signal(host=host, port=port, signal_type="json_endpoint",
                                  detail=f"{path} returns JSON (parser likely fastjson/jackson)",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))
        if SWAGGER_RE.search(body):
            signals.append(Signal(host=host, port=port, signal_type="swagger_page",
                                  detail=f"{path} looks like API docs; check /swagger-ui.html and /v2/api-docs",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))

    json_targets = [s for s in signals if s.signal_type == "json_endpoint"]
    if json_targets:
        probe_target = json_targets[0].url
        status, body, err, ms = fetch(probe_target, method="POST", body='{"probe":"triage"}')
        if not err and FASTJSON_RE.search(body):
            signals.append(Signal(host=host, port=port, signal_type="fastjson_confirmed_error",
                                  detail="POST empty JSON triggers fastjson-related error text",
                                  url=probe_target, status=status, duration_ms=ms, observed_at=obs))

    return signals


def main() -> int:
    ap = argparse.ArgumentParser(description="Low-impact Fastjson triage")
    ap.add_argument("--input", help="file with target URLs (one per line)")
    ap.add_argument("--url", help="single target URL")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "outputs" / "fastjson_triage"))
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
    sig_path = out_dir / "fastjson_signals.jsonl"
    cand_path = out_dir / "fastjson_candidates.jsonl"
    queue_path = out_dir / "fastjson_manual_queue.csv"
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
            has_marker = any(s.signal_type in ("fastjson_marker", "fastjson_confirmed_error") for s in sigs)
            json_cnt = sum(1 for s in sigs if s.signal_type == "json_endpoint")
            if args.require_2_signals:
                if not (has_marker and json_cnt >= 1):
                    continue
            elif not (has_marker or json_cnt >= 1):
                continue
            if hostkey in seen:
                continue
            seen.add(hostkey)
            cand = {"host": hostkey, "product": "fastjson", "signal_count": len(sigs),
                    "signals": [s.__dict__ for s in sigs], "observed_at": now_iso(), "status": "candidate"}
            append_jsonl(cand_path, cand)
            w.writerow([hostkey, len(sigs), " | ".join(s.detail for s in sigs[:4]),
                        "FastjsonScan.exe (tools/managed/fastjsonscan) or nuclei fastjson templates",
                        "YES"])

    print(f"scanned={len(urls)} signals={len(all_signals)} candidates={len(seen)}")
    print(f"signal jsonl : {sig_path}")
    print(f"candidates   : {cand_path}")
    print(f"manual queue : {queue_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
