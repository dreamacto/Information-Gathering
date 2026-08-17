#!/usr/bin/env python3
"""Low-impact Struts2 triage for authorized run directories.

This stage identifies targets that run Apache Struts2. It sends read-only GET
requests to a few common .action/.do paths and inspects response headers and
error pages for Struts markers. It does NOT send OGNL payloads, never tests
S2-xxx exploits, and performs no command execution.
"""

from __future__ import annotations

import argparse
import csv
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import urllib.request
import urllib.error
import ssl

from api_discovery import append_jsonl, now_iso, title_of


USER_AGENT = "Authorized-Struts2-Triage/1.0"

ACTION_PATHS = [
    "/login.action",
    "/index.action",
    "/default.action",
    "/home.action",
    "/user/login.action",
    "/system/login.action",
    "/login.do",
    "/index.do",
]

STRUTS_RE = re.compile(r"org\.apache\.struts|struts2|struts\-default|struts\.action", re.I)
OGNL_RE = re.compile(r"ognl|OgnlException|java\.lang\.runtimeexception.*ognl", re.I)
XWORK_RE = re.compile(r"com\.opensymphony\.xwork2|com\.opensymphony\.webwork", re.I)


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
    base = base_site(url)

    found_action = False
    for path in ACTION_PATHS:
        target = base + path
        status, body, err, ms = fetch(target)
        if err or status in (0, 404):
            continue
        if status < 500:
            found_action = True
        if STRUTS_RE.search(body) or XWORK_RE.search(body):
            signals.append(Signal(host=host, port=port, signal_type="struts_marker",
                                  detail=f"{path} error/body mentions struts/xwork2",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))
        if OGNL_RE.search(body):
            signals.append(Signal(host=host, port=port, signal_type="ognl_error",
                                  detail=f"{path} shows OGNL-related error (needs manual S2 review)",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))

    if found_action:
        signals.append(Signal(host=host, port=port, signal_type="action_suffix",
                              detail="app responds on .action/.do paths (Struts2 or compatible)",
                              url=base, status=200, duration_ms=0, observed_at=obs))

    return signals


def main() -> int:
    ap = argparse.ArgumentParser(description="Low-impact Struts2 triage")
    ap.add_argument("--input", help="file with target URLs")
    ap.add_argument("--url", help="single target URL")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "outputs" / "struts2_triage"))
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
    sig_path = out_dir / "struts2_signals.jsonl"
    cand_path = out_dir / "struts2_candidates.jsonl"
    queue_path = out_dir / "struts2_manual_queue.csv"
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
            marker_cnt = sum(1 for s in sigs if s.signal_type in ("struts_marker", "ognl_error"))
            action_cnt = sum(1 for s in sigs if s.signal_type == "action_suffix")
            if args.require_2_signals:
                if not (marker_cnt >= 1 and action_cnt >= 1):
                    continue
            elif not (marker_cnt >= 1 or action_cnt >= 1):
                continue
            if hostkey in seen:
                continue
            seen.add(hostkey)
            cand = {"host": hostkey, "product": "struts2", "signal_count": len(sigs),
                    "signals": [s.__dict__ for s in sigs], "observed_at": now_iso(), "status": "candidate"}
            append_jsonl(cand_path, cand)
            w.writerow([hostkey, len(sigs), " | ".join(s.detail for s in sigs[:4]),
                        "Struts2Scan.py (tools/managed/struts2scan) or nuclei struts2 cves templates",
                        "YES"])

    print(f"scanned={len(urls)} signals={len(all_signals)} candidates={len(seen)}")
    print(f"signal jsonl : {sig_path}")
    print(f"candidates   : {cand_path}")
    print(f"manual queue : {queue_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
