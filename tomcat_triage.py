#!/usr/bin/env python3
"""Low-impact Tomcat / WebLogic / JBoss triage for authorized run directories.

This stage identifies targets that run a Java application container. It only
sends read-only GET/HEAD requests to a small set of well-known management paths
and checks TCP port reachability (8009 AJP / 7001 WebLogic / 8080 JBoss). It
does NOT attempt PUT uploads, deploy WARs, test default credentials, or send
deserialization payloads. Container exploitation is approval-gated and manual.
"""

from __future__ import annotations

import argparse
import csv
import re
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import urllib.request
import urllib.error
import ssl

from api_discovery import append_jsonl, now_iso, title_of


USER_AGENT = "Authorized-Container-Triage/1.0"

TOMCAT_PATHS = ["/manager/html", "/host-manager/html", "/docs/", "/examples/"]
WEBLOGIC_PATHS = ["/console", "/console/login/LoginForm.jsp", "/wls-wsat/CoordinatorPortType", "/weblogic/ready"]
JBOSS_PATHS = ["/web-console/", "/jmx-console/", "/admin-console/", "/invoker/JMXInvokerServlet"]

TOMCAT_HEADER_RE = re.compile(r"Apache-Coyote|Tomcat|tomcat", re.I)
WEBLOGIC_HEADER_RE = re.compile(r"WebLogic|weblogic|BEA-", re.I)
JBOSS_HEADER_RE = re.compile(r"JBoss|jboss", re.I)

# (signal_type, port, family label) - pure TCP connect probes, no data sent.
TCP_PROBES = [
    ("ajp_8009", 8009, "Tomcat AJP"),
    ("weblogic_7001", 7001, "WebLogic"),
    ("jboss_8080", 8080, "JBoss"),
]


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


def fetch(url: str, timeout: float = 10.0) -> tuple[int, str, str, float, dict]:
    """Minimal urllib GET. Returns (status, body_sample, error, duration_ms, headers)."""
    started = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(6144).decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, "", int((time.monotonic() - started) * 1000), hdrs
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2048).decode("utf-8", "replace")
        except Exception:
            body = ""
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, body, "", int((time.monotonic() - started) * 1000), hdrs
    except Exception as e:
        return 0, "", str(e), int((time.monotonic() - started) * 1000), {}


def tcp_open(host: str, port: int, timeout: float = 3.0) -> tuple[bool, int]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, int((time.monotonic() - started) * 1000)
    except Exception:
        return False, int((time.monotonic() - started) * 1000)


def probe_url(url: str) -> list[Signal]:
    signals: list[Signal] = []
    host = urlparse(url).hostname or url
    port = str(urlparse(url).port or ("443" if url.startswith("https") else "80"))
    obs = now_iso()
    base = base_site(url)

    status, body, err, ms, hdrs = fetch(base)
    if not err:
        server = hdrs.get("server", "")
        if TOMCAT_HEADER_RE.search(server):
            signals.append(Signal(host=host, port=port, signal_type="tomcat_header",
                                  detail=f"Server header: {server[:80]}",
                                  url=base, status=status, duration_ms=ms, observed_at=obs))
        if WEBLOGIC_HEADER_RE.search(server):
            signals.append(Signal(host=host, port=port, signal_type="weblogic_header",
                                  detail=f"Server header: {server[:80]}",
                                  url=base, status=status, duration_ms=ms, observed_at=obs))
        if JBOSS_HEADER_RE.search(server):
            signals.append(Signal(host=host, port=port, signal_type="jboss_header",
                                  detail=f"Server header: {server[:80]}",
                                  url=base, status=status, duration_ms=ms, observed_at=obs))

    for path in TOMCAT_PATHS:
        target = base + path
        status, body, err, ms, _ = fetch(target)
        if err or status in (0, 404):
            continue
        if path in ("/manager/html", "/host-manager/html") and status == 401:
            signals.append(Signal(host=host, port=port, signal_type="tomcat_manager",
                                  detail=f"{path} reachable but auth required ({status}); weak-credential check is approval-gated",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))
        elif path in ("/manager/html", "/host-manager/html") and status in (200, 302):
            signals.append(Signal(host=host, port=port, signal_type="tomcat_manager_open",
                                  detail=f"{path} reachable WITHOUT auth ({status}); manual review required",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))
        elif path == "/docs/" and status == 200:
            signals.append(Signal(host=host, port=port, signal_type="tomcat_docs",
                                  detail="default /docs/ present (default install indicator)",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))

    for path in WEBLOGIC_PATHS:
        target = base + path
        status, body, err, ms, _ = fetch(target)
        if err or status in (0, 404):
            continue
        if path in ("/console", "/console/login/LoginForm.jsp") and status in (200, 302):
            signals.append(Signal(host=host, port=port, signal_type="weblogic_console",
                                  detail=f"{path} reachable ({status}); WebLogic console exposed",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))
        elif status in (200, 302):
            signals.append(Signal(host=host, port=port, signal_type="weblogic_path",
                                  detail=f"{path} responds {status}",
                                  url=target, status=status, duration_ms=ms, observed_at=obs))

    for path in JBOSS_PATHS:
        target = base + path
        status, body, err, ms, _ = fetch(target)
        if err or status in (0, 404):
            continue
        signals.append(Signal(host=host, port=port, signal_type="jboss_path",
                              detail=f"{path} responds {status}",
                              url=target, status=status, duration_ms=ms, observed_at=obs))

    for sig_type, port_no, family in TCP_PROBES:
        opened, ms = tcp_open(host, port_no)
        if opened:
            signals.append(Signal(host=host, port=port, signal_type=sig_type,
                                  detail=f"TCP port {port_no} open ({family}); manual review required",
                                  url=f"{base}:{port_no}", status=0, duration_ms=ms, observed_at=obs))

    return signals


def main() -> int:
    ap = argparse.ArgumentParser(description="Low-impact Tomcat/WebLogic/JBoss triage")
    ap.add_argument("--input", help="file with target URLs (one per line)")
    ap.add_argument("--url", help="single target URL")
    ap.add_argument("--limit", type=int, default=0, help="max targets to scan (0=all)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--dry-run", action="store_true", help="do not send any request")
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "outputs" / "tomcat_triage"))
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
    sig_path = out_dir / "container_signals.jsonl"
    cand_path = out_dir / "container_candidates.jsonl"
    queue_path = out_dir / "container_manual_queue.csv"
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
            high = any(s.signal_type in ("tomcat_manager_open",) for s in sigs)
            cand = {"host": hostkey, "product": "tomcat|weblogic|jboss", "signal_count": len(sigs),
                    "signals": [s.__dict__ for s in sigs], "observed_at": now_iso(), "status": "candidate"}
            append_jsonl(cand_path, cand)
            w.writerow([hostkey, len(sigs), " | ".join(s.detail for s in sigs[:5]),
                        "nuclei tomcat/weblogic/jboss templates (ghostcat 1938, 2725, 14882, 2894, 21839)",
                        "YES" if high else "NO"])

    print(f"scanned={len(urls)} signals={len(all_signals)} candidates={len(seen)}")
    print(f"signal jsonl : {sig_path}")
    print(f"candidates   : {cand_path}")
    print(f"manual queue : {queue_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
