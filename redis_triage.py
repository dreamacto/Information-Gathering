#!/usr/bin/env python3
"""Low-impact Redis / ZooKeeper / Elasticsearch triage for authorized run directories.

This stage identifies data-store services (Redis 6379, ZooKeeper 2181,
Elasticsearch 9200) that are reachable from the scan vantage point. It sends at
most one benign protocol handshake per service: PING for Redis, a TCP connect
for ZooKeeper, GET / for Elasticsearch. It does NOT execute Redis commands
(config/set/save), write SSH keys or crontabs, download ES indexes, or use
four-letter words. Exploitation is approval-gated and manual.
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

from api_discovery import append_jsonl, now_iso, title_of


USER_AGENT = "Authorized-Store-Triage/1.0"

REDIS_PING = b"PING\r\n"
ZK_NO_DATA = b""
ES_MARKER_RE = re.compile(r"\"cluster_name\"|\"tagline\"\s*:\s*\"You Know, for Search\"", re.I)


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


def host_of(url: str) -> str:
    p = urlparse(url)
    if p.hostname:
        return p.hostname
    return url.split(":")[0].strip()


def redis_ping(host: str, timeout: float = 4.0) -> tuple[bool, str, int]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, 6379), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(REDIS_PING)
            data = sock.recv(64)
            ok = data.startswith(b"+PONG")
            return ok, "", int((time.monotonic() - started) * 1000)
    except Exception as e:
        return False, str(e), int((time.monotonic() - started) * 1000)


def tcp_connect(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str, int]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "", int((time.monotonic() - started) * 1000)
    except Exception as e:
        return False, str(e), int((time.monotonic() - started) * 1000)


def es_root(host: str, timeout: float = 8.0) -> tuple[int, str, str, int]:
    started = time.monotonic()
    import urllib.request
    import urllib.error
    import ssl
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"http://{host}:9200/"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4096).decode("utf-8", "replace")
            return resp.status, body, "", int((time.monotonic() - started) * 1000)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(512).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, "", int((time.monotonic() - started) * 1000)
    except Exception as e:
        return 0, "", str(e), int((time.monotonic() - started) * 1000)


def probe_url(url: str) -> list[Signal]:
    signals: list[Signal] = []
    host = host_of(url)
    obs = now_iso()

    ok, err, ms = redis_ping(host)
    if ok:
        signals.append(Signal(host=host, port="6379", signal_type="redis_unauth",
                              detail="Redis replies +PONG without AUTH (no password gate detected)",
                              url=f"redis://{host}:6379", status=0, duration_ms=ms, observed_at=obs))

    ok, err, ms = tcp_connect(host, 2181)
    if ok:
        signals.append(Signal(host=host, port="2181", signal_type="zookeeper_port_open",
                              detail="ZooKeeper port 2181 accepts TCP connection (no auth check performed)",
                              url=f"tcp://{host}:2181", status=0, duration_ms=ms, observed_at=obs))

    status, body, err, ms = es_root(host)
    if not err and status and status < 500:
        if ES_MARKER_RE.search(body):
            signals.append(Signal(host=host, port="9200", signal_type="es_unauth",
                                  detail=f"Elasticsearch / responds {status} with ES marker (no auth gate detected)",
                                  url=f"http://{host}:9200/", status=status, duration_ms=ms, observed_at=obs))
        elif status == 200:
            signals.append(Signal(host=host, port="9200", signal_type="es_http",
                                  detail=f"port 9200 responds {status} on / (ES-like, no marker)",
                                  url=f"http://{host}:9200/", status=status, duration_ms=ms, observed_at=obs))

    return signals


def main() -> int:
    ap = argparse.ArgumentParser(description="Low-impact Redis/ZK/ES triage")
    ap.add_argument("--input", help="file with target hosts/URLs (one per line)")
    ap.add_argument("--url", help="single target host or URL")
    ap.add_argument("--limit", type=int, default=0, help="max targets to scan (0=all)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--dry-run", action="store_true", help="do not send any request")
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "outputs" / "redis_triage"))
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
    sig_path = out_dir / "store_signals.jsonl"
    cand_path = out_dir / "store_candidates.jsonl"
    queue_path = out_dir / "store_manual_queue.csv"
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
        by_host.setdefault(f"{s.host}", []).append(s)

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
            high = any(s.signal_type in ("redis_unauth", "es_unauth") for s in sigs)
            cand = {"host": hostkey, "product": "redis|zookeeper|elasticsearch", "signal_count": len(sigs),
                    "signals": [s.__dict__ for s in sigs], "observed_at": now_iso(), "status": "candidate"}
            append_jsonl(cand_path, cand)
            w.writerow([hostkey, len(sigs), " | ".join(s.detail for s in sigs[:4]),
                        "nuclei redis/elasticsearch templates, redis-cli manual (write ops approval-gated)",
                        "YES" if high else "NO"])

    print(f"scanned={len(urls)} signals={len(all_signals)} candidates={len(seen)}")
    print(f"signal jsonl : {sig_path}")
    print(f"candidates   : {cand_path}")
    print(f"manual queue : {queue_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
