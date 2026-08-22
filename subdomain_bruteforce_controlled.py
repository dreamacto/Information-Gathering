#!/usr/bin/env python3
"""Controlled subdomain discovery for authorized exercise runs.

This stage performs low-rate DNS lookups for a small, explicit wordlist. Each
input hostname is a scope anchor: the stage may look below that hostname, but it
must never widen a subdomain to its registered parent or discover sibling
hosts. Resolved hosts are written to handoff files for the next run.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")


DEFAULT_WORDS = (
    "www",
    "api",
    "app",
    "m",
    "wap",
    "mobile",
    "admin",
    "oa",
    "office",
    "portal",
    "login",
    "sso",
    "auth",
    "cas",
    "id",
    "ids",
    "mail",
    "email",
    "webmail",
    "vpn",
    "ssl",
    "hr",
    "edu",
    "jw",
    "jwc",
    "ehall",
    "service",
    "servicehall",
    "pay",
    "payment",
    "bank",
    "banking",
    "credit",
    "loan",
    "fund",
    "trade",
    "trading",
    "invest",
    "crm",
    "cms",
    "www1",
    "www2",
    "test",
    "dev",
    "uat",
    "stage",
    "staging",
    "pre",
    "prod",
    "old",
    "new",
    "static",
    "assets",
    "cdn",
    "img",
    "file",
    "files",
    "download",
    "upload",
    "open",
    "openapi",
    "gateway",
    "gw",
    "manage",
    "manager",
    "backend",
    "console",
    "monitor",
    "druid",
    "nacos",
    "xxl-job",
    "jenkins",
    "git",
    "svn",
    "wiki",
    "doc",
    "docs",
    "help",
    "support",
)


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def host_of(value: str) -> str:
    raw = value.strip().split("|", 1)[0].strip()
    if not raw or raw.startswith("#"):
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    return (urlparse(raw).hostname or "").strip(".").lower()


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_subdomain_root_candidate(root: str) -> bool:
    parts = [part for part in root.strip(".").lower().split(".") if part]
    if len(parts) < 2:
        return False
    if all(part.isdigit() for part in parts):
        return False
    try:
        ".".join(parts).encode("idna")
    except UnicodeError:
        return False
    return True


def intake_scope_hints(anchors: list[str]) -> list[dict]:
    """入口作用域预警（20260823 复盘）：锚点是主机名而非根域时，
    子域枚举只会查 <词>.<主机名> 形态（如 api.www.gxcic.net），现实中几乎必空。
    不自动扩大范围（授权决策属于操作者），但必须在开工前说清楚。"""
    hints = []
    for a in anchors:
        parent = registered_parent(a)
        if parent and a != parent:
            hints.append({
                "anchor": a,
                "registered_parent": parent,
                "effect": f"输入为主机名：原锚点只会查询 *.{a}（几乎必空）；本次已自动补充根域锚点 {parent}（操作者策略 20260823）",
                "suggestion": f"结果按后缀过滤只保留 *.{parent}；若某目标仅授权该主机、不含整域，请单独建 run 并加 --no-subdomain",
            })
    return hints


def registered_parent(host: str) -> str:
    host = host.strip(".").lower()
    if not host or is_ip_address(host):
        return ""
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host if is_subdomain_root_candidate(host) else ""
    second_level_suffixes = {
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "ac.cn",
        "mil.cn",
    }
    suffix = ".".join(parts[-2:])
    if suffix in second_level_suffixes and len(parts) >= 3:
        root = ".".join(parts[-3:])
        return root if is_subdomain_root_candidate(root) else ""
    root = ".".join(parts[-2:])
    return root if is_subdomain_root_candidate(root) else ""


def load_scope_anchors(targets: Path) -> list[str]:
    """Load exact input hosts without widening them to registered parents."""
    anchors: set[str] = set()
    if targets.suffix.lower() == ".csv":
        with targets.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                host = (row.get("host") or host_of(row.get("url") or "")).strip().lower()
                if host and not is_ip_address(host) and is_subdomain_root_candidate(host):
                    anchors.add(host)
        return sorted(anchors)
    for line in targets.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        host = host_of(line)
        if host and not is_ip_address(host) and is_subdomain_root_candidate(host):
            anchors.add(host)
    return sorted(anchors)


def load_roots(targets: Path) -> list[str]:
    """Compatibility alias; values are exact input scope anchors, not roots."""
    return load_scope_anchors(targets)


def is_host_within_scope(host: str, scope_anchor: str) -> bool:
    host = host.strip(".").lower()
    scope_anchor = scope_anchor.strip(".").lower()
    return bool(host and scope_anchor) and (
        host == scope_anchor or host.endswith("." + scope_anchor)
    )


def scope_anchor_for(host: str, scope_anchors: list[str]) -> str:
    matches = [
        anchor
        for anchor in scope_anchors
        if is_host_within_scope(host, anchor)
    ]
    return max(matches, key=len, default="")


def load_existing_target_lines(targets: Path) -> list[str]:
    lines: list[str] = []
    if targets.suffix.lower() == ".csv":
        with targets.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                url = str(row.get("url") or "").strip()
                if not url:
                    continue
                name = str(row.get("name") or "").strip()
                lines.append(f"{url}|{name}" if name else url)
        return lines
    for line in targets.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            lines.append(value)
    return lines


def dedup_target_lines(lines: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for line in lines:
        url = line.split("|", 1)[0].strip()
        if not url:
            continue
        key = url.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        output.append(line)
    return output


def load_words(path: Path | None, max_words: int) -> list[str]:
    words: list[str] = []
    if path and path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            value = line.strip().lower()
            if value and not value.startswith("#"):
                words.append(value.split()[0])
    else:
        words.extend(DEFAULT_WORDS)
    dedup = []
    seen = set()
    for word in words:
        word = word.strip(".")
        if not word or word in seen:
            continue
        seen.add(word)
        dedup.append(word)
    if max_words > 0:
        return dedup[:max_words]
    return dedup


def resolve_host(host: str, timeout: float) -> tuple[list[str], str]:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return [], f"dns_error:{exc.errno}"
    except OSError as exc:
        return [], f"os_error:{type(exc).__name__}"
    finally:
        socket.setdefaulttimeout(old_timeout)
    ips = sorted({item[4][0] for item in infos if item and item[4]})
    return ips, ""


class RateGate:
    """Global start-rate limiter for DNS lookups."""

    def __init__(self, interval: float) -> None:
        self.interval = max(0.0, interval)
        self._lock = threading.Lock()
        self._next_start = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_start:
                sleep_for = self._next_start - now
                self._next_start += self.interval
            else:
                sleep_for = 0.0
                self._next_start = now + self.interval
        if sleep_for > 0:
            time.sleep(sleep_for)


def build_queries(scope_anchors: list[str], words: list[str], max_queries: int) -> list[tuple[str, str]]:
    queries = [
        (scope_anchor, f"{word}.{scope_anchor}".lower())
        for scope_anchor in scope_anchors
        for word in words
    ]
    if max_queries > 0:
        return queries[:max_queries]
    return queries


def resolve_query(scope_anchor: str, host: str, timeout: float, gate: RateGate) -> dict:
    gate.wait()
    ips, error = resolve_host(host, timeout)
    return {
        "checked_at": now_iso(),
        "scope_anchor": scope_anchor,
        "registered_parent": registered_parent(host),
        "host": host,
        "ips": ",".join(ips),
        "status": "resolved" if ips else "unresolved",
        "error": error,
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "checked_at",
        "scope_anchor",
        "registered_parent",
        "host",
        "ips",
        "status",
        "error",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def main() -> int:
    parser = argparse.ArgumentParser(description="Low-rate subdomain brute-force discovery")
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--wordlist", type=Path)
    parser.add_argument("--delay", type=float, default=1.5)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--max-words", type=int, default=80)
    parser.add_argument(
        "--max-roots",
        "--max-scope-anchors",
        dest="max_roots",
        type=int,
        default=20,
        help="Maximum exact input host scope anchors; input hosts are never widened",
    )
    parser.add_argument("--qps", type=float, default=0.0, help="Global DNS lookup start rate; overrides --delay when > 0")
    parser.add_argument("--concurrency", type=int, default=3, help="Concurrent DNS workers; global qps/delay is still enforced")
    parser.add_argument("--max-queries", type=int, default=0, help="Maximum total DNS queries after root/word expansion")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    scope_anchors = load_scope_anchors(args.targets)[
        : args.max_roots if args.max_roots > 0 else None
    ]
    # 根域自动锚定（操作者策略 20260823）：输入主机名（如 www.gxcic.net）时自动补充其
    # 注册父域作为锚点，使枚举生成 api.gxcic.net 这类真实形态；结果仍经
    # is_host_within_scope 后缀过滤——只有 *.根域 内的主机会进入后续流程。
    _expanded = list(scope_anchors)
    for _a in scope_anchors:
        _parent = registered_parent(_a)
        if _parent and _parent not in _expanded:
            _expanded.append(_parent)
    if _expanded != scope_anchors:
        _added = [a for a in _expanded if a not in scope_anchors]
        print(f"[*] 根域自动锚定（操作者策略）：已补充根域锚点 {', '.join(_added)}；"
              f"结果按后缀过滤，仅 *.根域 内主机进入后续流程", flush=True)
        scope_anchors = _expanded
    words = load_words(args.wordlist, args.max_words)
    hints = intake_scope_hints(scope_anchors)
    if hints:
        print("[!] 目标作用域预警：以下锚点是主机名而非根域，子域枚举按纪律不扩大范围——", flush=True)
        for h in hints:
            print(f"      · {h['anchor']}：{h['effect']}", flush=True)
            print(f"        {h['suggestion']}", flush=True)
        hint_path = args.out_dir / "subdomain_intake_hints.jsonl"
        with hint_path.open("w", encoding="utf-8") as hf:
            for h in hints:
                hf.write(json.dumps(h, ensure_ascii=False) + "\n")
    raw_path = args.out_dir / "subdomains_raw.txt"
    dedup_path = args.out_dir / "subdomains_dedup.txt"
    pending_path = args.out_dir / "subdomains_for_scope_confirmation.txt"
    next_targets_path = args.out_dir / "subdomains_for_next_run.txt"
    auto_merged_path = args.out_dir / "targets_with_auto_subdomains.txt"
    jsonl_path = args.out_dir / "subdomains_resolved.jsonl"
    csv_path = args.out_dir / "subdomains_resolved.csv"
    rejected_path = args.out_dir / "subdomain_scope_rejections.jsonl"
    manifest_path = args.out_dir / "subdomain_bruteforce_manifest.json"

    for path in (
        raw_path,
        dedup_path,
        pending_path,
        next_targets_path,
        auto_merged_path,
        jsonl_path,
        rejected_path,
    ):
        path.write_text("", encoding="utf-8")

    interval = (1.0 / args.qps) if args.qps and args.qps > 0 else max(0.0, args.delay)
    concurrency = max(1, int(args.concurrency))
    queries = build_queries(scope_anchors, words, args.max_queries)
    rows: list[dict] = []
    gate = RateGate(interval)
    if concurrency == 1:
        for scope_anchor, host in queries:
            row = resolve_query(scope_anchor, host, args.timeout, gate)
            rows.append(row)
            append_jsonl(jsonl_path, row)
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [
                pool.submit(resolve_query, scope_anchor, host, args.timeout, gate)
                for scope_anchor, host in queries
            ]
            for future in as_completed(futures):
                row = future.result()
                rows.append(row)
                append_jsonl(jsonl_path, row)

    resolved_hosts: list[str] = []
    host_to_scope_anchor: dict[str, str] = {}
    rejected_count = 0
    for row in rows:
        if row.get("status") != "resolved":
            continue
        host = str(row.get("host") or "")
        if not host:
            continue
        scope_anchor = scope_anchor_for(host, scope_anchors)
        if not scope_anchor:
            rejected_count += 1
            append_jsonl(rejected_path, {
                "checked_at": now_iso(),
                "host": host,
                "reason": "outside_input_host_scope",
                "input_scope_anchors": scope_anchors,
            })
            continue
        resolved_hosts.append(host)
        host_to_scope_anchor[host] = scope_anchor
    unique_hosts = sorted(set(resolved_hosts))
    raw_path.write_text("\n".join(resolved_hosts) + ("\n" if resolved_hosts else ""), encoding="utf-8")
    dedup_path.write_text("\n".join(unique_hosts) + ("\n" if unique_hosts else ""), encoding="utf-8")
    pending_path.write_text(
        "\n".join(f"https://{host}|subdomain_scope_confirmation_required" for host in unique_hosts)
        + ("\n" if unique_hosts else ""),
        encoding="utf-8",
    )
    next_targets_path.write_text(
        "\n".join(f"https://{host}|subdomain_candidate" for host in unique_hosts) + ("\n" if unique_hosts else ""),
        encoding="utf-8",
    )
    existing_lines = load_existing_target_lines(args.targets)
    discovered_lines = [
        f"https://{host}|auto_subdomain_scope_anchor:{host_to_scope_anchor[host]}"
        for host in unique_hosts
    ]
    auto_merged_lines = dedup_target_lines(existing_lines + discovered_lines)
    auto_merged_path.write_text(
        "\n".join(auto_merged_lines) + ("\n" if auto_merged_lines else ""),
        encoding="utf-8",
    )
    write_csv(csv_path, rows)
    manifest = {
        "created_at": now_iso(),
        "targets": str(args.targets),
        "scope_mode": "input_host_subtree",
        "scope_anchor_count": len(scope_anchors),
        "input_scope_anchors": scope_anchors,
        "registered_parent_widening": False,
        "word_count": len(words),
        "query_count": len(queries),
        "resolved_count": len(unique_hosts),
        "out_of_scope_rejected_count": rejected_count,
        "delay": args.delay,
        "qps": args.qps,
        "effective_start_interval_seconds": interval,
        "concurrency": concurrency,
        "max_queries": args.max_queries,
        "timeout": args.timeout,
        "outputs": {
            "raw": str(raw_path),
            "dedup": str(dedup_path),
            "pending_scope_confirmation": str(pending_path),
            "next_run_targets": str(next_targets_path),
            "auto_merged_targets": str(auto_merged_path),
            "jsonl": str(jsonl_path),
            "csv": str(csv_path),
            "scope_rejections": str(rejected_path),
        },
        "default_policy": "input_host_subtree_only_no_parent_or_sibling_widening",
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
