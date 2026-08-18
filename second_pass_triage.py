#!/usr/bin/env python3
"""Second-pass lightweight confirmation for high-value triage candidates.

This module deliberately stays in the "candidate screening" lane.  It repeats
only bounded GET-style checks that the main workflow already performed:

- SQLi: rerun the tiny differential probe set for existing SQLi candidates.
- XSS: rerun one inert marker reflection check for previously reflected params.
- API: refetch already-confirmed GET-like JSON endpoints and compare metadata.

It does not run sqlmap, script payloads, stored-XSS submissions, POST bodies,
database enumeration, exports, downloads, or response-body persistence.
"""

from __future__ import annotations

import argparse
import csv
import json
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from api_discovery import append_jsonl, fetch, now_iso
from api_endpoint_confirm import json_shape, should_confirm
from sqli_triage import UrlParam, analyze_probe as analyze_sqli_probe
from xss_candidate_triage import analyze_reflection, endpoint_key as xss_key, load_url_params


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def confidence_tier(score: int) -> str:
    if score >= 85:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    return "P3"


def host_of(url: str) -> str:
    return (urlparse(url).hostname or urlparse(url).netloc or "").lower()


def sql_candidate_score(row: dict) -> int:
    signals = set(row.get("signals") or [])
    confidence = str(row.get("confidence") or "none")
    if row.get("high_probability"):
        return 88
    if any(str(signal).startswith("db_error_signature") for signal in signals):
        return 86
    if "boolean_differential" in signals:
        return 84
    if confidence == "medium":
        return 62
    if confidence == "low":
        return 45
    return 20


def run_sql_second_pass(run_dir: Path, delay: float, timeout: int, limit: int, force: bool) -> tuple[int, int]:
    source_rows = read_jsonl(run_dir / "sqli_candidates.jsonl")
    source_rows.sort(key=sql_candidate_score, reverse=True)
    if limit:
        source_rows = source_rows[:limit]
    completed = set()
    if not force:
        completed = {
            f"{row.get('url')}#{row.get('param')}{'@POST' if (row.get('method') or 'GET').upper() == 'POST' else ''}"
            for row in read_jsonl(run_dir / "second_pass_results.jsonl")
            if row.get("family") == "sqli"
        }
    tested = 0
    confirmed = 0
    for row in source_rows:
        url = str(row.get("url") or "")
        param = str(row.get("param") or "")
        if not url or not param or f"{url}#{param}{'@POST' if (row.get('method') or 'GET').upper() == 'POST' else ''}" in completed:
            continue
        tested += 1
        try:
            second = analyze_sqli_probe(
                UrlParam(
                    url=url,
                    param=param,
                    base_url=str(row.get("base_url") or ""),
                    source="second_pass",
                    priority_score=int(row.get("source_priority_score") or 0),
                    method=str(row.get("method") or "GET").upper(),
                    body=str(row.get("body") or ""),
                ),
                run_dir,
                timeout,
                delay,
            )
        except Exception as exc:  # noqa: BLE001
            second = {
                "checked_at": now_iso(),
                "url": url,
                "param": param,
                "signals": ["second_pass_error"],
                "confidence": "none",
                "high_probability": False,
                "error": str(exc)[:300],
            }
        stable = bool(second.get("high_probability")) or (
            row.get("high_probability")
            and set(row.get("signals") or []).intersection(set(second.get("signals") or []))
        )
        score = max(sql_candidate_score(row), sql_candidate_score(second))
        if stable:
            score = max(score, 88)
            confirmed += 1
        result = {
            "checked_at": now_iso(),
            "family": "sqli",
            "url": url,
            "param": param,
            "host": host_of(url),
            "stable": stable,
            "priority": confidence_tier(score),
            "score": score,
            "original_confidence": row.get("confidence"),
            "original_signals": row.get("signals", []),
            "second_confidence": second.get("confidence"),
            "second_signals": second.get("signals", []),
            "notes": "Second pass reran the same tiny differential GET probe set. Still a candidate, not a confirmed SQL injection claim.",
        }
        append_jsonl(run_dir / "second_pass_results.jsonl", result)
        if stable:
            append_jsonl(run_dir / "second_pass_confirmed.jsonl", result)
    return tested, confirmed


def run_xss_second_pass(run_dir: Path, delay: float, timeout: int, limit: int, force: bool) -> tuple[int, int]:
    reflected = [
        row for row in read_jsonl(run_dir / "xss_reflection_checks.jsonl")
        if row.get("marker_reflected") and row.get("source_key_sha256")
    ]
    reflected.sort(key=lambda row: (row.get("confidence") != "medium", row.get("host") or "", row.get("param") or ""))
    wanted = {str(row.get("source_key_sha256")) for row in reflected[:limit or None]}
    if not wanted:
        return 0, 0
    completed = set()
    if not force:
        completed = {
            str(row.get("source_key_sha256"))
            for row in read_jsonl(run_dir / "second_pass_results.jsonl")
            if row.get("family") == "xss"
        }
    candidates = [
        candidate
        for candidate in load_url_params(run_dir, max_params_per_url=3, max_per_host=1000, limit=0, force=True)
        if xss_key(candidate.url, candidate.param) in wanted
        and xss_key(candidate.url, candidate.param) not in completed
    ]
    marker_prefix = "xss2_" + uuid.uuid4().hex[:10]
    tested = 0
    confirmed = 0
    for index, candidate in enumerate(candidates, 1):
        marker = f"{marker_prefix}_{index}"
        tested += 1
        try:
            second = analyze_reflection(candidate, run_dir, timeout, delay, marker)
        except Exception as exc:  # noqa: BLE001
            second = {
                "checked_at": now_iso(),
                "source_key_sha256": xss_key(candidate.url, candidate.param),
                "param": candidate.param,
                "host": host_of(candidate.url),
                "signals": ["second_pass_error"],
                "confidence": "none",
                "marker_reflected": False,
                "error": str(exc)[:300],
            }
        stable = bool(second.get("marker_reflected"))
        medium_context = second.get("confidence") == "medium"
        score = 86 if stable and medium_context else 72 if stable else 35
        if stable:
            confirmed += 1
        result = {
            "checked_at": now_iso(),
            "family": "xss",
            "source_key_sha256": xss_key(candidate.url, candidate.param),
            "host": host_of(candidate.url),
            "param": candidate.param,
            "stable": stable,
            "priority": confidence_tier(score),
            "score": score,
            "second_confidence": second.get("confidence"),
            "reflection_context": second.get("reflection_context"),
            "signals": second.get("signals", []),
            "url": second.get("url"),
            "probe_url": second.get("probe_url"),
            "notes": "Second pass sent one new inert marker in the same GET parameter. Reflected marker remains a manual-review lead.",
        }
        append_jsonl(run_dir / "second_pass_results.jsonl", result)
        if stable:
            append_jsonl(run_dir / "second_pass_confirmed.jsonl", result)
    return tested, confirmed


def api_stability_score(first: dict, second: dict) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if int(first.get("status") or 0) == int(second.get("status") or 0) and int(second.get("status") or 0) in (200, 206):
        score += 25
        reasons.append("stable_200_status")
    if second.get("is_json") and not second.get("json_parse_error"):
        score += 25
        reasons.append("json_shape_confirmed")
    if first.get("top_level_keys") and second.get("top_level_keys"):
        overlap = set(first.get("top_level_keys") or []).intersection(set(second.get("top_level_keys") or []))
        if overlap:
            score += 15
            reasons.append("schema_key_overlap")
    if second.get("business_value_score"):
        score += min(20, int(second.get("business_value_score") or 0) * 2)
        reasons.append("business_value_schema")
    return min(95, score), reasons


def run_api_second_pass(run_dir: Path, delay: float, timeout: int, limit: int, force: bool) -> tuple[int, int]:
    rows: list[dict] = []
    for name in ("api_interesting.jsonl", "api_confirmed.jsonl", "authenticated_api_results.jsonl"):
        for row in read_jsonl(run_dir / name):
            if row.get("url") and int(row.get("status") or 0) in (200, 206):
                rows.append({**row, "_source_file": name})
    rows.sort(key=lambda row: int(row.get("source_priority_score") or row.get("priority_score") or 0), reverse=True)
    if limit:
        rows = rows[:limit]
    completed = set()
    if not force:
        completed = {
            str(row.get("url") or "").rstrip("/")
            for row in read_jsonl(run_dir / "second_pass_results.jsonl")
            if row.get("family") == "api"
        }
    tested = 0
    confirmed = 0
    for row in rows:
        url = str(row.get("url") or "").rstrip("/")
        if not url or url in completed:
            continue
        ok, reason = should_confirm(row, threshold=0)
        if not ok and reason == "risky_path_keyword":
            continue
        tested += 1
        result = fetch(url, timeout, min(4, timeout), run_dir / ".second_pass_tmp")
        second = {
            "url": url,
            "status": result.status,
            "final_url": result.final_url,
            "content_type": result.content_type,
            "content_length": result.content_length,
            "sample_sha256": result.sample_sha256,
            "elapsed_seconds": round(result.elapsed_seconds, 3),
            "error": result.error,
        }
        second.update(json_shape(result.text[:262144], result.content_type))
        score, reasons = api_stability_score(row, second)
        stable = score >= 50
        if stable:
            confirmed += 1
        out = {
            "checked_at": now_iso(),
            "family": "api",
            "url": url,
            "host": host_of(url),
            "stable": stable,
            "priority": confidence_tier(score),
            "score": score,
            "reasons": reasons,
            "source_file": row.get("_source_file"),
            "status": second.get("status"),
            "content_type": second.get("content_type"),
            "sample_sha256": second.get("sample_sha256"),
            "top_level_type": second.get("top_level_type"),
            "top_level_keys": second.get("top_level_keys", []),
            "business_value_score": second.get("business_value_score", 0),
            "business_value_reasons": second.get("business_value_reasons", []),
            "notes": "Second pass refetched an already discovered GET-like endpoint and stored metadata/schema only.",
        }
        append_jsonl(run_dir / "second_pass_results.jsonl", out)
        if stable:
            append_jsonl(run_dir / "second_pass_confirmed.jsonl", out)
        time.sleep(delay)
    return tested, confirmed


def header_key(row: dict) -> str:
    return f"{row.get('host', '')}#{row.get('header', '')}#{row.get('cookie_key') or ''}"


def run_header_second_pass(run_dir: Path, delay: float, timeout: int, limit: int, force: bool,
                           login_data: str | None = None) -> tuple[int, int]:
    from header_reflection_probe import run_probe
    source = [
        row for row in read_jsonl(run_dir / "header_reflection_candidates.jsonl")
        if row.get("url") and row.get("header")
    ]
    if limit:
        source = source[:limit]
    completed: set[str] = set()
    if not force:
        completed = {
            str(row.get("source_key_sha256"))
            for row in read_jsonl(run_dir / "second_pass_results.jsonl")
            if row.get("family") == "header_sqli"
        }
    tested = 0
    confirmed = 0
    for index, row in enumerate(source, 1):
        key = header_key(row)
        if key in completed:
            continue
        tested += 1
        marker = f"hxmk2_{uuid.uuid4().hex[:10]}"
        try:
            second = run_probe(
                str(row.get("url") or ""),
                str(row.get("header") or ""),
                row.get("cookie_key"),
                marker,
                timeout,
                delay,
                run_dir,
                set(),
                login_data,
            )
        except Exception as exc:  # noqa: BLE001
            second = None
            error = str(exc)[:300]
        else:
            error = ""
        stable = bool(second and second.get("reflection_count"))
        score = 86 if stable else 45
        if stable:
            confirmed += 1
        result = {
            "checked_at": now_iso(),
            "family": "header_sqli",
            "source_key_sha256": key,
            "host": str(row.get("host") or ""),
            "url": str(row.get("url") or ""),
            "header": str(row.get("header") or ""),
            "cookie_key": row.get("cookie_key"),
            "stable": stable,
            "priority": confidence_tier(score),
            "score": score,
            "first_reflection_count": row.get("reflection_count"),
            "second_reflection_count": second.get("reflection_count") if second else 0,
            "marker": marker,
            "context_snippet": second.get("context_snippet") if second else "",
            "signals": ["header_marker_reflected"] if stable else ["header_marker_not_restable"],
            "notes": "Second pass sent a fresh inert marker in the same header. Stable reflection remains a manual-review lead for header-context SQLi.",
            "suggest_command": row.get("suggest_command", ""),
        }
        if error:
            result["error"] = error
        append_jsonl(run_dir / "second_pass_results.jsonl", result)
        if stable:
            append_jsonl(run_dir / "second_pass_confirmed.jsonl", result)
    return tested, confirmed


def refresh_markdown(run_dir: Path) -> Path:
    rows = read_jsonl(run_dir / "second_pass_results.jsonl")
    confirmed = [row for row in rows if row.get("stable")]
    lines = [
        "# Second-Pass Triage",
        "",
        f"- Generated: {now_iso()}",
        f"- Results: {len(rows)}",
        f"- Stable candidates: {len(confirmed)}",
        "",
        "| Priority | Family | Host | Target | Stable | Reasons |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in sorted(rows, key=lambda item: (item.get("priority", "P3"), -(int(item.get("score") or 0))))[:200]:
        target = row.get("url") or f"{row.get('host')} param={row.get('param')}"
        reasons = ",".join(row.get("reasons") or row.get("signals") or row.get("second_signals") or [])
        lines.append(
            f"| {row.get('priority', '')} | {row.get('family', '')} | `{row.get('host', '')}` | "
            f"`{str(target).replace('|', '/')[:180]}` | {row.get('stable')} | {reasons[:180]} |"
        )
    lines.extend([
        "",
        "## Boundary",
        "",
        "- SQLi second pass repeats the same tiny differential GET probes; it does not enumerate or dump data.",
        "- XSS second pass uses one new inert marker; it does not send script payloads or stored submissions.",
        "- API second pass stores status, length, hash, and schema metadata only.",
    ])
    out = run_dir / "reports" / "second_pass_review.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Second-pass lightweight candidate confirmation")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--sql-limit", type=int, default=10)
    parser.add_argument("--xss-limit", type=int, default=20)
    parser.add_argument("--api-limit", type=int, default=20)
    parser.add_argument("--header-limit", type=int, default=20)
    parser.add_argument("--header-login-data", default=None)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.force:
        for name in ("second_pass_results.jsonl", "second_pass_confirmed.jsonl"):
            (args.run_dir / name).write_text("", encoding="utf-8")
    elif not (args.run_dir / "second_pass_results.jsonl").exists():
        (args.run_dir / "second_pass_results.jsonl").write_text("", encoding="utf-8")
        (args.run_dir / "second_pass_confirmed.jsonl").write_text("", encoding="utf-8")

    sql_tested, sql_confirmed = run_sql_second_pass(args.run_dir, args.delay, args.timeout, args.sql_limit, args.force)
    xss_tested, xss_confirmed = run_xss_second_pass(args.run_dir, args.delay, args.timeout, args.xss_limit, args.force)
    api_tested, api_confirmed = run_api_second_pass(args.run_dir, args.delay, args.timeout, args.api_limit, args.force)
    header_tested, header_confirmed = run_header_second_pass(
        args.run_dir, args.delay, args.timeout, args.header_limit, args.force, args.header_login_data
    )
    report = refresh_markdown(args.run_dir)
    manifest = {
        "created_at": now_iso(),
        "delay": args.delay,
        "timeout": args.timeout,
        "sql_tested": sql_tested,
        "sql_stable": sql_confirmed,
        "xss_tested": xss_tested,
        "xss_stable": xss_confirmed,
        "api_tested": api_tested,
        "api_stable": api_confirmed,
        "header_sqli_tested": header_tested,
        "header_sqli_stable": header_confirmed,
        "report": str(report),
        "disabled_actions": [
            "sqlmap",
            "database_dump",
            "script_payloads",
            "stored_xss_submit",
            "exports_or_downloads",
            "post_body_mutation",
        ],
    }
    write_json(args.run_dir / "second_pass_manifest.json", manifest)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
