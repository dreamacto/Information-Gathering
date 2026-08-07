#!/usr/bin/env python3
"""Bounded read-only confirmation for discovered API endpoints.

This stage confirms only low-risk GET-looking endpoints extracted by
`api_discovery.py`. It records status, type, length, hash, title, and JSON shape
metadata. It does not submit request bodies or store response content.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

from api_discovery import append_jsonl, business_value_score, classify_endpoint, fetch, fetch_record, now_iso


RISKY_ENDPOINT_RE = re.compile(
    r"(/|\b)(upload|import|export|download|delete|remove|drop|update|modify|edit|save|create|add|submit|"
    r"pay|payment|refund|send|mail|sms|reset|password|passwd|logout|file|attachment)(/|\b|[A-Z_-])",
    re.I,
)


def read_jsonl(path: Path) -> list[dict]:
    rows = []
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


def endpoint_key(row: dict) -> str:
    return str(row.get("url") or "").rstrip("/")


def json_shape(text: str, content_type: str) -> dict:
    out = {"is_json": "json" in content_type.lower() or text.lstrip().startswith(("{", "["))}
    if not out["is_json"]:
        return out
    try:
        parsed = json.loads(text)
    except Exception:
        out["json_parse_error"] = True
        return out
    if isinstance(parsed, dict):
        out["top_level_type"] = "object"
        out["top_level_keys"] = list(parsed.keys())[:20]
        out["top_level_key_count"] = len(parsed)
        out.update(business_value_score(out["top_level_keys"]))
    elif isinstance(parsed, list):
        out["top_level_type"] = "array"
        out["array_length_sample"] = len(parsed)
        if parsed and isinstance(parsed[0], dict):
            out["first_item_keys"] = list(parsed[0].keys())[:20]
            out.update(business_value_score(out["first_item_keys"]))
    else:
        out["top_level_type"] = type(parsed).__name__
        out.update(business_value_score(type(parsed).__name__))
    return out


def should_confirm(row: dict, threshold: int) -> tuple[bool, str]:
    url = endpoint_key(row)
    if not url:
        return False, "empty_url"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False, "not_http_url"
    path = parsed.path or "/"
    if RISKY_ENDPOINT_RE.search(path):
        return False, "risky_path_keyword"
    score = int(row.get("priority_score") or classify_endpoint(url).get("priority_score") or 0)
    if score < threshold:
        return False, "below_threshold"
    tags = set(row.get("tags") or classify_endpoint(url).get("tags") or [])
    if not tags.intersection({"api", "data_query", "openapi_or_docs", "admin_or_portal", "auth_or_login"}):
        return False, "not_interesting_tag"
    return True, ""


def load_candidates(run_dir: Path, threshold: int, max_per_target: int, force: bool) -> list[dict]:
    completed = set()
    if not force:
        completed = {endpoint_key(row) for row in read_jsonl(run_dir / "api_confirmed.jsonl")}
    accepted: list[dict] = []
    per_base: dict[str, int] = defaultdict(int)
    rows = sorted(
        read_jsonl(run_dir / "api_candidates.jsonl"),
        key=lambda row: int(row.get("priority_score") or 0),
        reverse=True,
    )
    for row in rows:
        url = endpoint_key(row)
        if not url or url in completed:
            continue
        ok, reason = should_confirm(row, threshold)
        if not ok:
            append_jsonl(run_dir / "api_confirm_skips.jsonl", {
                "checked_at": now_iso(),
                "url": url,
                "base_url": row.get("base_url"),
                "reason": reason,
            })
            continue
        base = str(row.get("base_url") or urlparse(url).netloc)
        if per_base[base] >= max_per_target:
            continue
        per_base[base] += 1
        accepted.append(row)
    return accepted


def confirm_endpoint(row: dict, run_dir: Path, timeout: int) -> dict:
    tmp_dir = run_dir / ".api_confirm_tmp"
    result = fetch(endpoint_key(row), timeout, min(4, timeout), tmp_dir)
    record = fetch_record(result, "api_confirm", urlparse(result.url).path)
    record.update({
        "base_url": row.get("base_url"),
        "source_priority_score": row.get("priority_score"),
        "source_tags": row.get("tags", []),
        "source_business_value_score": row.get("business_value_score", 0),
        "source_business_value_reasons": row.get("business_value_reasons", []),
    })
    record.update(json_shape(result.text[:262144], result.content_type))
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded read-only API endpoint confirmation")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=2.0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--max-per-target", type=int, default=8)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    candidates = load_candidates(args.run_dir, args.threshold, args.max_per_target, args.force)
    manifest = {
        "created_at": now_iso(),
        "candidate_count": len(candidates),
        "threshold": args.threshold,
        "max_per_target": args.max_per_target,
        "delay": args.delay,
        "timeout": args.timeout,
    }
    (args.run_dir / "api_confirm_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for row in candidates:
        record = confirm_endpoint(row, args.run_dir, args.timeout)
        append_jsonl(args.run_dir / "api_confirmed.jsonl", record)
        if int(record.get("status") or 0) == 200 and record.get("is_json") and not record.get("json_parse_error"):
            interesting = dict(record)
            interesting["finding"] = "api_endpoint_json_confirmed"
            append_jsonl(args.run_dir / "api_interesting.jsonl", interesting)
        time.sleep(args.delay)
    print(json.dumps({"confirmed": len(candidates), "run_dir": str(args.run_dir)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
