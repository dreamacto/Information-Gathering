#!/usr/bin/env python3
"""Build a high-value review queue from a run directory.

This is offline result reduction: it does not touch targets. The goal is to
avoid missing valuable targets when a background run produces many JSONL files.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


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


def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def add_item(items: dict[str, dict], url: str, score: int, reason: str, source: str, evidence: dict | None = None) -> None:
    if not url:
        return
    key = url.rstrip("/")
    item = items.setdefault(key, {
        "url": key,
        "host": host_of(key),
        "score": 0,
        "reasons": [],
        "sources": [],
        "evidence": [],
    })
    item["score"] += score
    item["reasons"].append(reason)
    item["sources"].append(source)
    if evidence:
        item["evidence"].append(evidence)


def build_priority_items(run_dir: Path) -> list[dict]:
    items: dict[str, dict] = {}
    false_positive_paths = {
        ((row.get("base_url") or row.get("url") or "").rstrip("/"), row.get("path") or "")
        for row in read_jsonl(run_dir / "false_positive_exposures.jsonl")
    }

    for row in read_jsonl(run_dir / "verified_exposures.jsonl"):
        base = row.get("base_url") or row.get("url")
        kind = row.get("kind", "verified")
        score = int(row.get("verification_score") or 0)
        add_item(items, base, 10 + score, f"verified_{kind}", "verified_exposures", {
            "path": row.get("path"),
            "status": row.get("status"),
            "keyword_hits": row.get("body_keyword_hits", []),
        })

    for row in read_jsonl(run_dir / "candidate_exposures.jsonl"):
        base = row.get("base_url") or row.get("url")
        kind = str(row.get("kind") or "candidate")
        path = str(row.get("path") or "")
        status = int(row.get("status") or 0)
        if ((base or "").rstrip("/"), path) in false_positive_paths:
            continue
        if status in (200, 206):
            weight = 2
            if any(token in kind for token in ("config", "git", "actuator", "swagger", "druid")):
                weight += 2
            if row.get("body_keyword_hits"):
                weight += 3
            add_item(items, base, weight, f"candidate_{kind}", "candidate_exposures", {
                "path": path,
                "status": status,
                "keyword_hits": row.get("body_keyword_hits", []),
            })

    for row in read_jsonl(run_dir / "impact_candidates.jsonl"):
        base = row.get("base_url") or row.get("url")
        finding = str(row.get("finding") or "impact")
        weight = 4
        if finding == "openapi_json_with_paths":
            weight = 12 if int(row.get("path_count") or 0) >= 10 else 8
        elif finding == "source_map_reference":
            weight = 7
        elif finding == "js_sensitive_keyword":
            weight = 6
        elif finding == "high_priority_endpoint":
            weight = 5
        add_item(items, base, weight, finding, "impact_candidates", {
            "url": row.get("url"),
            "path_count": row.get("path_count"),
            "tags": row.get("tags", []),
            "priority": row.get("priority"),
        })

    for row in read_jsonl(run_dir / "api_candidates.jsonl"):
        url = row.get("url")
        score = int(row.get("priority_score") or 0)
        if score >= 5:
            add_item(items, row.get("base_url") or url, score, "api_candidate", "api_candidates", {
                "url": url,
                "tags": row.get("tags", []),
                "priority_score": score,
            })

    for row in read_jsonl(run_dir / "api_interesting.jsonl"):
        url = row.get("base_url") or row.get("url")
        weight = 9
        if int(row.get("top_level_key_count") or 0) >= 5:
            weight += 2
        add_item(items, url, weight, "api_endpoint_json_confirmed", "api_interesting", {
            "url": row.get("url"),
            "status": row.get("status"),
            "top_level_type": row.get("top_level_type"),
            "top_level_keys": row.get("top_level_keys", [])[:10],
            "source_tags": row.get("source_tags", []),
        })

    for row in read_jsonl(run_dir / "shiro_candidates.jsonl"):
        confidence = str(row.get("confidence") or "").lower()
        weight = {"high": 10, "medium": 7, "low": 4}.get(confidence, 4)
        add_item(items, row.get("url"), weight, f"shiro_{confidence or 'candidate'}", "shiro_candidates", {
            "signals": row.get("signals", []),
            "manual_check_recommended": bool(row.get("manual_check_recommended")),
        })

    for row in read_jsonl(run_dir / "xss_reflection_checks.jsonl"):
        if not row.get("marker_reflected"):
            continue
        confidence = str(row.get("confidence") or "low").lower()
        weight = {"medium": 6, "low": 3}.get(confidence, 3)
        add_item(items, row.get("url") or row.get("probe_url"), weight, f"xss_reflection_{confidence}", "xss_reflection_checks", {
            "param": row.get("param"),
            "reflection_context": row.get("reflection_context"),
            "manual_check_recommended": bool(row.get("manual_check_recommended")),
        })

    auth_queue_path = run_dir / "manual_auth_queue.json"
    if auth_queue_path.exists():
        try:
            auth_queue = json.loads(auth_queue_path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            auth_queue = {}
        for row in auth_queue.get("items", []):
            weight = 5 if row.get("registration_candidate") else 3
            add_item(items, row.get("base_url"), weight, "manual_authenticated_review_pending", "manual_auth_queue", {
                "registration_candidate": bool(row.get("registration_candidate")),
                "evidence_urls": row.get("evidence_urls", [])[:3],
            })

    for row in read_jsonl(run_dir / "authenticated_impact_candidates.jsonl"):
        finding = str(row.get("finding") or "authenticated_impact")
        weight = {
            "authenticated_json_sensitive_schema": 14,
            "authenticated_boundary_opened_json_api": 12,
            "authenticated_file_or_export_candidate": 10,
            "authenticated_source_map_reference": 7,
            "authenticated_js_sensitive_keywords": 6,
        }.get(finding, 6)
        add_item(items, row.get("base_url") or row.get("url"), weight, finding, "authenticated_impact_candidates", {
            "url": row.get("url"),
            "status": row.get("status"),
            "sensitive_field_names": row.get("sensitive_field_names", [])[:15],
            "priority": row.get("priority"),
        })

    for row in read_jsonl(run_dir / "fingerprints.jsonl"):
        url = row.get("url")
        cats = set(row.get("categories") or [])
        weight = 0
        reasons = []
        for cat, cat_weight in {
            "api": 4,
            "login": 3,
            "oa": 4,
            "java": 2,
            "net": 2,
            "php": 1,
            "ai": 3,
            "bigscreen": 2,
        }.items():
            if cat in cats:
                weight += cat_weight
                reasons.append(cat)
        if weight:
            add_item(items, url, weight, "fingerprint_" + ",".join(reasons), "fingerprints", {
                "categories": sorted(cats),
                "title": row.get("title"),
                "server": row.get("server"),
            })

    for row in read_jsonl(run_dir / "tool_triage_nuclei_impact.jsonl"):
        url = row.get("host") or row.get("matched-at") or row.get("url")
        severity = str(row.get("info", {}).get("severity") or row.get("severity") or "").lower()
        weight = {"info": 2, "low": 4, "medium": 8, "high": 12, "critical": 16}.get(severity, 3)
        add_item(items, url, weight, f"nuclei_{severity or 'finding'}", "tool_triage_nuclei", {
            "template": row.get("template-id") or row.get("template"),
            "matched": row.get("matched-at") or row.get("url"),
            "severity": severity,
        })

    output = []
    for item in items.values():
        item["reasons"] = sorted(set(item["reasons"]))
        item["sources"] = sorted(set(item["sources"]))
        item["evidence"] = item["evidence"][:12]
        if item["score"] >= 5:
            output.append(item)
    output.sort(key=lambda item: (-item["score"], item["host"], item["url"]))
    return output


def write_markdown(run_dir: Path, items: list[dict]) -> Path:
    reports = run_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    path = reports / "priority_review.md"
    lines = [
        "# Priority Review Queue",
        "",
        f"- Generated: {now_iso()}",
        f"- Run dir: `{run_dir}`",
        f"- Items: {len(items)}",
        "",
        "| Rank | Score | Host | URL | Reasons | Sources |",
        "| --- | ---: | --- | --- | --- | --- |",
    ]
    for idx, item in enumerate(items[:100], 1):
        reasons = ", ".join(item["reasons"])[:180]
        sources = ", ".join(item["sources"])
        lines.append(f"| {idx} | {item['score']} | `{item['host']}` | `{item['url']}` | {reasons} | {sources} |")
    lines.extend([
        "",
        "## Review Notes",
        "",
        "- Prefer items with `verified_`, `authenticated_json_sensitive_schema`, `authenticated_file_or_export_candidate`, `openapi_json_with_paths`, `source_map_reference`, `js_sensitive_keyword`, `api_candidate`, `xss_reflection_*`, and `nuclei_*` reasons.",
        "- A high score is a review priority, not a vulnerability claim. Confirm with screenshots and minimal proof before reporting.",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def build_priority_outputs(run_dir: Path) -> dict:
    items = build_priority_items(run_dir)
    json_path = run_dir / "priority_targets.json"
    json_path.write_text(json.dumps({
        "generated_at": now_iso(),
        "run_dir": str(run_dir),
        "count": len(items),
        "items": items,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path = write_markdown(run_dir, items)
    return {"json": str(json_path), "markdown": str(md_path), "count": len(items)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build offline high-value target review queue")
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_priority_outputs(args.run_dir), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
