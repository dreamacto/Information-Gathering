#!/usr/bin/env python3
"""Offline run-health metrics for background scans."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return {}


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


def pct(part: int, total: int) -> float:
    return round(part / total, 4) if total else 0.0


def build_health(run_dir: Path) -> dict:
    targets = read_json(run_dir / "targets.json")
    runtime = read_json(run_dir / "runtime_inventory.json")
    priority = read_json(run_dir / "priority_targets.json")
    probes = read_jsonl(run_dir / "probe_results.jsonl")
    candidates = read_jsonl(run_dir / "candidate_exposures.jsonl")
    verified = read_jsonl(run_dir / "verified_exposures.jsonl")
    false_positive = read_jsonl(run_dir / "false_positive_exposures.jsonl")
    api_candidates = read_jsonl(run_dir / "api_candidates.jsonl")
    impact = read_jsonl(run_dir / "impact_candidates.jsonl")
    api_confirmed = read_jsonl(run_dir / "api_confirmed.jsonl")
    api_interesting = read_jsonl(run_dir / "api_interesting.jsonl")
    xss_reflections = read_jsonl(run_dir / "xss_reflection_checks.jsonl")
    shiro_candidates = read_jsonl(run_dir / "shiro_candidates.jsonl")
    authenticated_results = read_jsonl(run_dir / "authenticated_api_results.jsonl")
    authenticated_impact = read_jsonl(run_dir / "authenticated_impact_candidates.jsonl")
    rate_skips = read_jsonl(run_dir / "rate_limit_skips.jsonl")

    status_counts = Counter(str(row.get("status") or "error") for row in probes)
    ok_count = sum(1 for row in probes if row.get("ok"))
    target_count = int(targets.get("count") or 0)
    completed_target_ratio = pct(len({row.get("url") for row in probes if row.get("url")}), target_count)
    false_positive_ratio = pct(len(false_positive), len(false_positive) + len(verified))
    missing_tools = sorted(name for name, path in (runtime.get("tools", {}) or {}).items() if not path)

    score = 100
    recommendations = []
    if target_count and completed_target_ratio < 0.9:
        score -= 20
        recommendations.append("Probe coverage is below 90%; resume this run or inspect failures before trusting negative results.")
    if probes and pct(ok_count, len(probes)) < 0.6:
        score -= 15
        recommendations.append("Probe success ratio is low; network/VPN/DNS quality may be affecting results.")
    if candidates and false_positive_ratio > 0.9:
        score -= 10
        recommendations.append("False-positive ratio is high; prioritize JS/API discovery and body-keyword verification over fixed-path claims.")
    if not api_candidates and not impact:
        score -= 10
        recommendations.append("No API/JS candidates were produced; enable --api-discovery for better depth.")
    auth_queue_count = 0
    auth_queue = read_json(run_dir / "manual_auth_queue.json")
    if auth_queue:
        auth_queue_count = int(auth_queue.get("count") or 0)
    if auth_queue_count and not authenticated_results:
        recommendations.append("Login targets are pending manual registration/login; provide a local session file and resume with --auth-review.")
    if "nuclei" in missing_tools:
        score -= 5
        recommendations.append("Nuclei is not available to the runner; mature template confirmation will be weaker.")
    if rate_skips:
        score -= 5
        recommendations.append("Some hosts hit repeated-error backoff; review rate_limit_skips.jsonl.")

    score = max(0, min(100, score))
    return {
        "generated_at": now_iso(),
        "run_dir": str(run_dir),
        "health_score": score,
        "target_count": target_count,
        "probe_rows": len(probes),
        "probe_unique_urls": len({row.get("url") for row in probes if row.get("url")}),
        "probe_coverage_ratio": completed_target_ratio,
        "probe_ok_ratio": pct(ok_count, len(probes)),
        "probe_status_counts": dict(status_counts),
        "candidate_exposures": len(candidates),
        "verified_exposures": len(verified),
        "false_positive_exposures": len(false_positive),
        "false_positive_ratio": false_positive_ratio,
        "api_candidates": len(api_candidates),
        "impact_candidates": len(impact),
        "api_confirmed": len(api_confirmed),
        "api_interesting": len(api_interesting),
        "xss_reflection_checks": len(xss_reflections),
        "xss_reflected_markers": sum(1 for row in xss_reflections if row.get("marker_reflected")),
        "shiro_candidates": len(shiro_candidates),
        "manual_auth_queue": auth_queue_count,
        "authenticated_api_results": len(authenticated_results),
        "authenticated_impact_candidates": len(authenticated_impact),
        "priority_items": int(priority.get("count") or 0),
        "rate_limit_skips": len(rate_skips),
        "missing_tools": missing_tools,
        "recommendations": recommendations,
    }


def write_markdown(run_dir: Path, health: dict) -> Path:
    reports = run_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    path = reports / "run_health.md"
    lines = [
        "# Run Health",
        "",
        f"- Generated: {health['generated_at']}",
        f"- Score: {health['health_score']}/100",
        f"- Targets: {health['target_count']}",
        f"- Probe coverage: {health['probe_coverage_ratio']}",
        f"- Probe OK ratio: {health['probe_ok_ratio']}",
        f"- Verified / false-positive: {health['verified_exposures']} / {health['false_positive_exposures']}",
        f"- API candidates / impact / confirmed: {health['api_candidates']} / {health['impact_candidates']} / {health['api_confirmed']}",
        f"- XSS reflection checks / reflected markers: {health['xss_reflection_checks']} / {health['xss_reflected_markers']}",
        f"- Shiro candidates: {health['shiro_candidates']}",
        f"- Manual auth queue / authenticated impact: {health['manual_auth_queue']} / {health['authenticated_impact_candidates']}",
        f"- Priority items: {health['priority_items']}",
        "",
        "## Recommendations",
        "",
    ]
    if health["recommendations"]:
        lines.extend(f"- {item}" for item in health["recommendations"])
    else:
        lines.append("- No major scan-quality issue detected.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def build_health_outputs(run_dir: Path) -> dict:
    health = build_health(run_dir)
    json_path = run_dir / "run_health.json"
    json_path.write_text(json.dumps(health, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path = write_markdown(run_dir, health)
    return {"json": str(json_path), "markdown": str(md_path), "score": health["health_score"]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build offline run-health metrics")
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_health_outputs(args.run_dir), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
