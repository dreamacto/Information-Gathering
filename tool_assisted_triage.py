#!/usr/bin/env python3
"""Controlled wrapper for mature tool-assisted triage.

The default mode is dry-run: write the exact commands that would be executed.
Use --execute only for approved, bounded target sets. This wrapper is designed
for read-only/template triage, not brute force, uploads, shells, or data export.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

from exercise_runtime import DEFAULT_CONFIG, append_jsonl, collect_runtime_inventory, read_json


DEFAULT_EXCLUDE_TAGS = ",".join([
    "bruteforce",
    "default-login",
    "dos",
    "fuzz",
    "intrusive",
    "rce",
    "sqli",
    "upload",
    "xxe",
])


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def load_urls(run_dir: Path, source: str, limit: int) -> list[str]:
    urls: list[str] = []
    if source == "probe":
        for row in read_jsonl(run_dir / "probe_results.jsonl"):
            if row.get("ok") and row.get("url"):
                urls.append(row["url"])
    elif source == "verified":
        for row in read_jsonl(run_dir / "verified_exposures.jsonl"):
            if row.get("base_url"):
                urls.append(row["base_url"])
            elif row.get("url"):
                urls.append(row["url"])
    elif source == "impact":
        for row in read_jsonl(run_dir / "impact_candidates.jsonl"):
            if row.get("url"):
                urls.append(row["url"])
            elif row.get("base_url"):
                urls.append(row["base_url"])
    elif source == "priority":
        priority_path = run_dir / "priority_targets.json"
        try:
            parsed = json.loads(priority_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            parsed = {}
        for row in parsed.get("items", []):
            if row.get("url"):
                urls.append(row["url"])
    else:
        raise SystemExit(f"Unsupported source: {source}")
    deduped = sorted(set(urls))
    return deduped[:limit] if limit else deduped


def merge_tags(*values: str) -> str:
    tags: list[str] = []
    seen = set()
    for value in values:
        for tag in str(value or "").split(","):
            tag = tag.strip()
            if tag and tag not in seen:
                tags.append(tag)
                seen.add(tag)
    return ",".join(tags)


def suggest_nuclei_tags(run_dir: Path) -> str:
    tags = ["exposure", "misconfig", "panel", "swagger", "api", "backup", "config", "git"]
    categories = set()
    for row in read_jsonl(run_dir / "fingerprints.jsonl"):
        categories.update(row.get("categories") or [])
    kinds = set()
    for row in read_jsonl(run_dir / "candidate_exposures.jsonl"):
        if row.get("kind"):
            kinds.add(str(row["kind"]))
    if "java" in categories or any("spring" in kind for kind in kinds):
        tags.extend(["springboot", "actuator", "druid", "tomcat"])
    if "net" in categories or any("dotnet" in kind for kind in kinds):
        tags.extend(["iis", "aspnet", "elmah"])
    if "php" in categories:
        tags.extend(["php", "composer", "thinkphp", "laravel"])
    if "oa" in categories:
        tags.extend(["oa", "seeyon", "weaver", "tongda"])
    if "api" in categories:
        tags.extend(["openapi", "swagger", "graphql"])
    return merge_tags(",".join(tags))


def write_command_plan(run_dir: Path, commands: list[list[str]], execute: bool) -> Path:
    plan = {
        "created_at": now_iso(),
        "execute": execute,
        "commands": commands,
        "safety": {
            "default_dry_run": True,
            "blocked": [
                "bruteforce",
                "credential spraying",
                "webshell",
                "file upload proof",
                "command execution proof",
                "internal scanning",
                "data export",
            ],
        },
    }
    path = run_dir / "tool_assisted_triage_plan.json"
    path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def nuclei_command(nuclei: str, target_file: Path, output_file: Path, args: argparse.Namespace) -> list[str]:
    cmd = [
        nuclei,
        "-l",
        str(target_file),
        "-o",
        str(output_file),
        "-jsonl",
        "-rl",
        str(args.rate_limit),
        "-c",
        str(args.concurrency),
        "-retries",
        "0",
        "-timeout",
        str(args.timeout),
        "-severity",
        args.severity,
        "-exclude-tags",
        args.exclude_tags,
    ]
    if args.tags:
        cmd.extend(["-tags", args.tags])
    return cmd


def run_command(run_dir: Path, name: str, cmd: list[str]) -> int:
    logs = run_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    out_path = logs / f"{name}.out.log"
    err_path = logs / f"{name}.err.log"
    with out_path.open("wb") as out, err_path.open("wb") as err:
        proc = subprocess.run(cmd, cwd=str(run_dir), stdout=out, stderr=err, stdin=subprocess.DEVNULL, check=False)
    append_jsonl(run_dir / "tool_assisted_triage_runs.jsonl", {
        "checked_at": now_iso(),
        "tool": name,
        "returncode": proc.returncode,
        "stdout": str(out_path),
        "stderr": str(err_path),
        "cmd": cmd,
    })
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Controlled mature-tool triage wrapper")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--source", choices=["probe", "verified", "impact", "priority"], default="impact")
    parser.add_argument("--tool", choices=["nuclei"], default="nuclei")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--rate-limit", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--severity", default="info,low,medium")
    parser.add_argument("--tags", default="exposure,misconfig,panel,swagger,api,backup,config,git")
    parser.add_argument("--exclude-tags", default=DEFAULT_EXCLUDE_TAGS)
    parser.add_argument("--no-auto-tags", action="store_true", help="Do not merge fingerprint-derived nuclei tags")
    parser.add_argument("--execute", action="store_true", help="Actually run the generated command")
    args = parser.parse_args()

    cfg = read_json(DEFAULT_CONFIG)
    runtime = collect_runtime_inventory(cfg)
    tool_path = (runtime.get("tools", {}) or {}).get(args.tool)
    if not tool_path:
        raise SystemExit(f"{args.tool} not found. Check gov_exercise_config.json or TIANHU_BASE.")

    if not args.no_auto_tags:
        args.tags = merge_tags(args.tags, suggest_nuclei_tags(args.run_dir))

    urls = load_urls(args.run_dir, args.source, args.limit)
    if not urls:
        raise SystemExit(f"No URLs loaded from {args.source} in {args.run_dir}")

    target_file = args.run_dir / f"tool_triage_{args.source}_targets.txt"
    target_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
    output_file = args.run_dir / f"tool_triage_{args.tool}_{args.source}.jsonl"
    commands = [nuclei_command(tool_path, target_file, output_file, args)]
    plan_path = write_command_plan(args.run_dir, commands, args.execute)

    if not args.execute:
        print(json.dumps({"plan": str(plan_path), "targets": len(urls), "execute": False}, ensure_ascii=False, indent=2))
        return 0

    code = run_command(args.run_dir, args.tool, commands[0])
    print(json.dumps({
        "plan": str(plan_path),
        "targets": len(urls),
        "execute": True,
        "returncode": code,
        "output": str(output_file),
    }, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
