#!/usr/bin/env python3
"""Create a local post-run review workspace for one-click workflow outputs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


DEFAULT_RUNS_ROOT = Path(r"D:\PythonSource\PythonProjects\PythonProject4\runs")
TEXT_SUFFIXES = {".txt", ".md", ".csv", ".json", ".jsonl", ".log"}
REVIEW_FIELDS = (
    "item_id",
    "order",
    "priority",
    "category",
    "run_dir",
    "source_file",
    "item_count",
    "safe_default",
    "approval_gate",
    "recommended_action",
    "status",
    "notes",
)
FINDING_FIELDS = (
    "finding_id",
    "status",
    "run_dir",
    "source_item_id",
    "target",
    "url_or_path",
    "category",
    "title",
    "impact",
    "permission_level",
    "evidence_paths",
    "video_time",
    "cleanup",
    "retest",
    "notes",
)
TARGET_FIELDS = (
    "target_id",
    "review_order",
    "priority",
    "value_score",
    "host",
    "base_url",
    "representative_url",
    "run_dirs",
    "categories",
    "signals",
    "source_files",
    "safe_readonly_plan",
    "approval_gates",
    "rate_limit",
    "status",
    "disposition",
    "evidence_paths",
    "notes",
)

LOW_RATE_POLICY = (
    "one target at a time; concurrency=1; delay>=3s between requests to the same host; "
    "read-only GET/HEAD/schema checks only; max 10 follow-up requests per target unless the operator extends; "
    "stop on errors, latency spikes, CAPTCHA, lockout, rate-limit, or service instability"
)
GENERATED_WORKSPACE_FILES = (
    "review_plan.md",
    "target_review_queue.csv",
    "target_review_index.md",
    "review_ledger.csv",
    "findings_ledger.csv",
    "approval_gates.md",
    "run_inventory.json",
)
URL_RE = re.compile(r"https?://[^\s\"'<>，,|)\\]]+", re.I)
NOISE_HOST_RE = re.compile(
    r"(^|\.)(prototype|constructor|document|window|console|string|array|object|function|math|this|attrs|children|exports)(\.|$)",
    re.I,
)
CATEGORY_SCORES = {
    "priority_candidates": 120,
    "business_api": 85,
    "login_session": 60,
    "weak_credentials": 55,
    "product_vulnerabilities": 75,
    "sqli": 65,
    "xss": 60,
    "shiro": 70,
    "upload_file_authz": 65,
    "miniapp": 45,
    "scope": 30,
}


SOURCE_RULES: list[dict[str, Any]] = [
    {
        "category": "health",
        "order": 10,
        "priority": "P0",
        "patterns": ["run_summary.json", "run_health.json", "reports/run_health.md", "runtime_inventory.json"],
        "safe": "offline metadata review",
        "gate": "",
        "action": "Confirm run health, tool availability, failed branches, and whether empty outputs mean no candidates or tool failure.",
    },
    {
        "category": "scope",
        "order": 20,
        "priority": "P0",
        "patterns": [
            "targets.csv",
            "targets.json",
            "new_assets_pending_apply.txt",
            "subdomains_for_scope_confirmation.txt",
            "subdomains_for_next_run.txt",
            "authenticated_new_assets_pending.txt",
            "miniapp_source_new_assets_pending.txt",
            "wechat_pending_extra_assets.txt",
        ],
        "safe": "offline scope classification",
        "gate": "active testing of new assets requires scope confirmation",
        "action": "Classify each new domain, subdomain, backend, and third-party service before any follow-up request.",
    },
    {
        "category": "priority_candidates",
        "order": 30,
        "priority": "P1",
        "patterns": [
            "00_*/04_可报告候选_TOP.csv",
            "00_*/04_可报告候选_TOP.md",
            "priority_targets.json",
            "reports/priority_review.md",
            "verified_exposures.jsonl",
            "impact_candidates.jsonl",
            "candidate_exposures.jsonl",
        ],
        "safe": "manual truth check and dedupe",
        "gate": "minimal active validation requires operator approval when it changes state or touches sensitive data",
        "action": "Review highest-priority candidates, cross-check their source files, merge duplicates, and reject weak fixed-path hits.",
    },
    {
        "category": "login_session",
        "order": 40,
        "priority": "P1",
        "patterns": [
            "00_*/01_需要你登录拿Cookie.csv",
            "00_*/01_需要你登录拿Cookie.md",
            "manual_auth_queue.csv",
            "manual_auth_queue.json",
            "auth_sessions.template.json",
            "wechat_auth_domains.csv",
        ],
        "safe": "operator manual login handoff",
        "gate": "registration/login only where authorized; raw sessions stay local-only",
        "action": "Identify login targets needing operator session handoff; do not store raw cookies, tokens, or passwords in review files.",
    },
    {
        "category": "business_api",
        "order": 50,
        "priority": "P1",
        "patterns": [
            "00_*/02_业务API只读复核队列.csv",
            "00_*/02_业务API只读复核队列.md",
            "api_candidates.jsonl",
            "api_interesting.jsonl",
            "api_confirmed.jsonl",
            "authenticated_api_results.jsonl",
            "authenticated_impact_candidates.jsonl",
        ],
        "safe": "read-only API schema and behavior review",
        "gate": "write, export, delete, upload, SMS, password, approval, and bulk actions require explicit approval",
        "action": "Review API paths, parameters, roles, JSON field names, counts, and auth boundaries without retaining sensitive values.",
    },
    {
        "category": "weak_credentials",
        "order": 60,
        "priority": "P1",
        "patterns": [
            "00_*/03_弱口令人工确认队列_不自动跑.csv",
            "00_*/03_弱口令人工确认队列_不自动跑.md",
            "weak_credential_manifest.json",
            "weak_credential_attempts.jsonl",
            "weak_credential_successes.jsonl",
            "weak_credential_skips.jsonl",
        ],
        "safe": "offline queue review only",
        "gate": "weak-password attempts require explicit operator approval and lockout/CAPTCHA review",
        "action": "Confirm scope and lockout risk; keep candidates manual-only unless explicitly approved.",
    },
    {
        "category": "product_vulnerabilities",
        "order": 70,
        "priority": "P1",
        "patterns": [
            "00_*/04B_产品漏洞候选队列.csv",
            "00_*/04B_产品漏洞候选队列.md",
            "product_triage_summary.json",
            "product_triage_queue.csv",
            "product_vuln_candidate_queue.csv",
            "product_vuln_candidates.jsonl",
            "reports/product_vuln_candidate_queue.md",
        ],
        "safe": "version and exposure evidence review",
        "gate": "RCE, callback, deserialization, JNDI, exploit templates, and product exploit checks require approval",
        "action": "Use product/version/static evidence first; do not run product exploits by default.",
    },
    {
        "category": "sqli",
        "order": 80,
        "priority": "P2",
        "patterns": [
            "00_*/08_SQL注入手工确认.md",
            "sqli_high_probability.txt",
            "sqli_high_probability.jsonl",
            "sqli_candidates.jsonl",
            "sqli_500_or_error_anomalies.txt",
            "sqli_triage_manifest.json",
        ],
        "safe": "manual comparison of recorded low-impact probes",
        "gate": "SQLMap, time-based, union, stacked, dump, DB access, and writes require approval",
        "action": "Prioritize high-probability rows; treat 500/status/length-only anomalies as weak leads.",
    },
    {
        "category": "xss",
        "order": 90,
        "priority": "P2",
        "patterns": [
            "00_*/04C_XSS反射候选队列.csv",
            "00_*/04C_XSS反射候选队列.md",
            "00_*/13_XSS候选手工确认.md",
            "xss_candidates.jsonl",
            "xss_reflection_checks.jsonl",
            "xss_reflection_candidates.txt",
            "xss_manual_review.md",
        ],
        "safe": "browser-context review of inert marker reflection",
        "gate": "stored payloads, submissions, and user-affecting XSS checks require approval",
        "action": "Confirm executable context manually; reflection alone is not a finding.",
    },
    {
        "category": "shiro",
        "order": 100,
        "priority": "P2",
        "patterns": [
            "00_*/12_Shiro候选判断.md",
            "shiro_candidates.jsonl",
            "shiro_manual_queue.csv",
            "shiro_triage_results.jsonl",
            "shiro_detected.txt",
        ],
        "safe": "offline candidate review",
        "gate": "ShiroAttack2 or rememberMe exploitation requires single-target approval",
        "action": "Use Java/OA/login clues and cookie behavior; do not broad-scan Shiro.",
    },
    {
        "category": "upload_file_authz",
        "order": 110,
        "priority": "P2",
        "patterns": [
            "00_*/09_文件上传安全测试.md",
            "00_*/10_越权和接口泄露复核.md",
            "validation_results.jsonl",
            "authenticated_review_skips.jsonl",
        ],
        "safe": "offline planning and read-only checks",
        "gate": "uploads, deletes, exports, object access to third-party records, and state changes require approval",
        "action": "Identify upload/file/IDOR branches and record required test accounts, objects, and cleanup plan.",
    },
    {
        "category": "miniapp",
        "order": 120,
        "priority": "P2",
        "patterns": [
            "summary.json",
            "**/summary.json",
            "**/domains.txt",
            "**/urls.txt",
            "**/api_paths.txt",
            "wxapkg_package_parse_summary.csv",
            "wxapkg_domains_all.csv",
            "wxapkg_urls.csv",
            "wxapkg_api_paths.csv",
            "miniapp_targets_for_project.txt",
            "third_party_or_need_confirm.txt",
            "wechat_miniapp_candidates.jsonl",
            "wechat_subdomain_scan_targets.txt",
            "wechat_auth_domains.csv",
            "miniapp_source_api_candidates.jsonl",
            "burp_miniapp_api_candidates.jsonl",
        ],
        "safe": "offline static/traffic clue classification",
        "gate": "mini-program backends and third-party domains require ownership confirmation before active tests",
        "action": "Separate code noise, third-party services, platform domains, and in-scope backends; route real targets to xcx or wz.",
    },
    {
        "category": "evidence_reporting",
        "order": 130,
        "priority": "P0",
        "patterns": [
            "reports/screenshot_queue.md",
            "reports/screenshot_queue.csv",
            "reports/evidence_index.md",
            "reports/daily_report_draft.md",
            "reports/platform_submission_template.json",
            "compliance_checklist.json",
            "evidence/screenshots/README_截图说明.md",
        ],
        "safe": "redacted evidence and report assembly",
        "gate": "authenticated/sensitive screenshots require redaction; do not submit unverified candidates",
        "action": "Build final evidence index and report only from confirmed findings.",
    },
]


def now_stamp() -> str:
    return datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")


def read_text(path: Path, limit: int = 200000) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "gb18030", "cp936", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit]
    return text


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def count_items(path: Path) -> int:
    if not path.is_file() or path.stat().st_size == 0:
        return 0
    suffix = path.suffix.lower()
    try:
        if suffix == ".csv":
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                reader = csv.reader(handle)
                rows = list(reader)
            return max(0, len(rows) - 1)
        if suffix == ".jsonl":
            return sum(1 for line in read_text(path).splitlines() if line.strip())
        if suffix == ".json":
            payload = json.loads(read_text(path))
            if isinstance(payload, list):
                return len(payload)
            if isinstance(payload, dict):
                for key in (
                    "items",
                    "targets",
                    "outcomes",
                    "candidates",
                    "priority_targets",
                    "next_steps",
                    "findings",
                ):
                    value = payload.get(key)
                    if isinstance(value, list):
                        return len(value)
                for key in (
                    "finding_count",
                    "candidate_count",
                    "target_count",
                    "product_vuln_candidates",
                    "api_candidates",
                    "verified_exposures",
                    "manual_auth_queue",
                ):
                    value = payload.get(key)
                    if isinstance(value, int):
                        return value
            return 1
        return sum(1 for line in read_text(path).splitlines() if line.strip())
    except Exception:
        return 1


def stable_id(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8", errors="replace")).hexdigest()
    return digest[:16]


def find_latest_run(runs_root: Path) -> Path:
    dirs = [p for p in runs_root.iterdir() if p.is_dir()]
    non_empty = [p for p in dirs if any(child.is_file() for child in p.rglob("*"))]
    if not non_empty:
        raise FileNotFoundError(f"No non-empty run directories found under {runs_root}")
    return max(non_empty, key=lambda path: path.stat().st_mtime)


def batch_prefix(name: str) -> str | None:
    match = re.match(r"^(.+)_b\d{3}$", name)
    return match.group(1) if match else None


def resolve_runs(input_path: Path | None, runs_root: Path, include_siblings: bool) -> list[Path]:
    if input_path is None:
        selected = find_latest_run(runs_root)
    else:
        selected = input_path.resolve()
        if selected == runs_root.resolve() or selected.name.lower() in {"latest", "."}:
            selected = find_latest_run(runs_root)
        elif selected.is_dir() and selected.name.lower() == "runs":
            selected = find_latest_run(selected)
    if not selected.is_dir():
        raise FileNotFoundError(f"Run directory does not exist: {selected}")
    if include_siblings:
        prefix = batch_prefix(selected.name)
        if prefix:
            siblings = sorted(
                p for p in selected.parent.iterdir()
                if p.is_dir() and p.name.startswith(prefix + "_b")
            )
            if siblings:
                return siblings
    return [selected]


def rel_to_run(path: Path, run_dir: Path) -> str:
    try:
        return path.relative_to(run_dir).as_posix()
    except ValueError:
        return path.as_posix()


def glob_run(run_dir: Path, pattern: str) -> list[Path]:
    if "*" in pattern or "?" in pattern or "[" in pattern:
        return sorted(p for p in run_dir.glob(pattern) if p.is_file())
    candidate = run_dir / pattern
    return [candidate] if candidate.is_file() else []


def detect_manual_hub(run_dir: Path) -> Path | None:
    direct = run_dir / "00_重要_人工复核入口"
    if direct.is_dir():
        return direct
    for child in run_dir.iterdir():
        if child.is_dir() and child.name.startswith("00_") and ("复核" in child.name or "人工" in child.name):
            return child
    return None


def is_probable_host(host: str) -> bool:
    value = host.strip().strip(".").lower()
    if not value or len(value) > 253 or "." not in value:
        return False
    if any(char in value for char in "/\\:@?&=%"):
        return False
    if NOISE_HOST_RE.search(value):
        return False
    labels = value.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return False
    if not re.fullmatch(r"[a-z0-9.-]+", value):
        return False
    return True


def host_from_url(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower().strip(".")
    return host if is_probable_host(host) else ""


def first_url(value: str) -> str:
    match = URL_RE.search(value or "")
    return match.group(0).rstrip(".;，,") if match else ""


def normalize_host_from_row(row: dict[str, Any]) -> tuple[str, str, str]:
    url_keys = (
        "url",
        "base_url",
        "input_url",
        "target",
        "asset",
        "evidence_urls",
        "final_url",
        "path_or_url",
        "endpoint",
    )
    host = str(row.get("host") or row.get("domain") or row.get("asset_host") or "").strip().lower()
    if host and not is_probable_host(host):
        host = ""
    url = ""
    for key in url_keys:
        value = row.get(key)
        if value is None:
            continue
        text = str(value)
        candidate = text if text.lower().startswith(("http://", "https://")) else first_url(text)
        if candidate:
            url = candidate
            host = host or host_from_url(candidate)
            break
    if not host:
        for key in ("base_url", "url", "target", "asset"):
            value = str(row.get(key) or "").strip()
            if is_probable_host(value):
                host = value.lower().strip(".")
                break
    base_url = str(row.get("base_url") or "").strip()
    if not base_url and url and host:
        try:
            parsed = urlsplit(url)
            base_url = f"{parsed.scheme}://{host}" if parsed.scheme else ""
        except ValueError:
            base_url = ""
    if not base_url and host:
        base_url = f"https://{host}"
    return host, base_url, url


def signal_from_row(row: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "reasons",
        "reason",
        "signals",
        "finding",
        "candidate_type",
        "product",
        "category",
        "status",
        "confidence",
        "title",
        "notes",
    ):
        value = row.get(key)
        if value in (None, "", []):
            continue
        if isinstance(value, list):
            parts.extend(str(item) for item in value[:6])
        else:
            parts.append(str(value))
    return ";".join(part.strip() for part in parts if part.strip())[:600]


def numeric_score(row: dict[str, Any], category: str) -> int:
    for key in ("score", "priority_score", "source_priority_score", "rank_score"):
        value = row.get(key)
        try:
            if value not in (None, ""):
                return max(CATEGORY_SCORES.get(category, 20), int(float(value)))
        except (TypeError, ValueError):
            pass
    if str(row.get("high_probability", "")).lower() == "true":
        return max(CATEGORY_SCORES.get(category, 20), 95)
    confidence = str(row.get("confidence", "")).lower()
    if confidence == "high":
        return max(CATEGORY_SCORES.get(category, 20), 85)
    if confidence == "medium":
        return max(CATEGORY_SCORES.get(category, 20), 60)
    return CATEGORY_SCORES.get(category, 20)


def add_target(
    targets: dict[str, dict[str, Any]],
    *,
    run_dir: Path,
    source_file: str,
    category: str,
    host: str,
    base_url: str,
    representative_url: str,
    score: int,
    signal: str,
    approval_gate: str,
    create: bool = True,
) -> None:
    if not host or not is_probable_host(host):
        return
    key = host.lower()
    if not create and key not in targets:
        return
    target = targets.setdefault(
        key,
        {
            "host": key,
            "base_url": base_url or f"https://{key}",
            "representative_url": representative_url or base_url or f"https://{key}",
            "run_dirs": set(),
            "source_files": set(),
            "categories": set(),
            "signals": [],
            "approval_gates": set(),
            "category_scores": {},
            "value_score": 0,
        },
    )
    if base_url and not target["base_url"]:
        target["base_url"] = base_url
    if representative_url and (not target["representative_url"] or target["representative_url"] == target["base_url"]):
        target["representative_url"] = representative_url
    target["run_dirs"].add(str(run_dir))
    target["source_files"].add(f"{run_dir.name}/{source_file}")
    target["categories"].add(category)
    if signal and signal not in target["signals"]:
        target["signals"].append(signal)
    if approval_gate:
        target["approval_gates"].add(approval_gate)
    if create:
        scores = target["category_scores"]
        scores[category] = max(int(scores.get(category, 0)), score)
        target["value_score"] = sum(int(value) for value in scores.values())


def iter_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in read_text(path).splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def iter_csv(path: Path) -> list[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    except OSError:
        return []


def walk_json_dicts(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if isinstance(value, dict):
        result.append(value)
        for child in value.values():
            result.extend(walk_json_dicts(child))
    elif isinstance(value, list):
        for child in value:
            result.extend(walk_json_dicts(child))
    return result


def ingest_structured_targets(
    targets: dict[str, dict[str, Any]],
    run_dir: Path,
    path: Path,
    category: str,
    approval_gate: str,
    create: bool,
) -> None:
    suffix = path.suffix.lower()
    rows: list[dict[str, Any]] = []
    if suffix == ".csv":
        rows = iter_csv(path)
    elif suffix == ".jsonl":
        rows = iter_jsonl(path)
    elif suffix == ".json":
        try:
            payload = json.loads(read_text(path))
        except json.JSONDecodeError:
            payload = {}
        rows = walk_json_dicts(payload)
    for row in rows:
        host, base_url, url = normalize_host_from_row(row)
        if not host:
            continue
        add_target(
            targets,
            run_dir=run_dir,
            source_file=rel_to_run(path, run_dir),
            category=category,
            host=host,
            base_url=base_url,
            representative_url=url,
            score=numeric_score(row, category),
            signal=signal_from_row(row),
            approval_gate=approval_gate,
            create=create,
        )


def ingest_text_targets(
    targets: dict[str, dict[str, Any]],
    run_dir: Path,
    path: Path,
    category: str,
    approval_gate: str,
    create: bool,
) -> None:
    text = read_text(path)
    seen: set[str] = set()
    for url in URL_RE.findall(text):
        host = host_from_url(url)
        if host and url not in seen:
            seen.add(url)
            add_target(
                targets,
                run_dir=run_dir,
                source_file=rel_to_run(path, run_dir),
                category=category,
                host=host,
                base_url=f"{urlsplit(url).scheme}://{host}",
                representative_url=url,
                score=CATEGORY_SCORES.get(category, 20),
                signal=f"text_url:{path.name}",
                approval_gate=approval_gate,
                create=create,
            )
    if category == "miniapp":
        for raw in text.splitlines():
            value = raw.strip().split(",", 1)[0].strip()
            if is_probable_host(value):
                add_target(
                    targets,
                    run_dir=run_dir,
                    source_file=rel_to_run(path, run_dir),
                    category=category,
                    host=value.lower(),
                    base_url=f"https://{value.lower()}",
                    representative_url=f"https://{value.lower()}",
                    score=CATEGORY_SCORES.get(category, 20),
                    signal=f"miniapp_domain:{path.name}",
                    approval_gate=approval_gate,
                    create=create,
                )


def should_create_target(row: dict[str, str]) -> bool:
    category = row["category"]
    if category in {"health", "evidence_reporting"}:
        return False
    if category == "scope":
        name = Path(row["source_file"]).name.lower()
        return name not in {"targets.csv", "targets.json"}
    if category == "miniapp":
        name = Path(row["source_file"]).name.lower()
        return name in {
            "in_scope_suffix_match.txt",
            "wechat_auth_domains.csv",
            "wechat_subdomain_scan_targets.txt",
            "miniapp_source_api_candidates.jsonl",
            "burp_miniapp_api_candidates.jsonl",
            "burp_miniapp_in_scope_api_candidates.jsonl",
        }
    return True


def build_target_rows(run_dirs: list[Path], review_rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], dict[str, dict[str, Any]]]:
    targets: dict[str, dict[str, Any]] = {}
    for create_pass in (True, False):
        for row in review_rows:
            create = should_create_target(row)
            if create != create_pass:
                continue
            run_dir = Path(row["run_dir"])
            path = run_dir / row["source_file"]
            if not path.is_file():
                continue
            category = row["category"]
            approval_gate = row["approval_gate"]
            if path.suffix.lower() in {".csv", ".json", ".jsonl"}:
                ingest_structured_targets(targets, run_dir, path, category, approval_gate, create=create)
            elif path.suffix.lower() in {".txt", ".md"}:
                ingest_text_targets(targets, run_dir, path, category, approval_gate, create=create)

    rows: list[dict[str, str]] = []
    sorted_targets = sorted(
        targets.values(),
        key=lambda item: (-int(item["value_score"]), item["host"]),
    )
    for index, target in enumerate(sorted_targets, 1):
        score = min(int(target["value_score"]), 9999)
        if score >= 200:
            priority = "P0"
        elif score >= 100:
            priority = "P1"
        elif score >= 50:
            priority = "P2"
        else:
            priority = "P3"
        target_id = f"T{index:04d}_{stable_id(target['host'])}"
        target["target_id"] = target_id
        target["review_order"] = index
        target["priority"] = priority
        row = {
            "target_id": target_id,
            "review_order": str(index),
            "priority": priority,
            "value_score": str(score),
            "host": target["host"],
            "base_url": target["base_url"],
            "representative_url": target["representative_url"],
            "run_dirs": "|".join(sorted(target["run_dirs"])),
            "categories": "|".join(sorted(target["categories"])),
            "signals": " | ".join(target["signals"][:12]),
            "source_files": "|".join(sorted(target["source_files"])),
            "safe_readonly_plan": "Review offline evidence first; if live confirmation is necessary, use only the low-rate read-only policy.",
            "approval_gates": " | ".join(sorted(target["approval_gates"])),
            "rate_limit": LOW_RATE_POLICY,
            "status": "pending",
            "disposition": "",
            "evidence_paths": "",
            "notes": "",
        }
        rows.append(row)
    return rows, targets


def build_review_rows(run_dirs: list[Path]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for run_dir in run_dirs:
        for rule in SOURCE_RULES:
            for pattern in rule["patterns"]:
                for path in glob_run(run_dir, pattern):
                    count = count_items(path)
                    if count == 0 and path.suffix.lower() not in {".md", ".json"}:
                        continue
                    item_id = stable_id(str(run_dir), str(path), rule["category"])
                    rows.append(
                        {
                            "item_id": item_id,
                            "order": str(rule["order"]),
                            "priority": rule["priority"],
                            "category": rule["category"],
                            "run_dir": str(run_dir),
                            "source_file": rel_to_run(path, run_dir),
                            "item_count": str(count),
                            "safe_default": rule["safe"],
                            "approval_gate": rule["gate"],
                            "recommended_action": rule["action"],
                            "status": "pending",
                            "notes": "",
                        }
                    )
    rows.sort(key=lambda row: (int(row["order"]), row["priority"], row["run_dir"], row["source_file"]))
    return rows


def write_csv(path: Path, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def target_filename(row: dict[str, str]) -> str:
    safe_host = re.sub(r"[^a-zA-Z0-9.-]+", "_", row["host"]).strip("._") or "target"
    safe_host = safe_host[:80]
    return f"{int(row['review_order']):04d}_{safe_host}.md"


def write_target_index(output: Path, target_rows: list[dict[str, str]]) -> None:
    lines = ["# Target-by-target review index", ""]
    lines.append("Review every row in order. Do not sample, batch-confirm, or skip a target because the queue is long.")
    lines.append("")
    lines.append(f"- Target count: {len(target_rows)}")
    lines.append(f"- Rate policy for any live read-only follow-up: {LOW_RATE_POLICY}")
    lines.append("- Default action: offline evidence review first; automatic activity is read-only only.")
    lines.append("- Any write, upload, delete, export, transaction, password/account/session change, command execution, or high-risk exploit check requires explicit operator approval.")
    lines.append("")
    lines.append("| Order | Priority | Score | Host | Categories | Review file | Status |")
    lines.append("| ---: | --- | ---: | --- | --- | --- | --- |")
    for row in target_rows:
        review_file = f"target_reviews/{target_filename(row)}"
        lines.append(
            f"| {row['review_order']} | {row['priority']} | {row['value_score']} | "
            f"`{row['host']}` | `{row['categories']}` | `{review_file}` | `{row['status']}` |"
        )
    (output / "target_review_index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def category_steps(categories: set[str]) -> list[str]:
    steps = [
        "Confirm the host is in the supplied target set or explicitly in scope before any follow-up request.",
        "Read all listed source files and copy only metadata, field names, counts, hashes, or redacted snippets into evidence.",
        "Decide whether existing artifacts are enough to confirm, reject, or mark the target as needing login or approval.",
    ]
    if "priority_candidates" in categories:
        steps.append("Cross-check priority reasons against verified_exposures, impact_candidates, API queues, and screenshots; merge duplicates.")
    if "business_api" in categories:
        steps.append("Review API methods, paths, parameters, auth requirements, JSON field names, and response metadata; do not call write/export/delete endpoints.")
    if "login_session" in categories:
        steps.append("If needed, ask the operator to log in and provide a local-only session file; never persist raw cookies or tokens in review outputs.")
    if "weak_credentials" in categories:
        steps.append("Keep weak-credential work as approval-required unless the operator explicitly approves the exact target and low-volume attempt set.")
    if "product_vulnerabilities" in categories:
        steps.append("Look for product/version/static evidence first; RCE, callback, deserialization, JNDI, and exploit-template checks are approval-gated.")
    if "sqli" in categories:
        steps.append("Compare recorded baseline and probe metadata; SQLMap, time-based, union, stacked, dump, and DB-access checks are approval-gated.")
    if "xss" in categories:
        steps.append("Treat marker reflection as a candidate only; confirm browser execution context manually before reporting.")
    if "shiro" in categories:
        steps.append("Review Java/OA/login clues and rememberMe behavior; do not run broad Shiro tooling.")
    if "upload_file_authz" in categories:
        steps.append("Plan upload/file/IDOR checks with disposable objects and cleanup; actual upload/delete/export/state changes need approval.")
    if "miniapp" in categories:
        steps.append("Separate real mini-program backend hosts from code noise and third parties; route in-scope web/API hosts to $wz and mini-program context to $xcx.")
    steps.append("If live read-only confirmation is still necessary, apply the rate policy exactly and stop on any service-health concern.")
    steps.append("Set final disposition in target_review_queue.csv: confirmed, rejected, duplicate, out_of_scope, needs_login, approval_required, blocked, or accepted_risk.")
    return steps


def write_target_dossiers(output: Path, target_rows: list[dict[str, str]]) -> None:
    target_dir = output / "target_reviews"
    target_dir.mkdir(parents=True, exist_ok=True)
    for row in target_rows:
        categories = {item for item in row["categories"].split("|") if item}
        lines: list[str] = []
        lines.append(f"# Target review {row['review_order']}: {row['host']}")
        lines.append("")
        lines.append("Review this target by itself before moving to the next target in `target_review_queue.csv`.")
        lines.append("")
        lines.append("## Target")
        lines.append("")
        lines.append(f"- Target ID: `{row['target_id']}`")
        lines.append(f"- Priority: `{row['priority']}`")
        lines.append(f"- Value score: `{row['value_score']}`")
        lines.append(f"- Host: `{row['host']}`")
        lines.append(f"- Base URL: `{row['base_url']}`")
        lines.append(f"- Representative URL: `{row['representative_url']}`")
        lines.append(f"- Categories: `{row['categories']}`")
        lines.append(f"- Rate policy: {row['rate_limit']}")
        lines.append("")
        lines.append("## Source Files")
        lines.append("")
        for source in row["source_files"].split("|"):
            if source:
                lines.append(f"- `{source}`")
        lines.append("")
        lines.append("## Signals")
        lines.append("")
        if row["signals"]:
            for signal in row["signals"].split(" | "):
                lines.append(f"- {signal}")
        else:
            lines.append("- No extracted signal text; inspect source files directly.")
        lines.append("")
        lines.append("## Required Review Sequence")
        lines.append("")
        for index, step in enumerate(category_steps(categories), 1):
            lines.append(f"{index}. {step}")
        lines.append("")
        lines.append("## Approval Gates")
        lines.append("")
        if row["approval_gates"]:
            for gate in row["approval_gates"].split(" | "):
                lines.append(f"- {gate}")
        else:
            lines.append("- No category-specific approval gate was extracted, but all write/state-changing or high-risk actions still require explicit approval.")
        lines.append("")
        lines.append("## Evidence Notes")
        lines.append("")
        lines.append("- Keep screenshots redacted and include current date/time where required.")
        lines.append("- Keep passwords, cookies, tokens, personal data, business values, and downloaded sensitive files out of prompts, ledgers, and reports.")
        lines.append("- Prefer status, length, hashes, field names, counts, and minimal redacted snippets.")
        lines.append("")
        lines.append("## Disposition")
        lines.append("")
        lines.append("- Status: `pending`")
        lines.append("- Evidence paths:")
        lines.append("- Cleanup:")
        lines.append("- Retest:")
        lines.append("- Notes:")
        (target_dir / target_filename(row)).write_text("\n".join(lines) + "\n", encoding="utf-8")


def summarize_run(run_dir: Path) -> dict[str, Any]:
    files = [p for p in run_dir.rglob("*") if p.is_file()]
    summary = read_json(run_dir / "run_summary.json")
    health = read_json(run_dir / "run_health.json")
    hub = detect_manual_hub(run_dir)
    return {
        "run_dir": str(run_dir),
        "file_count": len(files),
        "manual_hub": str(hub) if hub else "",
        "run_summary": {
            key: summary.get(key)
            for key in (
                "created_at",
                "target_count",
                "mode",
                "verified_exposures",
                "candidate_exposures",
                "api_candidates",
                "api_confirmed",
                "api_interesting",
                "sqli_candidates",
                "sqli_high_probability",
                "xss_candidates",
                "xss_reflected_markers",
                "shiro_candidates",
                "product_fingerprints",
                "product_vuln_candidates",
                "manual_auth_queue",
                "weak_credential_review",
                "weak_credential_attempts",
                "weak_credential_successes",
            )
            if key in summary
        },
        "run_health": {
            key: health.get(key)
            for key in ("score", "target_count", "probe_coverage", "probe_ok_ratio", "recommendations")
            if key in health
        },
    }


def write_review_plan(
    output: Path,
    run_dirs: list[Path],
    rows: list[dict[str, str]],
    target_rows: list[dict[str, str]],
) -> None:
    by_category: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_category.setdefault(row["category"], []).append(row)
    lines: list[str] = []
    lines.append("# Post-run review plan")
    lines.append("")
    lines.append(f"- Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}")
    lines.append(f"- Run directories: {len(run_dirs)}")
    for run_dir in run_dirs:
        lines.append(f"  - `{run_dir}`")
    lines.append("")
    lines.append("## Mandatory Target-By-Target Review")
    lines.append("")
    lines.append("Use `target_review_queue.csv` and `target_review_index.md` as the primary workflow.")
    lines.append("Review every valuable target in order. Do not randomly sample targets and do not batch-confirm a whole category.")
    lines.append("")
    lines.append(f"- Valuable target count: {len(target_rows)}")
    lines.append(f"- Rate policy for optional live read-only follow-up: {LOW_RATE_POLICY}")
    lines.append("- Default automation: offline review and read-only validation planning only.")
    lines.append("- Any write, upload, delete, export, transaction, password/account/session change, command execution, exploit callback, or high-risk validation must be explained to the operator and explicitly approved before execution.")
    lines.append("")
    if target_rows:
        lines.append("| Order | Priority | Score | Host | Categories | Review File |")
        lines.append("| ---: | --- | ---: | --- | --- | --- |")
        for row in target_rows[:50]:
            lines.append(
                f"| {row['review_order']} | {row['priority']} | {row['value_score']} | "
                f"`{row['host']}` | `{row['categories']}` | `target_reviews/{target_filename(row)}` |"
            )
        if len(target_rows) > 50:
            lines.append(f"| ... | ... | ... | ... | ... | See all {len(target_rows)} rows in `target_review_queue.csv` |")
    else:
        lines.append("No valuable targets were extracted. Inspect `review_ledger.csv` and run health to decide whether the run failed or truly produced no candidates.")
    lines.append("")
    lines.append("## Health Summary")
    lines.append("")
    for run_dir in run_dirs:
        data = summarize_run(run_dir)
        lines.append(f"### {run_dir.name}")
        lines.append("")
        lines.append(f"- Files: {data['file_count']}")
        if data.get("manual_hub"):
            lines.append(f"- Manual hub: `{data['manual_hub']}`")
        if data["run_summary"]:
            lines.append(f"- Summary: `{json.dumps(data['run_summary'], ensure_ascii=False)}`")
        if data["run_health"]:
            lines.append(f"- Health: `{json.dumps(data['run_health'], ensure_ascii=False)}`")
        lines.append("")
    lines.append("## Ordered Review")
    lines.append("")
    for category in sorted(by_category, key=lambda cat: min(int(row["order"]) for row in by_category[cat])):
        items = by_category[category]
        total = sum(int(row["item_count"] or 0) for row in items)
        lines.append(f"### {category}")
        lines.append("")
        lines.append(f"- Source files: {len(items)}")
        lines.append(f"- Approx item count: {total}")
        lines.append(f"- Safe default: {items[0]['safe_default']}")
        if items[0]["approval_gate"]:
            lines.append(f"- Approval gate: {items[0]['approval_gate']}")
        lines.append(f"- Action: {items[0]['recommended_action']}")
        lines.append("")
        for row in items[:20]:
            lines.append(f"- `{Path(row['run_dir']).name}/{row['source_file']}` count={row['item_count']} status=`pending`")
        if len(items) > 20:
            lines.append(f"- ... {len(items) - 20} more source files in `review_ledger.csv`")
        lines.append("")
    lines.append("## Closeout")
    lines.append("")
    lines.append("- Update `target_review_queue.csv` target by target. Preserve the order unless the operator explicitly reprioritizes.")
    lines.append("- Update `review_ledger.csv` as each source file is reviewed.")
    lines.append("- Move only manually validated findings into `findings_ledger.csv`.")
    lines.append("- Keep approval-required branches in `approval_gates.md` until the operator approves exact actions.")
    lines.append("- Use redacted screenshots and evidence hashes; do not store secrets or sensitive response values.")
    (output / "review_plan.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_approval_gates(output: Path, rows: list[dict[str, str]]) -> None:
    lines = ["# Approval gates", ""]
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        if row["approval_gate"]:
            grouped.setdefault(row["category"], []).append(row)
    for category in sorted(grouped):
        lines.append(f"## {category}")
        lines.append("")
        lines.append(f"- Gate: {grouped[category][0]['approval_gate']}")
        lines.append("- Before approval, record target, action, expected evidence, risk, cleanup plan, and stop condition.")
        for row in grouped[category][:20]:
            lines.append(f"- `{Path(row['run_dir']).name}/{row['source_file']}` count={row['item_count']}")
        if len(grouped[category]) > 20:
            lines.append(f"- ... {len(grouped[category]) - 20} more in `review_ledger.csv`")
        lines.append("")
    (output / "approval_gates.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def choose_default_output(run_dirs: list[Path]) -> Path:
    if len(run_dirs) == 1:
        return run_dirs[0] / "postrun_review"
    prefix = batch_prefix(run_dirs[0].name) or "multi_run"
    return run_dirs[0].parent / f"postrun_review_{now_stamp()}_{prefix}"


def refresh_generated_output(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    output_resolved = output.resolve()
    target_dir = output / "target_reviews"
    if target_dir.exists():
        if target_dir.is_symlink():
            raise RuntimeError(f"Refusing to refresh symlinked target review directory: {target_dir}")
        target_resolved = target_dir.resolve()
        if output_resolved not in target_resolved.parents:
            raise RuntimeError(f"Refusing to refresh directory outside output workspace: {target_dir}")
        shutil.rmtree(target_dir)
    for name in GENERATED_WORKSPACE_FILES:
        path = output / name
        if not path.exists():
            continue
        if not path.is_file():
            raise RuntimeError(f"Refusing to replace non-file generated artifact: {path}")
        path.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize a post-run review workspace.")
    parser.add_argument("run", nargs="?", help="Run directory, runs root, or omit/latest for newest non-empty run.")
    parser.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT), help="Default runs root.")
    parser.add_argument("--output", default="", help="Review workspace output directory. Defaults beside the run.")
    parser.add_argument("--single-run", action="store_true", help="Do not include sibling parallel batch directories.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runs_root = Path(args.runs_root).resolve()
    input_path = Path(args.run).resolve() if args.run else None
    try:
        run_dirs = resolve_runs(input_path, runs_root, include_siblings=not args.single_run)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    output = Path(args.output).resolve() if args.output else choose_default_output(run_dirs).resolve()
    try:
        refresh_generated_output(output)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    rows = build_review_rows(run_dirs)
    target_rows, target_details = build_target_rows(run_dirs, rows)
    write_csv(output / "target_review_queue.csv", TARGET_FIELDS, target_rows)
    write_target_index(output, target_rows)
    write_target_dossiers(output, target_rows)
    write_csv(output / "review_ledger.csv", REVIEW_FIELDS, rows)
    write_csv(output / "findings_ledger.csv", FINDING_FIELDS, [])
    write_review_plan(output, run_dirs, rows, target_rows)
    write_approval_gates(output, rows)
    inventory = {
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "run_dirs": [str(path) for path in run_dirs],
        "review_workspace": str(output),
        "source_file_count": len(rows),
        "valuable_target_count": len(target_rows),
        "runs": [summarize_run(path) for path in run_dirs],
    }
    (output / "run_inventory.json").write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"review_workspace={output}")
    print(f"run_count={len(run_dirs)}")
    print(f"source_file_count={len(rows)}")
    print(f"valuable_target_count={len(target_rows)}")
    print(f"start={output / 'review_plan.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
