#!/usr/bin/env python3
"""Controlled runner for the Guangxi government exercise scope.

Default behavior is intentionally non-invasive:
  - import and normalize the approved target list
  - create a timestamped run directory under ./runs
  - check local runtimes and tools
  - write compliance and evidence templates

Use --probe only for low-rate HTTP metadata collection against approved targets.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import http.client
import json
import random
import re
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urljoin
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from exercise_runtime import (
    DEFAULT_CONFIG,
    BASE_DIR,
    append_jsonl,
    collect_runtime_inventory,
    create_run_dir,
    load_targets,
    now_iso,
    read_json,
    write_json,
    write_targets,
)
from result_prioritizer import build_priority_outputs
from run_health import build_health_outputs
from authenticated_session_review import build_manual_auth_handoff
from product_triage import build_findings as build_product_findings
from product_triage import write_outputs as write_product_outputs
from healthcare_privacy_triage import build_triage as build_healthcare_privacy_triage
from healthcare_privacy_triage import write_outputs as write_healthcare_privacy_outputs
from operator_action_hub import build_operator_action_hub
from weak_credential_review import run_review as run_weak_credential_review


DEFAULT_WORKFLOW = BASE_DIR / "gov_exercise_workflow.json"
DEFAULT_TOOL_STRATEGY = BASE_DIR / "tool_strategy.json"
MINIAPP_BURP_DIR_NAME = "07_小程序Burp导入结果"

SAFE_HEADERS = {
    "User-Agent": "Mozilla/5.0 exercise-recon/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

HIGH_VALUE_PATHS = [
    ("/actuator", "spring_actuator", ["_links", "self", "health", "env"]),
    ("/actuator/env", "spring_actuator", ["propertySources", "activeProfiles", "spring"]),
    ("/actuator/configprops", "spring_actuator", ["contexts", "beans", "prefix"]),
    ("/actuator/beans", "spring_actuator", ["contexts", "beans"]),
    ("/actuator/mappings", "spring_actuator", ["dispatcherServlets", "handler"]),
    ("/actuator/metrics", "spring_actuator", ["names", "jvm.", "process."]),
    ("/actuator/logfile", "spring_actuator", ["ERROR", "INFO", "WARN"]),
    ("/actuator/heapdump", "spring_heapdump", ["JAVA PROFILE", "heap"]),
    ("/druid/index.html", "druid", ["Druid Stat", "Druid Monitor"]),
    ("/druid/login.html", "druid", ["Druid Stat", "Druid Monitor"]),
    ("/druid/basic.json", "druid", ["ResultCode", "Content", "Version"]),
    ("/druid/datasource.json", "druid", ["ResultCode", "Content", "Identity"]),
    ("/swagger-ui.html", "swagger", ["swagger", "Swagger UI"]),
    ("/swagger-ui/index.html", "swagger", ["swagger", "Swagger UI"]),
    ("/swagger-ui/", "swagger", ["swagger", "Swagger UI"]),
    ("/api/swagger-ui.html", "swagger", ["swagger", "Swagger UI"]),
    ("/doc.html", "swagger", ["swagger", "Knife4j", "OpenAPI"]),
    ("/api/doc.html", "swagger", ["swagger", "Knife4j", "OpenAPI"]),
    ("/v2/api-docs", "swagger_api", ["swagger", "paths"]),
    ("/v3/api-docs", "swagger_api", ["openapi", "paths"]),
    ("/v3/api-docs/swagger-config", "swagger_api", ["configUrl", "urls", "swagger"]),
    ("/swagger-resources", "swagger_api", ["swaggerVersion", "location", "name"]),
    ("/.git/HEAD", "git_exposure", ["ref:"]),
    ("/.git/config", "git_exposure", ["[core]", "[remote", "repositoryformatversion"]),
    ("/.svn/entries", "svn_exposure", ["dir", "file"]),
    ("/.env", "env_file", ["APP_", "DB_", "SECRET", "PASSWORD"]),
    ("/.env.production", "env_file", ["APP_", "DB_", "SECRET", "PASSWORD"]),
    ("/web.config", "dotnet_config", ["<configuration", "connectionStrings"]),
    ("/Web.config", "dotnet_config", ["<configuration", "connectionStrings"]),
    ("/appsettings.json", "dotnet_config", ["ConnectionStrings", "Logging", "AllowedHosts"]),
    ("/appsettings.Production.json", "dotnet_config", ["ConnectionStrings", "Logging", "AllowedHosts"]),
    ("/trace.axd", "dotnet_trace", ["Trace Information", "Application Trace"]),
    ("/elmah", "dotnet_elmah", ["Error Log", "ELMAH"]),
    ("/manager/html", "tomcat_manager", ["Tomcat", "Manager App"]),
    ("/phpinfo.php", "php_info", ["PHP Version", "phpinfo"]),
    ("/info.php", "php_info", ["PHP Version", "phpinfo"]),
    ("/composer.json", "php_config", ["require", "autoload", "name"]),
    ("/application.properties", "java_config", ["spring.", "server.", "datasource"]),
    ("/bootstrap.properties", "java_config", ["spring.", "server.", "datasource"]),
    ("/application.yml", "java_config", ["spring:", "server:", "datasource:"]),
    ("/bootstrap.yml", "java_config", ["spring:", "server:", "datasource:"]),
    ("/WEB-INF/web.xml", "java_config", ["<web-app", "servlet", "filter"]),
    ("/WEB-INF/classes/application.properties", "java_config", ["spring.", "server.", "datasource"]),
]


def load_config(path: Path) -> dict:
    cfg = read_json(path)
    cfg.setdefault("label", "gx_gov")
    cfg.setdefault("max_targets", 500)
    cfg.setdefault("default_delay_seconds", 2.0)
    cfg.setdefault("probe_timeout_seconds", 8)
    cfg.setdefault("rate_control", {
        "default_delay_seconds": 2.0,
        "jitter_ratio": 0.25,
        "per_host_min_interval_seconds": 2.0,
        "backoff_status_codes": [429, 500, 502, 503, 504],
        "backoff_seconds": 10,
        "max_concurrency_default": 1,
        "stop_on_repeated_errors_per_host": 5,
    })
    cfg.setdefault("allowed_modes", ["check", "probe"])
    cfg.setdefault("workflow", str(DEFAULT_WORKFLOW))
    cfg.setdefault("tool_strategy", str(DEFAULT_TOOL_STRATEGY))
    cfg.setdefault("blocked_actions", [
        "password_spray",
        "bruteforce",
        "webshell",
        "c2",
        "tunnel",
        "data_export",
        "destructive_write",
        "ddos",
        "social_engineering",
        "near_field",
    ])
    return cfg


class RateController:
    def __init__(self, cfg: dict, delay_override: float | None = None) -> None:
        rate = cfg.get("rate_control", {})
        self.delay = float(delay_override if delay_override is not None else rate.get("default_delay_seconds", cfg.get("default_delay_seconds", 2.0)))
        self.jitter_ratio = float(rate.get("jitter_ratio", 0.25))
        self.per_host_min_interval = float(rate.get("per_host_min_interval_seconds", self.delay))
        self.backoff_status_codes = {int(x) for x in rate.get("backoff_status_codes", [429, 500, 502, 503, 504])}
        self.backoff_seconds = float(rate.get("backoff_seconds", 10))
        self.stop_on_repeated_errors = int(rate.get("stop_on_repeated_errors_per_host", 5))
        self.last_host_request: dict[str, float] = {}
        self.error_counts: dict[str, int] = {}

    def wait_before(self, host: str) -> None:
        now = time.time()
        last = self.last_host_request.get(host)
        if last is not None:
            remaining = self.per_host_min_interval - (now - last)
            if remaining > 0:
                time.sleep(remaining)
        jitter = self.delay * self.jitter_ratio
        sleep_for = self.delay + random.uniform(-jitter, jitter) if jitter else self.delay
        if sleep_for > 0:
            time.sleep(max(0.0, sleep_for))
        self.last_host_request[host] = time.time()

    def record_result(self, host: str, result: dict) -> bool:
        status = int(result.get("status") or 0)
        failed = not result.get("ok") or status in self.backoff_status_codes
        if failed:
            self.error_counts[host] = self.error_counts.get(host, 0) + 1
            if status in self.backoff_status_codes:
                time.sleep(self.backoff_seconds)
        else:
            self.error_counts[host] = 0
        return self.error_counts.get(host, 0) < self.stop_on_repeated_errors


def load_workflow(path: Path) -> dict:
    workflow = read_json(path)
    if not workflow:
        raise SystemExit(f"Workflow file is missing or empty: {path}")
    return workflow


def load_tool_strategy(path: Path) -> dict:
    strategy = read_json(path)
    if not strategy:
        raise SystemExit(f"Tool strategy file is missing or empty: {path}")
    return strategy


def resolve_relative_config_path(config_path: Path, configured: str | Path | None, default: Path) -> Path:
    path = Path(configured) if configured else default
    if not path.is_absolute():
        path = config_path.resolve().parent / path
    return path


def write_compliance_files(run_dir: Path, cfg: dict, args: argparse.Namespace) -> None:
    checklist = {
        "created_at": now_iso(),
        "operator_notes": "",
        "scope": {
            "target_file": str(args.targets),
            "target_count": None,
            "extra_targets_require_platform_application": True,
        },
        "recording": {
            "ev_screen_recording_required": True,
            "screenshots_must_show_system_datetime": True,
        },
        "safety_controls": {
            "default_mode": "check",
            "probe_requires_explicit_flag": True,
            "blocked_actions": cfg["blocked_actions"],
            "sensitive_data_policy": "Evidence only. Do not export, download, or store sensitive data.",
            "reported_attack_resources_required": True,
        },
        "high_risk_approval_required_for": [
            "exploitation beyond proof",
            "privilege changes",
            "internal network scanning",
            "webshell or backdoor tooling",
            "credential spraying",
            "database access validation",
        ],
        "workflow": cfg.get("workflow", str(DEFAULT_WORKFLOW)),
        "tool_strategy": cfg.get("tool_strategy", str(DEFAULT_TOOL_STRATEGY)),
    }
    write_json(run_dir / "compliance_checklist.json", checklist)

    notes = [
        "# Exercise Run Notes",
        "",
        f"- Created: {now_iso()}",
        f"- Target source: `{args.targets}`",
        f"- Mode: `{'probe' if args.probe else 'check'}`",
        "",
        "## Before Running",
        "",
        "- Confirm current exercise time window.",
        "- Confirm attack source IP/VPS has been reported.",
        "- Start screen recording before any live probing.",
        "- Keep screenshots with visible system date/time.",
        "- Do not export, download, or store sensitive production data.",
        "",
        "## Evidence",
        "",
        "- Put screenshots under `evidence/`.",
        "- Record video time ranges in `reports/evidence_index.md`.",
        "- Use `evidence_builder.py` to refresh report drafts.",
    ]
    (run_dir / "README.md").write_text("\n".join(notes) + "\n", encoding="utf-8")


def body_keyword_hits(text: str, keywords: list[str] | None) -> list[str]:
    if not text or not keywords:
        return []
    lower = text.lower()
    return sorted({keyword for keyword in keywords if keyword and keyword.lower() in lower})


def probe_one(url: str, timeout: int, marker_keywords: list[str] | None = None) -> dict:
    started = time.time()
    ctx = ssl._create_unverified_context()
    req = Request(url, headers=SAFE_HEADERS, method="GET")
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            sample = resp.read(8192)
            sample_text = sample.decode("utf-8", "ignore")
            return {
                "url": url,
                "ok": True,
                "status": resp.status,
                "final_url": resp.geturl(),
                "server": resp.headers.get("Server", ""),
                "content_type": resp.headers.get("Content-Type", ""),
                "content_length": resp.headers.get("Content-Length", ""),
                "body_sample_sha256": hashlib.sha256(sample).hexdigest(),
                "body_sample_length": len(sample),
                "title": extract_title(sample),
                "body_keyword_hits": body_keyword_hits(sample_text, marker_keywords),
                "elapsed_seconds": round(time.time() - started, 3),
                "checked_at": now_iso(),
            }
    except HTTPError as e:
        return {
            "url": url,
            "ok": True,
            "status": e.code,
            "final_url": e.url,
            "server": e.headers.get("Server", "") if e.headers else "",
            "content_type": e.headers.get("Content-Type", "") if e.headers else "",
            "content_length": e.headers.get("Content-Length", "") if e.headers else "",
            "title": "",
            "body_sample_sha256": "",
            "body_sample_length": 0,
            "elapsed_seconds": round(time.time() - started, 3),
            "checked_at": now_iso(),
        }
    except (URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError, http.client.HTTPException) as e:
        return {
            "url": url,
            "ok": False,
            "error": type(e).__name__,
            "message": str(e)[:300],
            "elapsed_seconds": round(time.time() - started, 3),
            "checked_at": now_iso(),
        }


def extract_title(sample: bytes) -> str:
    text = sample.decode("utf-8", "ignore")
    lower = text.lower()
    start = lower.find("<title")
    if start < 0:
        return ""
    start = lower.find(">", start)
    end = lower.find("</title>", start)
    if start < 0 or end < 0:
        return ""
    title = text[start + 1:end]
    return " ".join(title.split())[:160]


def run_probe(run_dir: Path, targets: list, cfg: dict, limit: int | None, delay: float, force: bool = False) -> None:
    timeout = int(cfg.get("probe_timeout_seconds", 8))
    selected = targets[:limit] if limit else targets
    output = run_dir / "probe_results.jsonl"
    completed_urls = set()
    if not force:
        completed_urls = {row.get("url") for row in read_jsonl(output) if row.get("url")}
    rate = RateController(cfg, delay_override=delay)
    for index, target in enumerate(selected, 1):
        if target.url in completed_urls:
            append_jsonl(run_dir / "stage_skips.jsonl", {
                "checked_at": now_iso(),
                "stage": "probe",
                "url": target.url,
                "reason": "already_completed",
            })
            continue
        rate.wait_before(target.host)
        result = probe_one(target.url, timeout)
        result["index"] = index
        result["name"] = target.name
        result["host"] = target.host
        append_jsonl(output, result)
        if not rate.record_result(target.host, result):
            append_jsonl(run_dir / "rate_limit_skips.jsonl", {
                "checked_at": now_iso(),
                "host": target.host,
                "reason": "repeated_errors",
                "stage": "probe",
            })


def detect_categories(row: dict) -> list[str]:
    text = " ".join(str(row.get(k, "")) for k in ("url", "final_url", "server", "content_type", "title")).lower()
    cats: set[str] = set()
    if any(k in text for k in ("jsessionid", "tomcat", "spring", "java", "weblogic", "jboss")):
        cats.add("java")
    if any(k in text for k in ("asp.net", "aspx", "iis", "microsoft-iis")):
        cats.add("net")
    if any(k in text for k in ("php", "thinkphp", "laravel")):
        cats.add("php")
    if any(k in text for k in (
        "oa", "seeyon", "tongda", "weaver", "fanwei", "ecology", "e-office",
        "landray", "wanhu", "yonyou", "kingdee", "致远", "泛微", "通达", "蓝凌",
        "万户", "用友", "金蝶",
    )):
        cats.add("oa")
    if any(k in text for k in ("ai", "chat", "llm", "assistant", "问答", "智能")):
        cats.add("ai")
    if any(k in text for k in ("screen", "大屏", "可视化", "display")):
        cats.add("bigscreen")
    if any(k in text for k in ("login", "signin", "sso", "cas", "统一认证", "登录")):
        cats.add("login")
    if any(k in text for k in ("swagger", "openapi", "api-docs", "json")):
        cats.add("api")
    if not cats:
        cats.add("other")
    return sorted(cats)


def run_fingerprint(run_dir: Path) -> None:
    probes = read_jsonl(run_dir / "probe_results.jsonl")
    latest_by_url = {}
    for row in probes:
        if row.get("url"):
            latest_by_url[row["url"]] = row
    probes = list(latest_by_url.values())
    by_cat = {
        "java": [],
        "net": [],
        "php": [],
        "oa": [],
        "ai": [],
        "bigscreen": [],
        "login": [],
        "api": [],
        "other": [],
    }
    out = run_dir / "fingerprints.jsonl"
    out.write_text("", encoding="utf-8")
    for row in probes:
        cats = detect_categories(row)
        enriched = dict(row)
        enriched["categories"] = cats
        append_jsonl(out, enriched)
        for cat in cats:
            by_cat.setdefault(cat, []).append(row.get("url", ""))
    for cat, urls in by_cat.items():
        (run_dir / f"cat_{cat}.txt").write_text("\n".join(sorted(set(filter(None, urls)))) + ("\n" if urls else ""), encoding="utf-8")


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def count_nonempty_lines(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def key_for_path(row: dict) -> tuple[str, str]:
    return ((row.get("base_url") or row.get("url") or "").rstrip("/"), row.get("path") or "")


def looks_like_spa_or_error(candidate: dict, home: dict) -> tuple[bool, str]:
    status = int(candidate.get("status") or 0)
    if status in (301, 302, 401, 403, 404):
        return True, f"status_{status}"
    if candidate.get("body_sample_sha256") and candidate.get("body_sample_sha256") == home.get("body_sample_sha256"):
        return True, "same_as_home_hash"
    title = str(candidate.get("title", "")).lower()
    if any(k in title for k in ("404", "not found", "error", "login")):
        return True, f"title_{title[:40]}"
    return False, ""


def candidate_score(candidate: dict, home: dict, keywords: list[str]) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    content_type = str(candidate.get("content_type", "")).lower()
    home_type = str(home.get("content_type", "")).lower()
    length = int(candidate.get("body_sample_length") or 0)
    home_length = int(home.get("body_sample_length") or 0)
    if candidate.get("ok") and int(candidate.get("status") or 0) == 200:
        score += 2
        reasons.append("http_200")
    if content_type and content_type != home_type:
        score += 1
        reasons.append("content_type_differs_from_home")
    if abs(length - home_length) > 200:
        score += 1
        reasons.append("length_differs_from_home")
    haystack = " ".join(str(candidate.get(k, "")) for k in ("title", "server", "content_type", "final_url"))
    if any(k.lower() in haystack.lower() for k in keywords):
        score += 2
        reasons.append("keyword_hit")
    if candidate.get("body_keyword_hits"):
        score += 3
        reasons.append("body_keyword_hit")
    return score, reasons


def check_path(url: str, path: str, timeout: int, keywords: list[str]) -> dict:
    return probe_one(urljoin(url.rstrip("/") + "/", path.lstrip("/")), timeout, marker_keywords=keywords)


def run_high_value_paths(run_dir: Path, targets: list, cfg: dict, limit: int | None, delay: float, force: bool = False) -> None:
    timeout = int(cfg.get("probe_timeout_seconds", 8))
    selected = targets[:limit] if limit else targets
    home_by_url = {row.get("url"): row for row in read_jsonl(run_dir / "probe_results.jsonl")}
    completed_keys = set()
    if not force:
        completed_keys = {key_for_path(row) for row in read_jsonl(run_dir / "verified_exposures.jsonl")}
        completed_keys.update(key_for_path(row) for row in read_jsonl(run_dir / "false_positive_exposures.jsonl"))
    rate = RateController(cfg, delay_override=delay)
    for index, target in enumerate(selected, 1):
        if rate.error_counts.get(target.host, 0) >= rate.stop_on_repeated_errors:
            continue
        home = home_by_url.get(target.url) or probe_one(target.url, timeout)
        for path, kind, keywords in HIGH_VALUE_PATHS:
            if (target.url.rstrip("/"), path) in completed_keys:
                append_jsonl(run_dir / "stage_skips.jsonl", {
                    "checked_at": now_iso(),
                    "stage": "high_value_paths",
                    "url": target.url,
                    "path": path,
                    "reason": "already_completed",
                })
                continue
            if rate.error_counts.get(target.host, 0) >= rate.stop_on_repeated_errors:
                append_jsonl(run_dir / "rate_limit_skips.jsonl", {
                    "checked_at": now_iso(),
                    "host": target.host,
                    "reason": "repeated_errors",
                    "stage": "high_value_paths",
                })
                break
            rate.wait_before(target.host)
            candidate = check_path(target.url, path, timeout, keywords)
            candidate.update({
                "index": index,
                "base_url": target.url,
                "host": target.host,
                "name": target.name,
                "path": path,
                "kind": kind,
                "expected_keywords": keywords,
            })
            append_jsonl(run_dir / "candidate_exposures.jsonl", candidate)
            false_like, false_reason = looks_like_spa_or_error(candidate, home)
            score, reasons = candidate_score(candidate, home, keywords)
            verified = dict(candidate)
            verified["verification_score"] = score
            verified["verification_reasons"] = reasons
            verified["false_positive_reason"] = false_reason
            if not false_like and score >= 3:
                append_jsonl(run_dir / "verified_exposures.jsonl", verified)
            else:
                append_jsonl(run_dir / "false_positive_exposures.jsonl", verified)
            rate.record_result(target.host, candidate)


def write_workflow_plan(run_dir: Path, workflow: dict, args: argparse.Namespace) -> None:
    lines = [
        "# Workflow Plan",
        "",
        f"- Generated: {now_iso()}",
        f"- Workflow: `{workflow.get('name')}` v{workflow.get('version')}",
        f"- Live probe: `{args.probe}`",
        f"- Offline product-aware triage: `{args.product_triage}`",
        f"- Healthcare privacy profile: `{args.healthcare_profile}`",
        f"- High value path check: `{args.high_value_paths}`",
        f"- JS/API discovery: `{args.api_discovery}`",
        f"- API endpoint confirm: `{args.api_confirm}`",
        f"- XSS safe reflection triage: `{args.xss_triage}`",
        f"- Authenticated session review: `{args.auth_review}`",
        f"- Miniapp source offline import: `{bool(args.miniapp_source_dir)}`",
        f"- Miniapp manual search pack: `{args.miniapp_search_pack}`",
        f"- Miniapp Burp import: `{bool(args.miniapp_burp_export)}`",
        f"- WeChat mini-program discovery: `{args.wechat_miniapp}`",
        f"- WeChat live clue fetch: `{args.wechat_live}`",
        f"- Resume run dir: `{args.resume_run_dir or ''}`",
        "",
        "| Phase | Risk | Auto | Gate | Outputs |",
        "| --- | --- | --- | --- | --- |",
    ]
    for phase in workflow.get("phases", []):
        gate = "approval required" if phase.get("risk") in ("medium", "high") or phase.get("requires") else ""
        outputs = ", ".join(phase.get("outputs", []))
        lines.append(f"| {phase.get('id')} - {phase.get('title')} | {phase.get('risk')} | {phase.get('auto')} | {gate} | {outputs} |")
    (run_dir / "workflow_plan.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_json(run_dir / "workflow_snapshot.json", workflow)


def tool_available(tool_name: str, runtime: dict) -> str:
    tools = runtime.get("tools", {})
    normalized = tool_name.lower()
    aliases = {
        "runner_allowlist": "built-in",
        "runner_http_probe": "built-in",
        "runner_rules": "built-in",
        "runner_high_value_path_set": "built-in",
        "runner_truth_verification": "built-in",
        "wechat_miniapp_discovery.py": "built-in",
        "miniapp_endpoint_offline.py": "built-in_offline",
        "miniapp_manual_search_helper.py": "built-in_offline",
        "evidence_builder": "built-in",
        "api_endpoint_confirm.py": "built-in",
        "xss_candidate_triage.py": "built-in_safe_get_reflection",
        "authenticated_session_review.py": "built-in",
        "product_triage.py": "built-in_offline",
        "healthcare_privacy_triage.py": "built-in_offline_schema_only",
        "result_prioritizer_and_evidence_builder": "built-in",
        "manual_review": "manual",
        "manual_wechat_or_search_review": "manual",
        "manual_browser_or_proxy": "manual",
        "manual_minimal_check": "manual",
        "manual_minimal_validation": "manual",
        "nuclei_or_dalfox_or_xsstrike": tools.get("nuclei") or "optional_manual_tool",
        "none_by_default": "disabled",
        "subfinder_or_certificate_transparency": "external_or_manual",
        "katana_or_packerfuzzer": "external_or_tianhu",
        "vuescan_or_js_analyzer": "external_or_tianhu",
        "dirsearch_or_ffuf": "external_or_tianhu",
        "ehole_or_tidefinger_or_p1finger": "tianhu",
        "oa-exptool": str(BASE_DIR / "tools" / "OA-EXPTOOL") if (BASE_DIR / "tools" / "OA-EXPTOOL").exists() else "not_installed",
        "dddd/nuclei": str(BASE_DIR / "tools" / "dddd") if (BASE_DIR / "tools" / "dddd").exists() else "not_installed",
        "oa-exptool_or_dddd/nuclei_template_inventory": "local_template_inventories" if (
            (BASE_DIR / "tools" / "OA-EXPTOOL").exists() and (BASE_DIR / "tools" / "dddd").exists()
        ) else "partial_or_not_installed",
        "afrog": tools.get("afrog"),
        "nuclei": tools.get("nuclei"),
        "httpx": tools.get("httpx"),
        "oneforall": tools.get("oneforall"),
        "dirsearch": tools.get("dirsearch"),
        "packerfuzzer": tools.get("packerfuzzer"),
        "api_tool": tools.get("api_tool"),
        "api_explorer": tools.get("api_explorer"),
    }
    value = aliases.get(normalized)
    if value:
        return value if isinstance(value, str) else str(value)
    if normalized in tools and tools[normalized]:
        return str(tools[normalized])
    return "not_configured"


def write_tool_strategy_plan(run_dir: Path, strategy: dict, runtime: dict) -> None:
    lines = [
        "# Tool Strategy Plan",
        "",
        f"- Generated: {now_iso()}",
        f"- Strategy: `{strategy.get('name')}` v{strategy.get('version')}",
        f"- Principle: {strategy.get('principle')}",
        "",
        "## Active Workflow Phases",
        "",
        "| Phase | Primary | Primary availability | Backup | Backup mode | Backup availability |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for phase, spec in strategy.get("phases", {}).items():
        primary = spec.get("primary", "")
        backup = spec.get("backup", "")
        lines.append(
            f"| {phase} | `{primary}` | {tool_available(primary, runtime)} | "
            f"`{backup}` | {spec.get('backup_mode', '')} | {tool_available(backup, runtime)} |"
        )
    gated = strategy.get("approval_gated_phases", {})
    if gated:
        lines.extend([
            "",
            "## Approval-Gated Phases",
            "",
            "| Phase | Primary | Backup | Mode | Notes |",
            "| --- | --- | --- | --- | --- |",
        ])
        for phase, spec in gated.items():
            lines.append(
                f"| {phase} | `{spec.get('primary', '')}` | `{spec.get('backup', '')}` | "
                f"{spec.get('backup_mode', '')} | {spec.get('notes', '')} |"
            )
    (run_dir / "tool_strategy_plan.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_json(run_dir / "tool_strategy_snapshot.json", strategy)


def write_approval_required(run_dir: Path, workflow: dict) -> None:
    rows = []
    for phase in workflow.get("phases", []):
        if phase.get("risk") in ("medium", "high") or phase.get("requires"):
            rows.append(phase)
    lines = [
        "# Approval Required",
        "",
        "Do not run these stages until the platform approval/resource reporting requirements are satisfied.",
        "",
        "| Phase | Risk | Required Conditions | Rules |",
        "| --- | --- | --- | --- |",
    ]
    for phase in rows:
        requires = ", ".join(phase.get("requires", [])) or "operator review"
        rules = "; ".join(phase.get("rules", []))
        lines.append(f"| {phase.get('id')} - {phase.get('title')} | {phase.get('risk')} | {requires} | {rules} |")
    (run_dir / "approval_required.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_empty_workflow_outputs(run_dir: Path) -> None:
    placeholders = {
        "new_assets_pending_apply.txt": "# New assets that require platform target application before testing.\n",
        "subdomains_raw.txt": "",
        "subdomains_dedup.txt": "",
        "candidate_exposures.jsonl": "",
        "verified_exposures.jsonl": "",
        "false_positive_exposures.jsonl": "",
        "api_discovery.jsonl": "",
        "api_candidates.jsonl": "",
        "impact_candidates.jsonl": "",
        "api_confirmed.jsonl": "",
        "api_interesting.jsonl": "",
        "sqli_triage_results.jsonl": "",
        "sqli_candidates.jsonl": "",
        "sqli_high_probability.jsonl": "",
        "sqli_high_probability.txt": "",
        "sqli_500_or_error_anomalies.txt": "",
        "second_pass_results.jsonl": "",
        "second_pass_confirmed.jsonl": "",
        "second_pass_manifest.json": "",
        "xss_triage_manifest.json": "",
        "xss_candidates.jsonl": "",
        "xss_reflection_checks.jsonl": "",
        "xss_reflection_candidates.txt": "",
        "xss_manual_review.md": "# XSS 候选与安全反射检查\n\nRun with `--xss-triage` to populate this file.\n",
        "xss_triage_errors.jsonl": "",
        "shiro_triage_results.jsonl": "",
        "shiro_candidates.jsonl": "",
        "shiro_detected.txt": "",
        "shiro_manual_queue.csv": "",
        "product_fingerprints.jsonl": "",
        "product_triage_queue.csv": "",
        "product_vuln_candidates.jsonl": "",
        "product_vuln_candidate_queue.csv": "",
        "fingerprint_deepening_plan.jsonl": "",
        "fingerprint_deepening_safe_queue.csv": "",
        "fingerprint_deepening_approval_queue.csv": "",
        "fingerprint_tool_command_queue.csv": "",
        "fingerprint_tool_matrix.json": "",
        "fingerprint_deepening_manifest.json": "",
        "authenticated_api_results.jsonl": "",
        "authenticated_impact_candidates.jsonl": "",
        "authenticated_review_skips.jsonl": "",
        "authenticated_new_assets_pending.txt": "",
        "weak_credential_attempts.jsonl": "",
        "weak_credential_successes.jsonl": "",
        "weak_credential_skips.jsonl": "",
        "weak_auto_auth_errors.jsonl": "",
        "candidate_confidence.jsonl": "",
        "candidate_confidence.csv": "",
        "review_intelligence_manifest.json": "",
        "target_dossier_manifest.json": "",
        "subdomains_raw.txt": "",
        "subdomains_dedup.txt": "",
        "subdomains_for_scope_confirmation.txt": "",
        "subdomains_for_next_run.txt": "",
        "targets_with_auto_subdomains.txt": "",
        "subdomains_resolved.jsonl": "",
        "tool_fingerprints.jsonl": "",
        "tool_fingerprint_errors.jsonl": "",
        "miniapp_source_api_candidates.jsonl": "",
        "miniapp_source_new_assets_pending.txt": "",
        "wechat_miniapp_candidates.jsonl": "",
        "wechat_home_checks.jsonl": "",
        "wechat_js_checks.jsonl": "",
        "wechat_subdomain_scan_targets.txt": "",
        "wechat_pending_extra_assets.txt": "",
        "wechat_auth_domains.json": "",
        "wechat_auth_domains.csv": "",
        "wechat_auth_domains.txt": "",
        "wechat_auth_sessions.template.json": "",
        "validation_results.jsonl": "",
        "manual_exploitability_notes.md": "# Manual Exploitability Notes\n\nDo not use until approval requirements are satisfied.\n",
    }
    for rel, content in placeholders.items():
        path = run_dir / rel
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    score_mapping = run_dir / "score_mapping.json"
    if not score_mapping.exists():
        write_json(score_mapping, {
            "generated_at": now_iso(),
            "items": [],
            "note": "Populate only after manual verification and evidence review.",
        })


def count_named_jsonl(root: Path, filename: str) -> int:
    total = len(read_jsonl(root / filename))
    if root.exists():
        for path in root.glob(f"*/{filename}"):
            total += len(read_jsonl(path))
    return total


def write_summary(run_dir: Path, targets: list, runtime: dict, cfg: dict, args: argparse.Namespace) -> None:
    missing_tools = sorted(name for name, path in runtime.get("tools", {}).items() if not path)
    verified_count = len(read_jsonl(run_dir / "verified_exposures.jsonl"))
    candidate_count = len(read_jsonl(run_dir / "candidate_exposures.jsonl"))
    api_candidate_count = len(read_jsonl(run_dir / "api_candidates.jsonl"))
    impact_candidate_count = len(read_jsonl(run_dir / "impact_candidates.jsonl"))
    api_confirmed_count = len(read_jsonl(run_dir / "api_confirmed.jsonl"))
    api_interesting_count = len(read_jsonl(run_dir / "api_interesting.jsonl"))
    sqli_candidate_count = len(read_jsonl(run_dir / "sqli_candidates.jsonl"))
    sqli_high_probability_count = len(read_jsonl(run_dir / "sqli_high_probability.jsonl"))
    second_pass_results = read_jsonl(run_dir / "second_pass_results.jsonl")
    second_pass_confirmed_count = len(read_jsonl(run_dir / "second_pass_confirmed.jsonl"))
    xss_candidate_count = len(read_jsonl(run_dir / "xss_candidates.jsonl"))
    xss_reflection_checks = read_jsonl(run_dir / "xss_reflection_checks.jsonl")
    xss_reflection_count = sum(1 for row in xss_reflection_checks if row.get("marker_reflected"))
    shiro_candidate_count = len(read_jsonl(run_dir / "shiro_candidates.jsonl"))
    subdomain_resolved_count = len(read_jsonl(run_dir / "subdomains_resolved.jsonl"))
    auto_merged_target_count = 0
    auto_merged_path = run_dir / "targets_with_auto_subdomains.txt"
    if auto_merged_path.exists():
        auto_merged_target_count = len([line for line in auto_merged_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.lstrip().startswith("#")])
    tool_fingerprint_count = len(read_jsonl(run_dir / "tool_fingerprints.jsonl"))
    product_fingerprint_count = len(read_jsonl(run_dir / "product_fingerprints.jsonl"))
    product_vuln_candidate_count = len(read_jsonl(run_dir / "product_vuln_candidates.jsonl"))
    fingerprint_deepening_count = len(read_jsonl(run_dir / "fingerprint_deepening_plan.jsonl"))
    fingerprint_deepening_approval_count = 0
    approval_queue_path = run_dir / "fingerprint_deepening_approval_queue.csv"
    if approval_queue_path.exists():
        with approval_queue_path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
            fingerprint_deepening_approval_count = max(0, sum(1 for _ in csv.DictReader(handle)))
    healthcare_privacy_summary = {}
    healthcare_summary_path = run_dir / "healthcare_privacy" / "healthcare_privacy_summary.json"
    if healthcare_summary_path.exists():
        try:
            healthcare_privacy_summary = read_json(healthcare_summary_path)
        except (OSError, json.JSONDecodeError):
            healthcare_privacy_summary = {"error": "summary_unreadable"}
    auth_queue_count = 0
    auth_queue_path = run_dir / "manual_auth_queue.json"
    if auth_queue_path.exists():
        try:
            auth_queue_count = int(read_json(auth_queue_path).get("count") or 0)
        except (AttributeError, ValueError):
            auth_queue_count = 0
    authenticated_result_count = len(read_jsonl(run_dir / "authenticated_api_results.jsonl"))
    authenticated_impact_count = len(read_jsonl(run_dir / "authenticated_impact_candidates.jsonl"))
    weak_credential_attempt_count = len(read_jsonl(run_dir / "weak_credential_attempts.jsonl"))
    weak_credential_success_count = len(read_jsonl(run_dir / "weak_credential_successes.jsonl"))
    weak_auto_auth_summary = {}
    weak_auto_auth_path = run_dir / "weak_auto_authenticated_review_manifest.json"
    if weak_auto_auth_path.exists():
        try:
            weak_auto_auth_summary = read_json(weak_auto_auth_path)
        except (OSError, json.JSONDecodeError):
            weak_auto_auth_summary = {"error": "manifest_unreadable"}
    confidence_rows = read_jsonl(run_dir / "candidate_confidence.jsonl")
    confidence_counts = {
        "P0": sum(1 for row in confidence_rows if row.get("priority") == "P0"),
        "P1": sum(1 for row in confidence_rows if row.get("priority") == "P1"),
        "P2": sum(1 for row in confidence_rows if row.get("priority") == "P2"),
        "P3": sum(1 for row in confidence_rows if row.get("priority") == "P3"),
    }
    dossier_manifest = {}
    dossier_manifest_path = run_dir / "target_dossier_manifest.json"
    if dossier_manifest_path.exists():
        try:
            dossier_manifest = read_json(dossier_manifest_path)
        except (OSError, json.JSONDecodeError):
            dossier_manifest = {"error": "manifest_unreadable"}
    miniapp_source_candidate_count = len(read_jsonl(run_dir / "miniapp_source_api_candidates.jsonl"))
    miniapp_burp_dir = run_dir / MINIAPP_BURP_DIR_NAME
    burp_miniapp_candidate_count = count_named_jsonl(miniapp_burp_dir, "burp_miniapp_api_candidates.jsonl")
    burp_miniapp_in_scope_count = count_named_jsonl(miniapp_burp_dir, "burp_miniapp_in_scope_api_candidates.jsonl")
    if not burp_miniapp_candidate_count:
        burp_miniapp_candidate_count = len(read_jsonl(run_dir / "burp_miniapp_api_candidates.jsonl"))
    if not burp_miniapp_in_scope_count:
        burp_miniapp_in_scope_count = len(read_jsonl(run_dir / "burp_miniapp_in_scope_api_candidates.jsonl"))
    wechat_candidate_count = len(read_jsonl(run_dir / "wechat_miniapp_candidates.jsonl"))
    wechat_scan_targets = 0
    wechat_scan_targets_path = run_dir / "wechat_subdomain_scan_targets.txt"
    if wechat_scan_targets_path.exists():
        wechat_scan_targets = len([line for line in wechat_scan_targets_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()])
    wechat_auth_domain_count = 0
    wechat_auth_in_scope_count = 0
    wechat_auth_path = run_dir / "wechat_auth_domains.json"
    if wechat_auth_path.exists():
        try:
            wechat_auth_data = read_json(wechat_auth_path)
            wechat_auth_domain_count = int(wechat_auth_data.get("count") or 0)
            wechat_auth_in_scope_count = sum(
                item.get("scope_state") == "in_current_scope"
                for item in wechat_auth_data.get("items", [])
                if isinstance(item, dict)
            )
        except (AttributeError, ValueError, json.JSONDecodeError):
            pass
    priority_outputs = {}
    try:
        priority_outputs = build_priority_outputs(run_dir)
    except Exception as exc:  # noqa: BLE001
        append_jsonl(run_dir / "priority_errors.jsonl", {
            "checked_at": now_iso(),
            "error": str(exc)[:300],
        })
    health_outputs = {}
    try:
        health_outputs = build_health_outputs(run_dir)
    except Exception as exc:  # noqa: BLE001
        append_jsonl(run_dir / "health_errors.jsonl", {
            "checked_at": now_iso(),
            "error": str(exc)[:300],
        })
    operator_action_hub = {}
    try:
        operator_action_hub = build_operator_action_hub(run_dir)
    except Exception as exc:  # noqa: BLE001
        append_jsonl(run_dir / "operator_action_hub_errors.jsonl", {
            "checked_at": now_iso(),
            "error": str(exc)[:300],
        })
    summary = {
        "created_at": now_iso(),
        "run_dir": str(run_dir),
        "target_count": len(targets),
        "mode": "probe" if args.probe else "check",
        "subdomain_bruteforce": bool(args.subdomain_bruteforce),
        "subdomains_resolved": subdomain_resolved_count,
        "targets_with_auto_subdomains": auto_merged_target_count,
        "tool_fingerprint": bool(args.tool_fingerprint),
        "tool_fingerprints": tool_fingerprint_count,
        "high_value_paths": bool(args.high_value_paths),
        "api_discovery": bool(args.api_discovery),
        "candidate_exposures": candidate_count,
        "verified_exposures": verified_count,
        "api_candidates": api_candidate_count,
        "impact_candidates": impact_candidate_count,
        "api_confirmed": api_confirmed_count,
        "api_interesting": api_interesting_count,
        "sqli_triage": bool(args.sqli_triage),
        "sqli_candidates": sqli_candidate_count,
        "sqli_high_probability": sqli_high_probability_count,
        "second_pass_triage": bool(args.second_pass_triage),
        "second_pass_results": len(second_pass_results),
        "second_pass_stable_candidates": second_pass_confirmed_count,
        "xss_triage": bool(args.xss_triage),
        "xss_reflect_check": bool(args.xss_reflect_check),
        "xss_candidates": xss_candidate_count,
        "xss_reflected_markers": xss_reflection_count,
        "shiro_triage": bool(args.shiro_triage),
        "shiro_candidates": shiro_candidate_count,
        "product_triage": bool(args.product_triage),
        "product_fingerprints": product_fingerprint_count,
        "product_vuln_candidates": product_vuln_candidate_count,
        "fingerprint_deepening": bool(args.fingerprint_deepening),
        "fingerprint_deepening_branches": fingerprint_deepening_count,
        "fingerprint_deepening_approval_queue": fingerprint_deepening_approval_count,
        "healthcare_profile": bool(args.healthcare_profile),
        "healthcare_privacy": healthcare_privacy_summary,
        "manual_auth_queue": auth_queue_count,
        "authenticated_review": bool(args.auth_review),
        "authenticated_api_results": authenticated_result_count,
        "authenticated_impact_candidates": authenticated_impact_count,
        "weak_credential_review": bool(args.weak_credential_review),
        "weak_credential_auto_auth_review": bool(args.weak_credential_auto_auth_review),
        "weak_credential_attempts": weak_credential_attempt_count,
        "weak_credential_successes": weak_credential_success_count,
        "weak_auto_authenticated_review": weak_auto_auth_summary,
        "review_intelligence": bool(args.review_intelligence),
        "candidate_confidence": len(confidence_rows),
        "candidate_confidence_counts": confidence_counts,
        "target_dossier_count": dossier_manifest.get("host_count", 0),
        "target_dossier_index": dossier_manifest.get("index", ""),
        "miniapp_source_import": bool(args.miniapp_source_dir),
        "miniapp_source_api_candidates": miniapp_source_candidate_count,
        "miniapp_search_pack": bool(args.miniapp_search_pack),
        "miniapp_burp_import": bool(args.miniapp_burp_export),
        "burp_miniapp_api_candidates": burp_miniapp_candidate_count,
        "burp_miniapp_in_scope_api_candidates": burp_miniapp_in_scope_count,
        "wechat_miniapp_discovery": bool(args.wechat_miniapp),
        "wechat_candidates": wechat_candidate_count,
        "wechat_subdomain_scan_targets": wechat_scan_targets,
        "wechat_auth_domains": wechat_auth_domain_count,
        "wechat_auth_domains_in_scope": wechat_auth_in_scope_count,
        "evidence_build": not bool(args.no_evidence_build),
        "priority_review": priority_outputs,
        "run_health": health_outputs,
        "operator_action_hub": operator_action_hub,
        "python": runtime.get("python"),
        "java": runtime.get("java"),
        "missing_tools": missing_tools,
        "blocked_actions": cfg["blocked_actions"],
        "next_steps": [
            "Start at 00_重要_人工复核入口/README_先看这里.md; it now links P0-P3 candidate confidence, target dossiers, login, business API, weak-credential queue, and reportable candidates.",
            "Review targets.csv and confirm scope.",
            "Use targets_with_auto_subdomains.txt for the next run when same-parent subdomain expansion is allowed.",
            "Review runtime_inventory.json and fix missing critical tools.",
            "Review impact_candidates.jsonl for JS/API-driven targets worth manual validation.",
            "Review sqli_high_probability.txt for parameterized URLs with high-probability SQL injection signals.",
            "Review reports/second_pass_review.md for candidates that stayed stable after the second lightweight check.",
            "Review candidate_confidence.csv and target_dossiers/index.md before opening raw JSONL files.",
            "Review sqli_500_or_error_anomalies.txt as weaker SQLi anomaly leads; 500 alone is not proof.",
            "Review xss_manual_review.md and xss_reflection_candidates.txt; marker reflection is a candidate, not a confirmed executable XSS proof.",
            "Review shiro_manual_queue.csv for Java/login/OA targets worth manual ShiroAttack2 single-target verification.",
            "Review product_triage_queue.csv for product-specific OA/framework/middleware branches; approval templates are never default automation.",
            "Review reports/fingerprint_deepening.md and 00_重要_人工复核入口/04D_指纹后深入分支.md for product-specific next checks.",
            "Review healthcare_privacy/healthcare_manual_review_queue.csv; it contains endpoint paths and field names only, never patient values.",
            "Review manual_auth_queue.csv; manually register/login where authorized, then provide a local auth session file.",
            "If rules allow credential checks, review 00_重要_人工复核入口/03_弱口令人工确认队列_不自动跑.md and run --weak-credential-review explicitly; add --weak-credential-auto-auth-review to use successful login cookies/tokens in memory before manual Cookie handoff.",
            "Review authenticated_impact_candidates.jsonl; it stores schema metadata only and never response values.",
            "For mini-programs, use --miniapp-search-pack to create manual search keywords, then import your Burp export with --miniapp-burp-export.",
            "If you already have unpacked mini-program source, use --miniapp-source-dir; only in-scope backend candidates are appended to api_candidates.jsonl.",
            "Review wechat_subdomain_scan_targets.txt and feed approved items back into subdomain/alive scanning.",
            "Review wechat_auth_domains.csv; log in manually only for in_current_scope domains, then copy the session into a local auth_sessions.local.json file.",
            "Review reports/screenshot_queue.md; run evidence/screenshots/截图队列_一键采集.bat for public-page screenshots, then manually add redacted authenticated/sensitive evidence.",
            "Review reports/daily_report_draft.md and reports/evidence_index.md before platform submission.",
        ],
    }
    write_json(run_dir / "run_summary.json", summary)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Guangxi government exercise controlled runner")
    parser.add_argument("--targets", type=Path, required=True, help="Approved target list, one URL per line or url|name")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="Runner config JSON")
    parser.add_argument("--workflow", type=Path, default=None, help="Workflow JSON")
    parser.add_argument("--label", default="", help="Run label suffix")
    parser.add_argument("--resume-run-dir", type=Path, default=None, help="Resume an existing run directory")
    parser.add_argument("--force", action="store_true", help="Ignore stage checkpoints and append fresh results")
    parser.add_argument("--subdomain-bruteforce", action="store_true", help="Run low-rate DNS subdomain discovery and write scope-confirmation handoff files")
    parser.add_argument("--subdomain-wordlist", type=Path, default=None, help="Optional subdomain wordlist")
    parser.add_argument("--subdomain-max-words", type=int, default=80, help="Max subdomain words per input host scope anchor")
    parser.add_argument(
        "--subdomain-max-roots",
        "--subdomain-max-scope-anchors",
        dest="subdomain_max_roots",
        type=int,
        default=20,
        help="Max exact input host anchors; input subdomains are never widened to registered parents",
    )
    parser.add_argument("--subdomain-delay", type=float, default=1.5, help="Delay between DNS lookups in subdomain discovery")
    parser.add_argument("--subdomain-qps", type=float, default=0.0, help="Global DNS lookup start rate for subdomain discovery; overrides subdomain delay when > 0")
    parser.add_argument("--subdomain-concurrency", type=int, default=1, help="Concurrent DNS workers for subdomain discovery; global qps/delay is still enforced")
    parser.add_argument("--subdomain-max-queries", type=int, default=0, help="Maximum total DNS queries for subdomain discovery")
    parser.add_argument("--probe", action="store_true", help="Run low-rate HTTP metadata probing")
    parser.add_argument("--fingerprint", action="store_true", help="Classify existing probe results")
    parser.add_argument("--tool-fingerprint", action="store_true", help="Run rate-controlled httpx technology fingerprinting")
    parser.add_argument("--tool-fingerprint-limit", type=int, default=0, help="Limit external fingerprint targets")
    parser.add_argument(
        "--product-triage",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Build an offline product/OA-specific tool queue (enabled by default; use --no-product-triage to skip)",
    )
    parser.add_argument(
        "--fingerprint-deepening",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Build offline post-fingerprint deepening queues and approval-gated tool plan (enabled by default)",
    )
    parser.add_argument(
        "--healthcare-profile",
        action="store_true",
        help="Enable healthcare-specific offline privacy triage and enforce a minimum 3-second live-request delay",
    )
    parser.add_argument("--high-value-paths", action="store_true", help="Check high-value paths and run truth verification")
    parser.add_argument("--api-discovery", action="store_true", help="Run read-only JS/API discovery and impact triage")
    parser.add_argument("--api-confirm", action="store_true", help="Confirm selected discovered GET-like API endpoints")
    parser.add_argument("--api-max-js", type=int, default=20, help="Max same-host JavaScript files to inspect per target")
    parser.add_argument("--api-confirm-max-per-target", type=int, default=8, help="Max API endpoint confirmations per target")
    parser.add_argument("--api-confirm-threshold", type=int, default=5, help="Minimum API candidate priority for confirmation")
    parser.add_argument("--api-use-katana", action="store_true", help="Use katana if installed before built-in parsing")
    parser.add_argument("--xss-triage", action="store_true", help="Build a safe XSS candidate queue from discovered parameterized URLs")
    parser.add_argument("--xss-reflect-check", action="store_true", help="Send one inert GET marker per safe XSS candidate and check reflection metadata")
    parser.add_argument("--xss-max-per-host", type=int, default=3, help="Max automatic XSS reflection probes per host")
    parser.add_argument("--xss-max-params-per-url", type=int, default=2, help="Max XSS parameters to queue per parameterized URL")
    parser.add_argument("--xss-limit", type=int, default=0, help="Limit total XSS candidate params")
    parser.add_argument("--sqli-triage", action="store_true", help="Run low-impact SQL injection triage on discovered parameterized URLs")
    parser.add_argument("--sqli-max-per-host", type=int, default=3, help="Max SQLi parameter probes per host")
    parser.add_argument("--sqli-max-params-per-url", type=int, default=2, help="Max parameters to test per parameterized URL")
    parser.add_argument("--sqli-limit", type=int, default=0, help="Limit total SQLi parameter probes")
    parser.add_argument("--second-pass-triage", action="store_true", help="Repeat a tiny bounded check for top SQLi/XSS/API candidates to reduce manual noise")
    parser.add_argument("--second-pass-sql-limit", type=int, default=10, help="Max SQLi candidates for second-pass lightweight retest")
    parser.add_argument("--second-pass-xss-limit", type=int, default=20, help="Max XSS reflected candidates for second-pass inert-marker retest")
    parser.add_argument("--second-pass-api-limit", type=int, default=20, help="Max API endpoints for second-pass metadata/schema refetch")
    parser.add_argument(
        "--review-intelligence",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Build offline P0-P3 candidate confidence and per-target dossiers (enabled by default)",
    )
    parser.add_argument("--shiro-triage", action="store_true", help="Run low-impact Apache Shiro rememberMe feature triage")
    parser.add_argument("--shiro-limit", type=int, default=0, help="Limit Shiro triage seed count")
    parser.add_argument("--shiro-include-all", action="store_true", help="Run Shiro triage on all scoped targets instead of Java/login/OA seeds")
    parser.add_argument("--auth-review", action="store_true", help="Run bounded authenticated JS/API review using an operator-provided session file")
    parser.add_argument("--auth-cookie-file", type=Path, default=None, help="Local JSON session file; cookies are never written to run outputs")
    parser.add_argument("--auth-max-js", type=int, default=20, help="Max authenticated same-host JavaScript files per session")
    parser.add_argument("--auth-max-endpoints", type=int, default=30, help="Max authenticated safe GET endpoints per session")
    parser.add_argument("--weak-credential-review", action="store_true", help="Explicitly run bounded weak-credential review; never enabled by default")
    parser.add_argument(
        "--weak-credential-auto-auth-review",
        action="store_true",
        help="After an explicit weak-credential success, use returned cookies/tokens in memory for bounded authenticated read-only review",
    )
    parser.add_argument("--weak-credential-max-targets", type=int, default=10, help="Max login surfaces for explicit weak-credential review")
    parser.add_argument("--weak-credential-max-pairs", type=int, default=5, help="Max dynamic credential pairs per target in explicit weak-credential review")
    parser.add_argument("--weak-credential-timeout", type=int, default=10, help="HTTP timeout for explicit weak-credential review")
    parser.add_argument("--miniapp-source-dir", type=Path, action="append", default=[], help="Offline unpacked mini-program source directory to import into this run")
    parser.add_argument("--miniapp-search-pack", action="store_true", help="Generate manual mini-program search keywords from target names/domains")
    parser.add_argument("--miniapp-burp-export", type=Path, action="append", default=[], help="Import Burp-captured mini-program URLs into the run")
    parser.add_argument("--wechat-miniapp", action="store_true", help="Generate WeChat mini-program clues and subdomain scan handoff files")
    parser.add_argument("--wechat-live", action="store_true", help="Fetch homepage and same-host JS for WeChat clues at the configured delay")
    parser.add_argument("--wechat-limit", type=int, default=0, help="Limit WeChat mini-program discovery seed count")
    parser.add_argument("--wechat-max-js", type=int, default=3, help="Max same-host JavaScript files to inspect per target for WeChat clues")
    parser.add_argument("--no-evidence-build", action="store_true", help="Skip automatic report/evidence draft generation at the end")
    parser.add_argument("--limit", type=int, default=0, help="Limit target count for this run")
    parser.add_argument("--delay", type=float, default=None, help="Seconds between live HTTP requests")
    return parser.parse_args()


def run_subdomain_bruteforce_stage(run_dir: Path, args: argparse.Namespace) -> None:
    expected_queries = 0
    estimate_ok = False
    try:
        from subdomain_bruteforce_controlled import build_queries, load_scope_anchors, load_words

        anchor_limit = args.subdomain_max_roots if args.subdomain_max_roots > 0 else None
        scope_anchors = load_scope_anchors(args.targets)[:anchor_limit]
        words = load_words(args.subdomain_wordlist, args.subdomain_max_words)
        expected_queries = len(build_queries(scope_anchors, words, args.subdomain_max_queries))
        estimate_ok = True
    except Exception as exc:  # noqa: BLE001
        append_jsonl(run_dir / "subdomain_bruteforce_errors.jsonl", {
            "checked_at": now_iso(),
            "error": f"progress_estimate_failed: {str(exc)[:200]}",
        })

    if estimate_ok and expected_queries == 0:
        append_jsonl(run_dir / "subdomain_bruteforce_errors.jsonl", {
            "checked_at": now_iso(),
            "stage": "subdomain_bruteforce",
            "reason": "no_valid_input_host_scope_anchors",
            "targets": str(args.targets),
        })
        print("[*] 子域名阶段跳过: 目标里没有有效的输入主机作用域锚点", flush=True)
        return

    cmd = [
        sys.executable,
        str(BASE_DIR / "subdomain_bruteforce_controlled.py"),
        "--targets",
        str(args.targets),
        "--out-dir",
        str(run_dir),
        "--delay",
        str(args.subdomain_delay),
        "--timeout",
        "3",
        "--max-words",
        str(args.subdomain_max_words),
        "--max-roots",
        str(args.subdomain_max_roots),
        "--qps",
        str(args.subdomain_qps),
        "--concurrency",
        str(args.subdomain_concurrency),
        "--max-queries",
        str(args.subdomain_max_queries),
    ]
    if args.subdomain_wordlist:
        cmd.extend(["--wordlist", str(args.subdomain_wordlist)])
    progress_path = run_dir / "subdomains_resolved.jsonl"
    started = time.monotonic()
    last_report = 0.0
    if expected_queries:
        print(
            f"[*] 子域名阶段启动: 按输入主机锚定作用域，预计 {expected_queries} 次 DNS 查询，"
            f"结果实时写入 {progress_path}",
            flush=True,
        )
    else:
        print(f"[*] 子域名阶段启动: 结果实时写入 {progress_path}", flush=True)
    try:
        with (run_dir / "subdomain_bruteforce.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
            run_dir / "subdomain_bruteforce.err.log"
        ).open("w", encoding="utf-8", errors="ignore") as err:
            proc = subprocess.Popen(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
            while True:
                returncode = proc.poll()
                now = time.monotonic()
                if returncode is not None or now - last_report >= 30:
                    completed = count_nonempty_lines(progress_path)
                    elapsed = int(now - started)
                    if expected_queries:
                        pct = min(100.0, completed * 100.0 / max(1, expected_queries))
                        print(f"[*] 子域名阶段进度: {completed}/{expected_queries} ({pct:.1f}%), 已耗时 {elapsed}s", flush=True)
                    else:
                        print(f"[*] 子域名阶段进度: 已写入 {completed} 条，已耗时 {elapsed}s", flush=True)
                    last_report = now
                if returncode is not None:
                    break
                time.sleep(5)
    except Exception as exc:  # noqa: BLE001
        append_jsonl(run_dir / "subdomain_bruteforce_errors.jsonl", {
            "checked_at": now_iso(),
            "stage": "subdomain_bruteforce",
            "error": type(exc).__name__,
            "message": str(exc)[:500],
            "cmd": cmd,
        })
        print(f"[!] 子域名阶段启动/监控失败，已记录并继续后续流程: {type(exc).__name__}: {str(exc)[:160]}", flush=True)
        return
    if proc.returncode != 0:
        append_jsonl(run_dir / "subdomain_bruteforce_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })
        print(f"[!] 子域名阶段异常退出，returncode={proc.returncode}，已记录并继续后续流程", flush=True)
    else:
        print("[*] 子域名阶段完成", flush=True)


def run_tool_fingerprint_stage(run_dir: Path, args: argparse.Namespace, delay: float) -> None:
    cmd = [
        sys.executable,
        str(BASE_DIR / "tool_fingerprint_httpx.py"),
        "--run-dir",
        str(run_dir),
        "--targets",
        str(args.targets),
        "--config",
        str(args.config),
        "--delay",
        str(delay),
        "--timeout",
        "10",
    ]
    if args.tool_fingerprint_limit:
        cmd.extend(["--limit", str(args.tool_fingerprint_limit)])
    with (run_dir / "tool_fingerprint.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "tool_fingerprint.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "tool_fingerprint_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def run_api_discovery_stage(run_dir: Path, args: argparse.Namespace, delay: float) -> None:
    target_lines = []
    for row in read_jsonl(run_dir / "probe_results.jsonl"):
        if row.get("ok") and row.get("url"):
            target_lines.append(row["url"])
    if not target_lines:
        with (run_dir / "targets.csv").open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            for row in csv.DictReader(handle):
                if row.get("url"):
                    target_lines.append(row["url"].strip())
    if not args.force:
        completed_bases = {row.get("base_url") for row in read_jsonl(run_dir / "api_discovery.jsonl") if row.get("base_url")}
        target_lines = [url for url in target_lines if url.rstrip("/") not in completed_bases]
    api_targets = run_dir / "api_discovery_targets.txt"
    api_targets.write_text("\n".join(sorted(set(filter(None, target_lines)))) + "\n", encoding="utf-8")
    if not target_lines:
        append_jsonl(run_dir / "stage_skips.jsonl", {
            "checked_at": now_iso(),
            "stage": "api_discovery",
            "reason": "no_pending_targets",
        })
        return
    cmd = [
        sys.executable,
        str(BASE_DIR / "api_discovery.py"),
        "--targets",
        str(api_targets),
        "--out-dir",
        str(run_dir),
        "--delay",
        str(delay),
        "--timeout",
        "10",
        "--max-js",
        str(args.api_max_js),
    ]
    if args.api_use_katana:
        cmd.append("--use-katana")
    with (run_dir / "api_discovery.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "api_discovery.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "api_discovery_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def run_api_confirm_stage(run_dir: Path, args: argparse.Namespace, delay: float) -> None:
    cmd = [
        sys.executable,
        str(BASE_DIR / "api_endpoint_confirm.py"),
        "--run-dir",
        str(run_dir),
        "--delay",
        str(delay),
        "--timeout",
        "10",
        "--threshold",
        str(args.api_confirm_threshold),
        "--max-per-target",
        str(args.api_confirm_max_per_target),
    ]
    if args.force:
        cmd.append("--force")
    with (run_dir / "api_confirm.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "api_confirm.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "api_confirm_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def run_sqli_triage_stage(run_dir: Path, args: argparse.Namespace, delay: float) -> None:
    cmd = [
        sys.executable,
        str(BASE_DIR / "sqli_triage.py"),
        "--run-dir",
        str(run_dir),
        "--delay",
        str(delay),
        "--timeout",
        "10",
        "--max-per-host",
        str(args.sqli_max_per_host),
        "--max-params-per-url",
        str(args.sqli_max_params_per_url),
    ]
    if args.sqli_limit:
        cmd.extend(["--limit", str(args.sqli_limit)])
    if args.force:
        cmd.append("--force")
    with (run_dir / "sqli_triage.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "sqli_triage.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "sqli_triage_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def run_xss_triage_stage(run_dir: Path, args: argparse.Namespace, delay: float) -> None:
    cmd = [
        sys.executable,
        str(BASE_DIR / "xss_candidate_triage.py"),
        "--run-dir",
        str(run_dir),
        "--delay",
        str(delay),
        "--timeout",
        "10",
        "--max-per-host",
        str(args.xss_max_per_host),
        "--max-params-per-url",
        str(args.xss_max_params_per_url),
    ]
    if args.xss_limit:
        cmd.extend(["--limit", str(args.xss_limit)])
    if args.xss_reflect_check:
        cmd.append("--reflect-check")
    if args.force:
        cmd.append("--force")
    with (run_dir / "xss_triage.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "xss_triage.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "xss_triage_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def run_shiro_triage_stage(run_dir: Path, args: argparse.Namespace, delay: float) -> None:
    cmd = [
        sys.executable,
        str(BASE_DIR / "shiro_triage.py"),
        "--run-dir",
        str(run_dir),
        "--delay",
        str(delay),
        "--timeout",
        "10",
    ]
    if args.shiro_limit:
        cmd.extend(["--limit", str(args.shiro_limit)])
    if args.shiro_include_all:
        cmd.append("--include-all")
    if args.force:
        cmd.append("--force")
    with (run_dir / "shiro_triage.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "shiro_triage.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "shiro_triage_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def run_authenticated_review_stage(run_dir: Path, args: argparse.Namespace, delay: float) -> None:
    if not args.auth_cookie_file:
        append_jsonl(run_dir / "authenticated_review_errors.jsonl", {
            "checked_at": now_iso(),
            "error": "auth_cookie_file_required",
        })
        return
    if not args.auth_cookie_file.exists():
        append_jsonl(run_dir / "authenticated_review_errors.jsonl", {
            "checked_at": now_iso(),
            "error": "auth_cookie_file_not_found",
            "path": str(args.auth_cookie_file),
        })
        return
    cmd = [
        sys.executable,
        str(BASE_DIR / "authenticated_session_review.py"),
        "--run-dir",
        str(run_dir),
        "--cookie-file",
        str(args.auth_cookie_file),
        "--delay",
        str(delay),
        "--timeout",
        "10",
        "--max-js",
        str(args.auth_max_js),
        "--max-endpoints",
        str(args.auth_max_endpoints),
    ]
    with (run_dir / "authenticated_review.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "authenticated_review.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "authenticated_review_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": [value if value != str(args.auth_cookie_file) else "<auth_cookie_file>" for value in cmd],
        })


def safe_stage_name(path: Path) -> str:
    raw = path.name or "miniapp_source"
    return re.sub(r"[^A-Za-z0-9_.\-\u4e00-\u9fff]+", "_", raw).strip("_")[:80] or "miniapp_source"


def safe_burp_label(value: str) -> str:
    raw = Path(value).stem if value else "小程序Burp"
    return re.sub(r"[^A-Za-z0-9_.\-\u4e00-\u9fff]+", "_", raw).strip("._-")[:80] or "小程序Burp"


def miniapp_manual_out_dir(run_dir: Path, args: argparse.Namespace) -> Path:
    base = run_dir / MINIAPP_BURP_DIR_NAME
    if args.miniapp_burp_export:
        labels = [safe_burp_label(str(path)) for path in args.miniapp_burp_export]
        if len(labels) == 1:
            return base / f"{labels[0]}_导入结果"
        return base / f"{labels[0]}_等{len(labels)}个文件_导入结果"
    return base / "小程序搜索包"


def run_miniapp_source_stage(run_dir: Path, args: argparse.Namespace) -> None:
    for index, source_dir in enumerate(args.miniapp_source_dir, start=1):
        if not source_dir.exists():
            append_jsonl(run_dir / "miniapp_source_errors.jsonl", {
                "checked_at": now_iso(),
                "source_dir": str(source_dir),
                "error": "source_dir_not_found",
            })
            continue
        out_dir = run_dir / "miniapp_source_offline" / f"{index:02d}_{safe_stage_name(source_dir)}"
        cmd = [
            sys.executable,
            str(BASE_DIR / "miniapp_endpoint_offline.py"),
            "--source-dir",
            str(source_dir),
            "--out-dir",
            str(out_dir),
            "--scope-targets",
            str(run_dir / "targets.json"),
            "--api-candidates-out",
            str(run_dir / "miniapp_source_api_candidates.jsonl"),
            "--in-scope-api-candidates-out",
            str(run_dir / "api_candidates.jsonl"),
            "--pending-assets-out",
            str(run_dir / "miniapp_source_new_assets_pending.txt"),
            "--append-api-candidates",
        ]
        with (run_dir / f"miniapp_source_{index:02d}.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
            run_dir / f"miniapp_source_{index:02d}.err.log"
        ).open("w", encoding="utf-8", errors="ignore") as err:
            proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
        if proc.returncode != 0:
            append_jsonl(run_dir / "miniapp_source_errors.jsonl", {
                "checked_at": now_iso(),
                "source_dir": str(source_dir),
                "returncode": proc.returncode,
                "cmd": cmd,
            })


def run_miniapp_manual_stage(run_dir: Path, args: argparse.Namespace) -> None:
    if not args.miniapp_search_pack and not args.miniapp_burp_export:
        return
    out_dir = miniapp_manual_out_dir(run_dir, args)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(BASE_DIR / "miniapp_manual_search_helper.py"),
        "--targets",
        str(run_dir / "targets.csv"),
        "--out-dir",
        str(out_dir),
        "--api-candidates-out",
        str(out_dir / "burp_miniapp_api_candidates.jsonl"),
        "--in-scope-api-candidates-out",
        str(out_dir / "burp_miniapp_in_scope_api_candidates.jsonl"),
        "--main-api-candidates-out",
        str(run_dir / "api_candidates.jsonl"),
        "--pending-assets-out",
        str(out_dir / "burp_miniapp_new_assets_pending.txt"),
    ]
    if args.miniapp_search_pack:
        cmd.append("--search-pack")
    for export in args.miniapp_burp_export:
        cmd.extend(["--burp-export", str(export)])
    redacted_cmd = ["<burp_export>" if any(str(path) == value for path in args.miniapp_burp_export) else value for value in cmd]
    with (out_dir / "miniapp_manual_search.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        out_dir / "miniapp_manual_search.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(out_dir / "miniapp_manual_search_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": redacted_cmd,
        })


def run_weak_credential_review_stage(run_dir: Path, args: argparse.Namespace, delay: float) -> None:
    try:
        manifest = run_weak_credential_review(
            run_dir=run_dir,
            max_targets=int(args.weak_credential_max_targets),
            max_pairs=int(args.weak_credential_max_pairs),
            delay=float(delay),
            timeout=int(args.weak_credential_timeout),
            force=bool(args.force),
            auto_auth_review=bool(args.weak_credential_auto_auth_review),
            auth_max_js=int(args.auth_max_js),
            auth_max_endpoints=int(args.auth_max_endpoints),
        )
        (run_dir / "weak_credential_review.out.log").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:  # noqa: BLE001
        append_jsonl(run_dir / "weak_credential_errors.jsonl", {
            "checked_at": now_iso(),
            "error": str(exc)[:300],
        })


def run_product_triage_stage(run_dir: Path) -> None:
    """Build the offline product-aware operator queue without sending requests."""
    try:
        write_product_outputs(run_dir, build_product_findings(run_dir))
    except Exception as exc:  # noqa: BLE001
        append_jsonl(run_dir / "product_triage_errors.jsonl", {
            "checked_at": now_iso(),
            "error": str(exc)[:500],
        })


def run_fingerprint_deepening_stage(run_dir: Path) -> None:
    """Build offline product-specific next-step queues without sending requests."""
    cmd = [
        sys.executable,
        str(BASE_DIR / "fingerprint_deepening.py"),
        "--run-dir",
        str(run_dir),
    ]
    with (run_dir / "fingerprint_deepening.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "fingerprint_deepening.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "fingerprint_deepening_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def run_healthcare_privacy_stage(run_dir: Path) -> None:
    """Create a schema-only patient-information exposure review queue offline."""
    try:
        findings = build_healthcare_privacy_triage(run_dir)
        write_healthcare_privacy_outputs(run_dir, findings)
    except Exception as exc:  # noqa: BLE001
        append_jsonl(run_dir / "healthcare_privacy_errors.jsonl", {
            "checked_at": now_iso(),
            "error": str(exc)[:500],
        })


def run_second_pass_triage_stage(run_dir: Path, args: argparse.Namespace, delay: float) -> None:
    cmd = [
        sys.executable,
        str(BASE_DIR / "second_pass_triage.py"),
        "--run-dir",
        str(run_dir),
        "--delay",
        str(delay),
        "--timeout",
        "10",
        "--sql-limit",
        str(args.second_pass_sql_limit),
        "--xss-limit",
        str(args.second_pass_xss_limit),
        "--api-limit",
        str(args.second_pass_api_limit),
    ]
    if args.force:
        cmd.append("--force")
    with (run_dir / "second_pass_triage.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "second_pass_triage.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "second_pass_triage_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def run_review_intelligence_stage(run_dir: Path) -> None:
    cmd = [
        sys.executable,
        str(BASE_DIR / "review_intelligence.py"),
        "--run-dir",
        str(run_dir),
    ]
    with (run_dir / "review_intelligence.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "review_intelligence.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "review_intelligence_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def run_wechat_miniapp_stage(run_dir: Path, args: argparse.Namespace, delay: float) -> None:
    cmd = [
        sys.executable,
        str(BASE_DIR / "wechat_miniapp_discovery.py"),
        "--run-dir",
        str(run_dir),
        "--out-dir",
        str(run_dir),
        "--delay",
        str(delay),
        "--timeout",
        "8",
        "--max-js",
        str(args.wechat_max_js),
    ]
    if args.wechat_limit:
        cmd.extend(["--limit", str(args.wechat_limit)])
    if args.wechat_live:
        cmd.append("--live")
    with (run_dir / "wechat_miniapp.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "wechat_miniapp.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "wechat_miniapp_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def run_evidence_builder_stage(run_dir: Path, args: argparse.Namespace) -> None:
    cmd = [
        sys.executable,
        str(BASE_DIR / "evidence_builder.py"),
        str(run_dir),
        "--config",
        str(args.config),
    ]
    with (run_dir / "evidence_builder.out.log").open("w", encoding="utf-8", errors="ignore") as out, (
        run_dir / "evidence_builder.err.log"
    ).open("w", encoding="utf-8", errors="ignore") as err:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), stdout=out, stderr=err)
    if proc.returncode != 0:
        append_jsonl(run_dir / "evidence_builder_errors.jsonl", {
            "checked_at": now_iso(),
            "returncode": proc.returncode,
            "cmd": cmd,
        })


def main() -> int:
    args = parse_args()
    if args.xss_reflect_check:
        args.xss_triage = True
    cfg = load_config(args.config)
    workflow_path = resolve_relative_config_path(args.config, args.workflow or cfg.get("workflow"), DEFAULT_WORKFLOW)
    workflow = load_workflow(workflow_path)
    strategy_path = resolve_relative_config_path(args.config, cfg.get("tool_strategy"), DEFAULT_TOOL_STRATEGY)
    tool_strategy = load_tool_strategy(strategy_path)
    targets = load_targets(args.targets)
    if not targets:
        raise SystemExit(f"No targets loaded from {args.targets}")
    max_targets = int(cfg.get("max_targets", 500))
    if len(targets) > max_targets:
        raise SystemExit(f"Refusing {len(targets)} targets; max_targets is {max_targets}")

    run_label = args.label or cfg.get("label", "gx_gov")
    if args.resume_run_dir:
        run_dir = args.resume_run_dir
        if not run_dir.exists():
            raise SystemExit(f"Resume run directory does not exist: {run_dir}")
        for subdir in ("logs", "evidence", "reports"):
            (run_dir / subdir).mkdir(parents=True, exist_ok=True)
    else:
        run_dir = create_run_dir(run_label)
    write_targets(run_dir, targets, args.targets)
    write_workflow_plan(run_dir, workflow, args)

    runtime = collect_runtime_inventory(cfg)
    write_json(run_dir / "runtime_inventory.json", runtime)
    write_tool_strategy_plan(run_dir, tool_strategy, runtime)
    write_compliance_files(run_dir, cfg, args)
    write_approval_required(run_dir, workflow)
    write_empty_workflow_outputs(run_dir)

    delay = cfg.get("default_delay_seconds", 2.0) if args.delay is None else args.delay
    if args.healthcare_profile:
        delay = max(float(delay), 3.0)
    if args.subdomain_bruteforce:
        try:
            run_subdomain_bruteforce_stage(run_dir, args)
        except Exception as exc:  # noqa: BLE001
            append_jsonl(run_dir / "subdomain_bruteforce_errors.jsonl", {
                "checked_at": now_iso(),
                "stage": "subdomain_bruteforce",
                "error": type(exc).__name__,
                "message": str(exc)[:500],
                "continuing": True,
            })
            print(f"[!] 子域名阶段未捕获异常，已记录并继续后续流程: {type(exc).__name__}: {str(exc)[:160]}", flush=True)
    if args.probe:
        run_probe(run_dir, targets, cfg, args.limit or None, float(delay), force=args.force)
    if args.fingerprint or args.probe:
        run_fingerprint(run_dir)
    if args.tool_fingerprint:
        if not args.probe and not (run_dir / "probe_results.jsonl").exists():
            run_probe(run_dir, targets, cfg, args.limit or None, float(delay), force=args.force)
            run_fingerprint(run_dir)
        run_tool_fingerprint_stage(run_dir, args, float(delay))
    if args.high_value_paths:
        if not args.probe:
            run_probe(run_dir, targets, cfg, args.limit or None, float(delay), force=args.force)
            run_fingerprint(run_dir)
        run_high_value_paths(run_dir, targets, cfg, args.limit or None, float(delay), force=args.force)
    if args.api_discovery:
        if not args.probe and not (run_dir / "probe_results.jsonl").exists():
            run_probe(run_dir, targets, cfg, args.limit or None, float(delay), force=args.force)
            run_fingerprint(run_dir)
        run_api_discovery_stage(run_dir, args, float(delay))
    if args.miniapp_source_dir:
        run_miniapp_source_stage(run_dir, args)
    if args.miniapp_search_pack or args.miniapp_burp_export:
        run_miniapp_manual_stage(run_dir, args)
    if args.api_confirm:
        if not (run_dir / "api_candidates.jsonl").exists():
            append_jsonl(run_dir / "api_confirm_errors.jsonl", {
                "checked_at": now_iso(),
                "error": "api_candidates_missing",
            })
        else:
            run_api_confirm_stage(run_dir, args, float(delay))
    if args.xss_triage:
        run_xss_triage_stage(run_dir, args, float(delay))
    if args.sqli_triage:
        if not args.api_discovery and not (run_dir / "api_candidates.jsonl").exists():
            append_jsonl(run_dir / "sqli_triage_errors.jsonl", {
                "checked_at": now_iso(),
                "error": "api_candidates_missing",
            })
        else:
            run_sqli_triage_stage(run_dir, args, float(delay))
    if args.shiro_triage:
        if not args.probe and not (run_dir / "fingerprints.jsonl").exists():
            run_probe(run_dir, targets, cfg, args.limit or None, float(delay), force=args.force)
            run_fingerprint(run_dir)
        run_shiro_triage_stage(run_dir, args, float(delay))
    if args.wechat_miniapp:
        # Mini-program clue generation is offline by default.  Do not silently
        # turn it into an HTTP probe; network access requires --probe or the
        # explicit, bounded --wechat-live option.
        run_wechat_miniapp_stage(run_dir, args, float(delay))

    # Always refresh the offline operator handoff after discovery stages.
    build_manual_auth_handoff(run_dir)
    if args.product_triage:
        run_product_triage_stage(run_dir)
    if args.fingerprint_deepening:
        run_fingerprint_deepening_stage(run_dir)
    if args.weak_credential_review:
        run_weak_credential_review_stage(run_dir, args, float(delay))
    if args.auth_review:
        run_authenticated_review_stage(run_dir, args, float(delay))

    if args.healthcare_profile:
        run_healthcare_privacy_stage(run_dir)

    if args.second_pass_triage:
        run_second_pass_triage_stage(run_dir, args, float(delay))
    if args.review_intelligence:
        run_review_intelligence_stage(run_dir)

    write_summary(run_dir, targets, runtime, cfg, args)
    if not args.no_evidence_build:
        run_evidence_builder_stage(run_dir, args)
    print(json.dumps({
        "run_dir": str(run_dir),
        "target_count": len(targets),
        "mode": "probe" if args.probe else "check",
        "summary": str(run_dir / "run_summary.json"),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
