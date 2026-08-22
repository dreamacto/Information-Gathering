#!/usr/bin/env python3
"""Manual-auth handoff and bounded authenticated JS/API review.

The module never registers accounts or performs login attempts. It prepares a
manual queue for the operator, then accepts an operator-provided session file
for same-host, GET-only metadata review. Cookies and authorization headers are
kept in memory and are never written to result files.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import ssl
import time
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from api_discovery import SCRIPT_RE, classify_endpoint, extract_js_findings, normalize_url


USER_AGENT = "Authorized-Authenticated-ReadOnly-Review/1.0"
REGISTER_RE = re.compile(r"(register|signup|sign-up|join|create.?account|注册|用户注册|立即注册)", re.I)
LOGIN_RE = re.compile(r"(login|signin|sign-in|sso|cas|auth|登录|统一认证)", re.I)
WRITE_RE = re.compile(
    r"(/|\b)(upload|import|delete|remove|drop|update|modify|edit|save|create|add|submit|"
    r"pay|payment|refund|send|mail|sms|reset|password|passwd|logout)(/|\b|[A-Z_-])",
    re.I,
)
DIRECT_FILE_RE = re.compile(r"(/|\b)(download|export|attachment|preview|file)(/|\b|[A-Z_-])", re.I)
QUERY_RE = re.compile(r"(/|\b)(list|page|query|search|find|get|detail|info|records?)(/|\b|[A-Z_-])", re.I)
ABSOLUTE_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
SENSITIVE_FIELD_RE = re.compile(
    r"(password|passwd|pwd|secret|token|credential|idcard|identity|mobile|phone|email|address|"
    r"bank|account|name|username|realname|身份证|手机号|电话|邮箱|地址|姓名|账号)",
    re.I,
)


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
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


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def build_manual_auth_handoff(run_dir: Path) -> dict:
    items: dict[str, dict] = {}

    def add(
        base_url: str,
        reason: str,
        evidence_url: str = "",
        register: bool = False,
        scope_state: str = "in_current_scope",
    ) -> None:
        if not base_url:
            return
        key = base_url.rstrip("/")
        item = items.setdefault(key, {
            "base_url": key,
            "host": host_of(key),
            "login_detected": False,
            "registration_candidate": False,
            "reasons": [],
            "evidence_urls": [],
            "operator_status": "pending",
            "scope_state": scope_state,
        })
        item["login_detected"] = True
        item["registration_candidate"] = bool(item["registration_candidate"] or register)
        if scope_state == "in_current_scope" or item.get("scope_state") != "in_current_scope":
            item["scope_state"] = scope_state
        item["reasons"].append(reason)
        if evidence_url:
            item["evidence_urls"].append(evidence_url)

    for row in read_jsonl(run_dir / "fingerprints.jsonl"):
        if "login" in set(row.get("categories") or []):
            add(str(row.get("url") or ""), "fingerprint_login", str(row.get("final_url") or row.get("url") or ""))

    for row in read_jsonl(run_dir / "api_candidates.jsonl"):
        url = str(row.get("url") or "")
        tags = set(row.get("tags") or [])
        text = url + " " + " ".join(tags)
        if "auth_or_login" in tags or LOGIN_RE.search(text) or REGISTER_RE.search(text):
            add(
                str(row.get("base_url") or url),
                "registration_endpoint_candidate" if REGISTER_RE.search(text) else "auth_endpoint_candidate",
                url,
                register=bool(REGISTER_RE.search(text)),
            )

    for row in read_jsonl(run_dir / "api_discovery.jsonl"):
        text = " ".join(str(row.get(k) or "") for k in ("url", "final_url", "title", "path"))
        if LOGIN_RE.search(text) or REGISTER_RE.search(text):
            add(
                str(row.get("base_url") or row.get("url") or ""),
                "registration_page_candidate" if REGISTER_RE.search(text) else "login_page_candidate",
                str(row.get("url") or ""),
                register=bool(REGISTER_RE.search(text)),
            )

    wechat_auth_path = run_dir / "wechat_auth_domains.json"
    if wechat_auth_path.exists():
        try:
            wechat_auth = json.loads(wechat_auth_path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            wechat_auth = {}
        for row in wechat_auth.get("items", []) if isinstance(wechat_auth, dict) else []:
            if not isinstance(row, dict) or row.get("scope_state") == "platform_excluded":
                continue
            login_urls = row.get("login_urls") if isinstance(row.get("login_urls"), list) else []
            add(
                str(row.get("base_url") or ""),
                "wechat_registration_candidate" if row.get("registration_candidate") else "wechat_login_candidate",
                str(login_urls[0] if login_urls else row.get("base_url") or ""),
                register=bool(row.get("registration_candidate")),
                scope_state=str(row.get("scope_state") or "ownership_confirmation_required"),
            )

    output = []
    for item in items.values():
        item["reasons"] = sorted(set(item["reasons"]))
        item["evidence_urls"] = sorted(set(item["evidence_urls"]))[:10]
        if item.get("scope_state") == "in_current_scope":
            item["manual_action"] = (
                "Open in browser; register only if explicitly allowed; login; capture the session cookie; fill auth_sessions.local.json."
            )
        else:
            item["manual_action"] = "Confirm domain ownership and target approval before login, registration, or cookie use."
        output.append(item)
    output.sort(key=lambda row: (row.get("scope_state") != "in_current_scope", not row["registration_candidate"], row["host"], row["base_url"]))

    json_path = run_dir / "manual_auth_queue.json"
    json_path.write_text(json.dumps({
        "generated_at": now_iso(),
        "count": len(output),
        "items": output,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    csv_path = run_dir / "manual_auth_queue.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "base_url", "host", "login_detected", "registration_candidate", "scope_state", "reasons", "evidence_urls", "operator_status"
        ])
        writer.writeheader()
        for item in output:
            writer.writerow({
                **{key: item.get(key, "") for key in writer.fieldnames},
                "reasons": ";".join(item["reasons"]),
                "evidence_urls": ";".join(item["evidence_urls"]),
            })

    md_lines = [
        "# Manual Authentication Queue",
        "",
        f"- Generated: {now_iso()}",
        f"- Pending targets: {len(output)}",
        "- This queue does not authorize automatic registration, password testing, or bypass attempts.",
        "",
        "| Scope | Registration | Target | Evidence | Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in output:
        evidence = "<br>".join(f"`{value}`" for value in item["evidence_urls"][:3])
        md_lines.append(
            f"| {item.get('scope_state', 'in_current_scope')} | {'yes' if item['registration_candidate'] else 'unknown'} | "
            f"`{item['base_url']}` | {evidence} | pending |"
        )
    (run_dir / "reports" / "manual_auth_queue.md").parent.mkdir(parents=True, exist_ok=True)
    (run_dir / "reports" / "manual_auth_queue.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    template_path = run_dir / "auth_sessions.template.json"
    if not template_path.exists():
        session_rows = [
            {
                "base_url": item["base_url"],
                "entry_url": item["evidence_urls"][0] if item["evidence_urls"] else item["base_url"],
                "cookie": "<paste locally; never submit this file with the report>",
                "headers": {},
            }
            for item in output if item.get("scope_state") == "in_current_scope"
        ]
        if not session_rows:
            session_rows = [{
                "base_url": "https://replace-me.invalid",
                "entry_url": "https://replace-me.invalid/dashboard",
                "cookie": "SESSION=<paste locally; never submit this file with the report>",
                "headers": {},
            }]
        template_path.write_text(json.dumps({
            "sessions": session_rows
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"count": len(output), "json": str(json_path), "csv": str(csv_path)}


def load_sessions(path: Path) -> list[dict]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    sessions = parsed.get("sessions", []) if isinstance(parsed, dict) else parsed
    if not isinstance(sessions, list):
        raise ValueError("session file must contain a sessions array")
    return [row for row in sessions if isinstance(row, dict)]


def allowed_hosts(run_dir: Path) -> set[str]:
    hosts: set[str] = set()
    targets_json = run_dir / "targets.json"
    if targets_json.exists():
        try:
            parsed = json.loads(targets_json.read_text(encoding="utf-8", errors="ignore"))
            for row in parsed.get("targets", []):
                hosts.add(host_of(str(row.get("url") or "")))
        except (json.JSONDecodeError, AttributeError):
            pass
    for name in ("probe_results.jsonl", "fingerprints.jsonl"):
        for row in read_jsonl(run_dir / name):
            hosts.add(host_of(str(row.get("url") or "")))
    return {host for host in hosts if host}


def safe_headers(session: dict) -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/json,*/*;q=0.8", "Range": "bytes=0-131071"}
    cookie = str(session.get("cookie") or "").strip()
    if cookie:
        headers["Cookie"] = cookie
    supplied = session.get("headers") or {}
    if isinstance(supplied, dict):
        for key, value in supplied.items():
            if str(key).lower() in {"authorization", "x-auth-token", "x-access-token"} and value:
                headers[str(key)] = str(value)
    return headers


def fetch_metadata(url: str, headers: dict[str, str], timeout: int, max_bytes: int = 131072) -> tuple[dict, str]:
    started = time.time()
    request = Request(url, headers=headers, method="GET")
    context = ssl._create_unverified_context()
    status = 0
    final_url = url
    response_headers: dict[str, str] = {}
    body = b""
    error = ""
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            status = int(response.getcode() or 0)
            final_url = response.geturl()
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read(max_bytes + 1)[:max_bytes]
    except HTTPError as exc:
        status = int(exc.code or 0)
        final_url = exc.geturl() or url
        response_headers = {key.lower(): value for key, value in exc.headers.items()}
        body = exc.read(max_bytes + 1)[:max_bytes]
    except (URLError, TimeoutError, OSError) as exc:
        error = str(exc)[:300]
    content_type = response_headers.get("content-type", "")
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type, re.I)
    if match:
        charset = match.group(1)
    text = body.decode(charset, errors="ignore")
    record = {
        "checked_at": now_iso(),
        "url": url,
        "status": status,
        "final_url": final_url,
        "content_type": content_type,
        "declared_content_length": response_headers.get("content-length", ""),
        "sample_length": len(body),
        "sample_sha256": hashlib.sha256(body).hexdigest() if body else "",
        "elapsed_seconds": round(time.time() - started, 3),
        "set_cookie_present": "set-cookie" in response_headers,
        "error": error,
    }
    return record, text


def json_schema(text: str, content_type: str) -> dict:
    out = {"is_json": "json" in content_type.lower() or text.lstrip().startswith(("{", "["))}
    if not out["is_json"]:
        return out
    try:
        parsed = json.loads(text)
    except Exception:
        out["json_parse_error"] = True
        return out
    keys: list[str] = []

    def walk(value, depth: int = 0) -> None:
        if depth > 3 or len(keys) >= 100:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                keys.append(str(key)[:80])
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value[:3]:
                walk(child, depth + 1)

    walk(parsed)
    out["top_level_type"] = "object" if isinstance(parsed, dict) else "array" if isinstance(parsed, list) else type(parsed).__name__
    out["top_level_keys"] = list(parsed.keys())[:30] if isinstance(parsed, dict) else []
    out["array_length_sample"] = len(parsed) if isinstance(parsed, list) else None
    out["observed_field_names"] = sorted(set(keys))[:100]
    out["sensitive_field_names"] = sorted({key for key in keys if SENSITIVE_FIELD_RE.search(key)})[:30]
    return out


def session_appears_valid(record: dict, text: str) -> bool:
    final_path = (urlparse(str(record.get("final_url") or "")).path or "").lower()
    if LOGIN_RE.search(final_path):
        return False
    lower = text[:200000].lower()
    has_password_field = "type=\"password\"" in lower or "type='password'" in lower
    has_login_text = bool(LOGIN_RE.search(lower))
    return not (has_password_field and has_login_text)


def should_fetch_endpoint(url: str) -> tuple[bool, str]:
    path = urlparse(url).path or "/"
    if WRITE_RE.search(path):
        return False, "write_or_account_action"
    if DIRECT_FILE_RE.search(path) and not QUERY_RE.search(path):
        return False, "direct_file_or_export_candidate"
    return True, ""


def run_authenticated_review_with_sessions(
    run_dir: Path,
    sessions: list[dict],
    delay: float,
    timeout: int,
    max_js: int,
    max_endpoints: int,
    *,
    reset_outputs: bool = True,
    manifest_name: str = "authenticated_review_manifest.json",
    session_source: str = "operator_file",
) -> dict:
    scope_hosts = allowed_hosts(run_dir)
    results_path = run_dir / "authenticated_api_results.jsonl"
    impact_path = run_dir / "authenticated_impact_candidates.jsonl"
    skips_path = run_dir / "authenticated_review_skips.jsonl"
    pending_assets_path = run_dir / "authenticated_new_assets_pending.txt"
    if reset_outputs:
        for path in (results_path, impact_path, skips_path):
            path.write_text("", encoding="utf-8")
    total_requests = 0
    impact_count = 0
    pending_assets: set[str] = set()

    existing_candidates = read_jsonl(run_dir / "api_candidates.jsonl")
    unauthenticated_baseline = {
        str(row.get("url") or "").rstrip("/"): row
        for row in read_jsonl(run_dir / "api_confirmed.jsonl")
        if row.get("url")
    }
    for session in sessions:
        base_url = str(session.get("base_url") or "").rstrip("/")
        entry_url = str(session.get("entry_url") or base_url).strip()
        host = host_of(base_url)
        if not base_url or not host or host not in scope_hosts or host_of(entry_url) != host:
            append_jsonl(skips_path, {"checked_at": now_iso(), "base_url": base_url, "reason": "outside_run_scope_or_host_mismatch"})
            continue
        headers = safe_headers(session)
        has_auth_material = bool(headers.get("Cookie")) or any(
            key.lower() in {"authorization", "x-auth-token", "x-access-token"}
            for key in headers
        )
        if not has_auth_material:
            append_jsonl(skips_path, {"checked_at": now_iso(), "base_url": base_url, "reason": "no_cookie_or_authorization_header"})
            continue

        endpoint_urls: set[str] = set()
        script_urls: set[str] = set()
        record, text = fetch_metadata(entry_url, headers, timeout)
        total_requests += 1
        record.update({"base_url": base_url, "family": "authenticated_entry"})
        record["session_appears_valid"] = session_appears_valid(record, text)
        record.update(json_schema(text, record["content_type"]))
        append_jsonl(results_path, record)
        if not record["session_appears_valid"]:
            append_jsonl(skips_path, {
                "checked_at": now_iso(), "base_url": base_url, "url": entry_url,
                "reason": "session_appears_expired_or_redirected_to_login",
            })
            time.sleep(delay)
            continue
        for match in SCRIPT_RE.finditer(text):
            js_url = normalize_url(entry_url, match.group(1))
            if js_url and host_of(js_url) == host:
                script_urls.add(js_url)
        time.sleep(delay)

        for js_url in sorted(script_urls)[:max_js]:
            js_record, js_text = fetch_metadata(js_url, headers, timeout)
            total_requests += 1
            js_record.update({"base_url": base_url, "family": "authenticated_javascript"})
            append_jsonl(results_path, js_record)
            if js_record["status"] in (200, 206) and js_text:
                for absolute_url in ABSOLUTE_URL_RE.findall(js_text):
                    discovered_host = host_of(absolute_url.rstrip("\"'();,}"))
                    if discovered_host and discovered_host != host:
                        pending_assets.add(absolute_url.rstrip("\"'();,}"))
                endpoints, source_maps, secrets = extract_js_findings(base_url, js_url, js_text)
                endpoint_urls.update(url for url in endpoints if host_of(url) == host)
                for map_url in source_maps:
                    append_jsonl(impact_path, {
                        "checked_at": now_iso(), "base_url": base_url, "finding": "authenticated_source_map_reference",
                        "url": map_url, "source": js_url, "priority": "medium",
                    })
                    impact_count += 1
                if secrets:
                    append_jsonl(impact_path, {
                        "checked_at": now_iso(), "base_url": base_url, "finding": "authenticated_js_sensitive_keywords",
                        "source": js_url, "keywords": sorted({str(row.get('keyword') or '') for row in secrets})[:20],
                        "priority": "review",
                    })
                    impact_count += 1
            time.sleep(delay)

        for row in existing_candidates:
            url = str(row.get("url") or "")
            if host_of(str(row.get("base_url") or url)) == host and host_of(url) == host:
                endpoint_urls.add(url)

        fetched = 0
        for endpoint in sorted(endpoint_urls, key=lambda value: -classify_endpoint(value)["priority_score"]):
            ok, reason = should_fetch_endpoint(endpoint)
            if not ok:
                append_jsonl(skips_path, {
                    "checked_at": now_iso(), "base_url": base_url, "url": endpoint, "reason": reason,
                    "manual_review_candidate": True,
                })
                if reason == "direct_file_or_export_candidate":
                    append_jsonl(impact_path, {
                        "checked_at": now_iso(), "base_url": base_url, "finding": "authenticated_file_or_export_candidate",
                        "url": endpoint, "priority": "high", "note": "not requested automatically",
                    })
                    impact_count += 1
                continue
            if fetched >= max_endpoints:
                break
            endpoint_record, endpoint_text = fetch_metadata(endpoint, headers, timeout)
            total_requests += 1
            fetched += 1
            endpoint_record.update({"base_url": base_url, "family": "authenticated_api", **classify_endpoint(endpoint)})
            endpoint_record.update(json_schema(endpoint_text, endpoint_record["content_type"]))
            baseline = unauthenticated_baseline.get(endpoint.rstrip("/"))
            if baseline:
                endpoint_record["unauthenticated_status"] = int(baseline.get("status") or 0)
                endpoint_record["status_changed_after_auth"] = endpoint_record["status"] != endpoint_record["unauthenticated_status"]
                endpoint_record["sample_changed_after_auth"] = bool(
                    baseline.get("sample_sha256")
                    and endpoint_record.get("sample_sha256")
                    and baseline.get("sample_sha256") != endpoint_record.get("sample_sha256")
                )
            append_jsonl(results_path, endpoint_record)
            if (
                baseline
                and int(baseline.get("status") or 0) in (0, 301, 302, 303, 307, 308, 401, 403)
                and endpoint_record["status"] in (200, 206)
                and endpoint_record.get("is_json")
            ):
                append_jsonl(impact_path, {
                    "checked_at": now_iso(), "base_url": base_url,
                    "finding": "authenticated_boundary_opened_json_api", "url": endpoint,
                    "unauthenticated_status": int(baseline.get("status") or 0),
                    "authenticated_status": endpoint_record["status"], "priority": "high",
                    "note": "compared with existing unauthenticated metadata; no extra baseline request",
                })
                impact_count += 1
            if endpoint_record.get("sensitive_field_names"):
                append_jsonl(impact_path, {
                    "checked_at": now_iso(), "base_url": base_url, "finding": "authenticated_json_sensitive_schema",
                    "url": endpoint, "status": endpoint_record["status"],
                    "sensitive_field_names": endpoint_record["sensitive_field_names"],
                    "top_level_type": endpoint_record.get("top_level_type"), "priority": "high",
                    "note": "field names only; response values were not persisted",
                })
                impact_count += 1
            time.sleep(delay)

    pending_assets_path.write_text(
        "\n".join(sorted(pending_assets)) + ("\n" if pending_assets else ""), encoding="utf-8"
    )

    manifest = {
        "created_at": now_iso(),
        "session_count": len(sessions),
        "request_count": total_requests,
        "impact_count": impact_count,
        "delay": delay,
        "timeout": timeout,
        "max_js_per_session": max_js,
        "max_endpoints_per_session": max_endpoints,
        "session_source": session_source,
        "cookie_persisted": False,
        "token_persisted": False,
        "response_body_persisted": False,
        "pending_new_assets": len(pending_assets),
    }
    (run_dir / manifest_name).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def run_authenticated_review(
    run_dir: Path,
    cookie_file: Path,
    delay: float,
    timeout: int,
    max_js: int,
    max_endpoints: int,
) -> dict:
    sessions = load_sessions(cookie_file)
    return run_authenticated_review_with_sessions(
        run_dir=run_dir,
        sessions=sessions,
        delay=delay,
        timeout=timeout,
        max_js=max_js,
        max_endpoints=max_endpoints,
        session_source="operator_file",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Manual-auth handoff and bounded authenticated API review")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--cookie-file", type=Path)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--max-js", type=int, default=20)
    parser.add_argument("--max-endpoints", type=int, default=30)
    args = parser.parse_args()
    result = {}
    if args.prepare or not args.cookie_file:
        result["handoff"] = build_manual_auth_handoff(args.run_dir)
    if args.cookie_file:
        result["authenticated_review"] = run_authenticated_review(
            args.run_dir, args.cookie_file, args.delay, args.timeout, args.max_js, args.max_endpoints
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
