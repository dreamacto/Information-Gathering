#!/usr/bin/env python3
"""Explicit, bounded weak-credential review.

This stage is never run by default. It is intended for exercise windows where
the operator has confirmed that tiny, product-aware weak-credential checks are
allowed. It stops on CAPTCHA/lockout signals, caps attempts per target, and
does not persist passwords, cookies, tokens, or response bodies.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html.parser
import json
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener
from http.cookiejar import CookieJar

from authenticated_session_review import run_authenticated_review_with_sessions
from operator_action_hub import HUB_DIR_NAME, build_weak_credential_rows


USER_AGENT = "Authorized-WeakCredential-Review/1.0"
CAPTCHA_OR_LOCK_RE = re.compile(
    r"(captcha|验证码|图形码|滑块|人机|lock(ed)?|锁定|失败次数|剩余次数|风控|频繁|too many|rate.?limit)",
    re.I,
)
LOGIN_FAIL_RE = re.compile(
    r"(invalid|incorrect|wrong|failed|failure|error|密码错误|账号或密码|用户名或密码|登录失败|认证失败|不存在|不正确)",
    re.I,
)
LOGIN_SUCCESS_RE = re.compile(
    r"(logout|sign.?out|dashboard|console|admin|profile|退出|注销|控制台|工作台|个人中心|欢迎)",
    re.I,
)
LOGIN_HINT_RE = re.compile(r"(login|signin|sign-in|sso|cas|auth|登录|统一认证)", re.I)
USERNAME_RE = re.compile(r"(user(name)?|account|login|email|mail|mobile|phone|uid|工号|账号|用户名|手机号)", re.I)
PASSWORD_RE = re.compile(r"(pass(word)?|passwd|pwd|密码)", re.I)
TOKEN_KEY_RE = re.compile(r"^(token|access[_-]?token|auth[_-]?token|jwt|id[_-]?token|x[_-]?access[_-]?token|authorization)$", re.I)
PRODUCT_DEFAULT_RE = re.compile(
    r"(jeecg|jeecgboot|jeecg-boot|ruoyi|若依|druid|tomcat|nacos|shiro|weblogic|jboss|"
    r"seeyon|致远|weaver|泛微|tongda|通达|landray|蓝凌|yonyou|用友|kingdee|金蝶|oa|erp)",
    re.I,
)
ADMIN_LOGIN_RE = re.compile(r"(admin|manage|manager|console|后台|管理|登录|login|signin|auth)", re.I)
SSO_OR_STRONG_AUTH_RE = re.compile(r"(sso|cas|统一认证|单点登录|oauth|oidc|idp|扫码|短信登录|验证码|captcha|滑块|人机)", re.I)


@dataclass
class InputField:
    name: str = ""
    field_type: str = "text"
    value: str = ""


@dataclass
class LoginForm:
    action: str = ""
    method: str = "get"
    inputs: list[InputField] = field(default_factory=list)


class LoginFormParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[LoginForm] = []
        self._current: LoginForm | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            self._current = LoginForm(
                action=attr.get("action", ""),
                method=(attr.get("method") or "get").lower(),
            )
            self.forms.append(self._current)
        elif tag.lower() == "input" and self._current is not None:
            self._current.inputs.append(InputField(
                name=attr.get("name", ""),
                field_type=(attr.get("type") or "text").lower(),
                value=attr.get("value", ""),
            ))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current = None


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def origin_of(url: str) -> str:
    try:
        parsed = urlparse(url)
    except Exception:
        return url.rstrip("/")
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return url.rstrip("/")


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def build_review_opener(jar: CookieJar):
    context = ssl._create_unverified_context()
    return build_opener(HTTPCookieProcessor(jar), HTTPSHandler(context=context))


def cookie_header_from_jar(jar: CookieJar) -> str:
    pairs = []
    for cookie in jar:
        if cookie.name and cookie.value:
            pairs.append(f"{cookie.name}={cookie.value}")
    return "; ".join(pairs)


def _walk_token_values(value, found: list[tuple[str, str]], depth: int = 0) -> None:
    if depth > 5 or len(found) >= 10:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if TOKEN_KEY_RE.search(key_text) and isinstance(child, (str, int, float)):
                token = str(child).strip()
                if 8 <= len(token) <= 4096:
                    found.append((key_text, token))
            _walk_token_values(child, found, depth + 1)
    elif isinstance(value, list):
        for child in value[:10]:
            _walk_token_values(child, found, depth + 1)


def extract_transient_auth_headers(text: str, content_type: str) -> tuple[dict[str, str], list[str]]:
    stripped = text.lstrip()
    if "json" not in content_type.lower() and not stripped.startswith(("{", "[")):
        return {}, []
    try:
        parsed = json.loads(text)
    except Exception:
        return {}, []
    found: list[tuple[str, str]] = []
    _walk_token_values(parsed, found)
    if not found:
        return {}, []
    key, token = found[0]
    headers: dict[str, str] = {}
    if key.lower() == "authorization" and token.lower().startswith(("bearer ", "basic ")):
        headers["Authorization"] = token
    else:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-Access-Token"] = token
    return headers, sorted({key for key, _token in found})


def split_cell(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v]
    if value is None:
        return []
    return [part for part in str(value).split(";") if part]


def weak_candidate_score(row: dict) -> tuple[int, list[str]]:
    text = " ".join([
        str(row.get("base_url") or ""),
        " ".join(split_cell(row.get("reason"))),
        " ".join(split_cell(row.get("evidence"))),
        str(row.get("host") or ""),
    ])
    score = 30
    reasons: list[str] = ["login_surface"]
    if PRODUCT_DEFAULT_RE.search(text):
        score += 30
        reasons.append("product_default_credential_pattern")
    if ADMIN_LOGIN_RE.search(text):
        score += 14
        reasons.append("admin_or_login_keyword")
    if any(token in text.lower() for token in ("fingerprint_", "product_login_default_credential_review", "login_or_auth_surface")):
        score += 10
        reasons.append("multi_source_login_evidence")
    if any(token in text.lower() for token in ("druid", "tomcat", "jeecg", "ruoyi", "若依")):
        score += 12
        reasons.append("known_small_preset_available")
    if SSO_OR_STRONG_AUTH_RE.search(text):
        score -= 18
        reasons.append("sso_or_strong_auth_hint")
    if CAPTCHA_OR_LOCK_RE.search(text):
        score -= 30
        reasons.append("captcha_or_lockout_hint")
    if not split_cell(row.get("evidence")):
        score -= 4
        reasons.append("thin_evidence")
    return max(0, min(100, score)), sorted(set(reasons))


def build_candidates(run_dir: Path, max_targets: int, force: bool = False) -> list[dict]:
    rows = build_weak_credential_rows(run_dir)
    if not force:
        attempted = {
            origin_of(str(row.get("base_url") or ""))
            for row in read_jsonl(run_dir / "weak_credential_attempts.jsonl")
            if row.get("base_url")
        }
        rows = [row for row in rows if origin_of(str(row.get("base_url") or "")) not in attempted]
    candidates: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        base_url = origin_of(str(row.get("base_url") or ""))
        if not base_url.startswith(("http://", "https://")) or base_url in seen:
            continue
        seen.add(base_url)
        row = dict(row)
        row["base_url"] = base_url
        score, reasons = weak_candidate_score(row)
        row["weak_candidate_score"] = score
        row["weak_candidate_reasons"] = reasons
        if score < 25 and not force:
            append_jsonl(run_dir / "weak_credential_skips.jsonl", {
                "checked_at": now_iso(),
                "base_url": base_url,
                "reason": "weak_candidate_score_too_low",
                "weak_candidate_score": score,
                "weak_candidate_reasons": reasons,
            })
            continue
        candidates.append(row)
    candidates.sort(key=lambda item: (-int(item.get("weak_candidate_score") or 0), str(item.get("host") or ""), str(item.get("base_url") or "")))
    if max_targets:
        candidates = candidates[:max_targets]
    return candidates


def credential_pairs_for_candidate(candidate: dict, max_pairs: int) -> list[dict]:
    text = " ".join([
        str(candidate.get("base_url") or ""),
        " ".join(split_cell(candidate.get("reason"))),
        " ".join(split_cell(candidate.get("evidence"))),
    ]).lower()

    presets: list[tuple[str, str, str]] = []
    if any(token in text for token in ("jeecg", "jeecgboot", "jeecg-boot")):
        presets.extend([
            ("jeecg_pair_1", "admin", "123456"),
            ("jeecg_pair_2", "admin", "admin"),
            ("jeecg_pair_3", "jeecg", "jeecg"),
            ("jeecg_pair_4", "admin", "888888"),
            ("jeecg_pair_5", "test", "123456"),
        ])
    elif any(token in text for token in ("ruoyi", "若依")):
        presets.extend([
            ("ruoyi_pair_1", "admin", "admin123"),
            ("ruoyi_pair_2", "admin", "123456"),
            ("ruoyi_pair_3", "admin", "admin"),
            ("ruoyi_pair_4", "ry", "123456"),
            ("ruoyi_pair_5", "test", "123456"),
        ])
    elif "druid" in text:
        presets.extend([
            ("druid_pair_1", "admin", "admin"),
            ("druid_pair_2", "druid", "druid"),
            ("druid_pair_3", "admin", "123456"),
            ("druid_pair_4", "root", "root"),
            ("druid_pair_5", "druid", "123456"),
        ])
    elif "tomcat" in text:
        presets.extend([
            ("tomcat_pair_1", "tomcat", "tomcat"),
            ("tomcat_pair_2", "admin", "admin"),
            ("tomcat_pair_3", "manager", "manager"),
            ("tomcat_pair_4", "tomcat", "s3cret"),
            ("tomcat_pair_5", "admin", "123456"),
        ])

    presets.extend([
        ("generic_pair_1", "admin", "123456"),
        ("generic_pair_2", "admin", "admin"),
        ("generic_pair_3", "admin", "admin123"),
        ("generic_pair_4", "test", "123456"),
        ("generic_pair_5", "guest", "guest"),
    ])

    output: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for preset_id, username, password in presets:
        key = (username, password)
        if key in seen:
            continue
        seen.add(key)
        output.append({
            "preset_id": preset_id,
            "username": username,
            "password": password,
            "password_profile": password_profile(password),
        })
        if len(output) >= max_pairs:
            break
    return output


def password_profile(password: str) -> str:
    if password.isdigit():
        return f"numeric_len_{len(password)}"
    if password.isalpha():
        return f"alpha_len_{len(password)}"
    return f"mixed_len_{len(password)}"


def fetch_text(opener, url: str, timeout: int) -> tuple[dict, str]:
    started = time.time()
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/json,*/*"}, method="GET")
    status = 0
    final_url = url
    headers: dict[str, str] = {}
    body = b""
    error = ""
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.getcode() or 0)
            final_url = response.geturl()
            headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read(131072)
    except HTTPError as exc:
        status = int(exc.code or 0)
        final_url = exc.geturl() or url
        headers = {key.lower(): value for key, value in exc.headers.items()}
        body = exc.read(131072)
    except (URLError, TimeoutError, OSError, TypeError) as exc:
        error = str(exc)[:300]
    content_type = headers.get("content-type", "")
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type, re.I)
    if match:
        charset = match.group(1)
    text = body.decode(charset, errors="ignore")
    return {
        "status": status,
        "final_url": final_url,
        "content_type": content_type,
        "sample_length": len(body),
        "sample_sha256": hashlib.sha256(body).hexdigest() if body else "",
        "set_cookie_present": "set-cookie" in headers,
        "elapsed_seconds": round(time.time() - started, 3),
        "error": error,
    }, text


def fetch_text_simple(url: str, timeout: int) -> tuple[dict, str, CookieJar]:
    jar = CookieJar()
    opener = build_review_opener(jar)
    meta, text = fetch_text(opener, url, timeout)
    return meta, text, jar


def parse_login_form(page_url: str, html_text: str) -> tuple[LoginForm | None, str]:
    parser = LoginFormParser()
    parser.feed(html_text)
    for form in parser.forms:
        password_inputs = [field for field in form.inputs if field.field_type == "password" or PASSWORD_RE.search(field.name)]
        username_inputs = [
            field for field in form.inputs
            if field.name and field.field_type not in {"hidden", "password", "submit", "button"} and USERNAME_RE.search(field.name)
        ]
        if password_inputs and username_inputs:
            if form.method.lower() != "post":
                return None, "login_form_not_post"
            form.action = urljoin(page_url, form.action or page_url)
            return form, ""
    return None, "no_supported_login_form"


def form_payload(form: LoginForm, username: str, password: str) -> bytes:
    values: list[tuple[str, str]] = []
    username_filled = False
    password_filled = False
    for field in form.inputs:
        if not field.name:
            continue
        value = field.value
        if not username_filled and field.field_type != "hidden" and USERNAME_RE.search(field.name):
            value = username
            username_filled = True
        elif not password_filled and (field.field_type == "password" or PASSWORD_RE.search(field.name)):
            value = password
            password_filled = True
        values.append((field.name, value))
    return urlencode(values).encode("utf-8")


def submit_login_form(opener, form: LoginForm, pair: dict, timeout: int) -> tuple[dict, str]:
    payload = form_payload(form, str(pair["username"]), str(pair["password"]))
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json,*/*",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    request = Request(form.action, data=payload, headers=headers, method="POST")
    started = time.time()
    status = 0
    final_url = form.action
    response_headers: dict[str, str] = {}
    body = b""
    error = ""
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.getcode() or 0)
            final_url = response.geturl()
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read(131072)
    except HTTPError as exc:
        status = int(exc.code or 0)
        final_url = exc.geturl() or form.action
        response_headers = {key.lower(): value for key, value in exc.headers.items()}
        body = exc.read(131072)
    except (URLError, TimeoutError, OSError, TypeError) as exc:
        error = str(exc)[:300]
    content_type = response_headers.get("content-type", "")
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type, re.I)
    if match:
        charset = match.group(1)
    text = body.decode(charset, errors="ignore")
    return {
        "status": status,
        "final_url": final_url,
        "content_type": content_type,
        "sample_length": len(body),
        "sample_sha256": hashlib.sha256(body).hexdigest() if body else "",
        "set_cookie_present": "set-cookie" in response_headers,
        "elapsed_seconds": round(time.time() - started, 3),
        "error": error,
    }, text


def appears_success(meta: dict, text: str, login_url: str) -> tuple[bool, str]:
    lower = text[:120000].lower()
    if meta.get("error"):
        return False, "request_error"
    if CAPTCHA_OR_LOCK_RE.search(lower):
        return False, "captcha_or_lockout_signal"
    if LOGIN_FAIL_RE.search(lower):
        return False, "login_failure_text"
    if int(meta.get("status") or 0) in (200, 201) and extract_transient_auth_headers(text, str(meta.get("content_type") or ""))[1]:
        return True, "json_token_in_login_response"
    final_path = urlparse(str(meta.get("final_url") or "")).path.lower()
    login_path = urlparse(login_url).path.lower()
    has_password = "type=\"password\"" in lower or "type='password'" in lower
    if final_path and final_path != login_path and not LOGIN_HINT_RE.search(final_path) and not has_password:
        return True, "redirected_away_from_login_without_password_form"
    if meta.get("set_cookie_present") and LOGIN_SUCCESS_RE.search(lower) and not has_password:
        return True, "success_keyword_and_cookie"
    return False, "not_enough_success_evidence"


def candidate_entry_urls(candidate: dict) -> list[str]:
    urls: list[str] = []
    for value in split_cell(candidate.get("evidence")):
        if value.startswith(("http://", "https://")):
            urls.append(value)
    base = str(candidate.get("base_url") or "").rstrip("/")
    if base:
        urls.extend([base, urljoin(base + "/", "login")])
    output: list[str] = []
    seen: set[str] = set()
    for url in urls:
        if url not in seen and host_of(url) == host_of(base):
            seen.add(url)
            output.append(url)
    return output[:3]


def review_candidate(
    run_dir: Path,
    candidate: dict,
    max_pairs: int,
    delay: float,
    timeout: int,
    auto_sessions: list[dict] | None = None,
) -> dict:
    base_url = str(candidate.get("base_url") or "")
    skips_path = run_dir / "weak_credential_skips.jsonl"
    attempts_path = run_dir / "weak_credential_attempts.jsonl"
    successes_path = run_dir / "weak_credential_successes.jsonl"
    pairs = credential_pairs_for_candidate(candidate, max_pairs)

    for entry_url in candidate_entry_urls(candidate):
        page_meta, page_text, jar = fetch_text_simple(entry_url, timeout)
        if page_meta.get("error"):
            append_jsonl(skips_path, {"checked_at": now_iso(), "base_url": base_url, "entry_url": entry_url, "reason": "entry_fetch_error", "error": page_meta.get("error")})
            continue
        if CAPTCHA_OR_LOCK_RE.search(page_text[:120000]):
            append_jsonl(skips_path, {"checked_at": now_iso(), "base_url": base_url, "entry_url": entry_url, "reason": "captcha_or_lockout_signal"})
            return {"base_url": base_url, "status": "skipped", "reason": "captcha_or_lockout_signal"}
        form, reason = parse_login_form(str(page_meta.get("final_url") or entry_url), page_text)
        if form is None:
            append_jsonl(skips_path, {"checked_at": now_iso(), "base_url": base_url, "entry_url": entry_url, "reason": reason})
            continue

        opener = build_review_opener(jar)
        for index, pair in enumerate(pairs, 1):
            meta, text = submit_login_form(opener, form, pair, timeout)
            ok, evidence = appears_success(meta, text, form.action)
            attempt_record = {
                "checked_at": now_iso(),
                "base_url": base_url,
                "login_url": form.action,
                "attempt_index": index,
                "username": pair["username"],
                "password_profile": pair["password_profile"],
                "preset_id": pair["preset_id"],
                "weak_candidate_score": candidate.get("weak_candidate_score"),
                "weak_candidate_reasons": candidate.get("weak_candidate_reasons", []),
                "status": meta.get("status"),
                "final_url": meta.get("final_url"),
                "content_type": meta.get("content_type"),
                "sample_length": meta.get("sample_length"),
                "sample_sha256": meta.get("sample_sha256"),
                "set_cookie_present": meta.get("set_cookie_present"),
                "appears_success": ok,
                "evidence": evidence,
                "password_persisted": False,
                "cookie_persisted": False,
                "response_body_persisted": False,
                "error": meta.get("error", ""),
            }
            append_jsonl(attempts_path, attempt_record)
            if ok:
                transient_headers, token_keys = extract_transient_auth_headers(text, str(meta.get("content_type") or ""))
                transient_cookie = cookie_header_from_jar(jar)
                transient_session_ready = bool(transient_cookie or transient_headers)
                if auto_sessions is not None and transient_session_ready:
                    entry_url = str(meta.get("final_url") or form.action or base_url)
                    entry_path = urlparse(entry_url).path.lower()
                    if LOGIN_HINT_RE.search(entry_path):
                        entry_url = origin_of(base_url)
                    auto_sessions.append({
                        "base_url": origin_of(base_url),
                        "entry_url": entry_url,
                        "cookie": transient_cookie,
                        "headers": transient_headers,
                        "source": "weak_credential_success_transient",
                    })
                append_jsonl(successes_path, {
                    **attempt_record,
                    "transient_session_prepared": transient_session_ready,
                    "transient_cookie_available": bool(transient_cookie),
                    "transient_token_keys": token_keys,
                    "manual_next_step": "If auto-auth review was not requested or could not use this session, open in browser and capture minimal screenshot; do not export data. Paste session into auth_sessions.local.json only if authorized.",
                })
                return {
                    "base_url": base_url,
                    "status": "success",
                    "attempts": index,
                    "transient_session_prepared": transient_session_ready,
                    "transient_cookie_available": bool(transient_cookie),
                    "transient_token_keys": token_keys,
                }
            if evidence == "captcha_or_lockout_signal":
                return {"base_url": base_url, "status": "skipped", "reason": evidence, "attempts": index}
            time.sleep(delay)
        return {"base_url": base_url, "status": "completed_no_success", "attempts": len(pairs)}
    return {"base_url": base_url, "status": "skipped", "reason": "no_supported_entry"}


def run_review(
    run_dir: Path,
    max_targets: int,
    max_pairs: int,
    delay: float,
    timeout: int,
    force: bool,
    auto_auth_review: bool = False,
    auth_max_js: int = 20,
    auth_max_endpoints: int = 30,
) -> dict:
    for name in ("weak_credential_attempts.jsonl", "weak_credential_successes.jsonl", "weak_credential_skips.jsonl"):
        path = run_dir / name
        if force or not path.exists():
            path.write_text("", encoding="utf-8")
    candidates = build_candidates(run_dir, max_targets, force=force)
    outcomes = []
    auto_sessions: list[dict] = []
    for candidate in candidates:
        outcomes.append(review_candidate(
            run_dir,
            candidate,
            max_pairs,
            delay,
            timeout,
            auto_sessions=auto_sessions if auto_auth_review else None,
        ))
        time.sleep(delay)
    auto_auth_manifest: dict = {}
    if auto_auth_review and auto_sessions:
        try:
            auto_auth_manifest = run_authenticated_review_with_sessions(
                run_dir=run_dir,
                sessions=auto_sessions,
                delay=delay,
                timeout=timeout,
                max_js=auth_max_js,
                max_endpoints=auth_max_endpoints,
                reset_outputs=True,
                manifest_name="weak_auto_authenticated_review_manifest.json",
                session_source="weak_credential_success_transient",
            )
        except Exception as exc:  # noqa: BLE001
            auto_auth_manifest = {"error": str(exc)[:300]}
            append_jsonl(run_dir / "weak_auto_auth_errors.jsonl", {
                "checked_at": now_iso(),
                "error": str(exc)[:300],
            })
    manifest = {
        "created_at": now_iso(),
        "candidate_count": len(candidates),
        "candidate_filter_policy": "Prefer product/admin/default-credential login surfaces; down-rank SSO/CAPTCHA/lockout signals; explicit operator flag still required.",
        "max_targets": max_targets,
        "max_pairs_per_target": max_pairs,
        "delay": delay,
        "timeout": timeout,
        "explicit_operator_flag_required": True,
        "default_stage": False,
        "password_persisted": False,
        "cookie_persisted": False,
        "token_persisted": False,
        "response_body_persisted": False,
        "auto_auth_review_requested": bool(auto_auth_review),
        "auto_auth_transient_session_count": len(auto_sessions),
        "auto_auth_manifest": auto_auth_manifest,
        "auto_auth_cookie_persisted": False,
        "auto_auth_token_persisted": False,
        "outcomes": outcomes,
    }
    (run_dir / "weak_credential_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_local_session_template(run_dir)
    return manifest


def write_local_session_template(run_dir: Path) -> None:
    successes = read_jsonl(run_dir / "weak_credential_successes.jsonl")
    if not successes:
        return
    template = {
        "sessions": [
            {
                "base_url": origin_of(str(row.get("base_url") or "")),
                "entry_url": str(row.get("final_url") or row.get("base_url") or ""),
                "cookie": "<paste browser session cookie locally; weak review does not persist cookies>",
                "headers": {},
                "source": "weak_credential_success_manual_followup",
            }
            for row in successes
        ]
    }
    (run_dir / "weak_credential_success_sessions.local.template.json").write_text(
        json.dumps(template, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Explicit bounded weak-credential review")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--max-targets", type=int, default=10)
    parser.add_argument("--max-pairs", type=int, default=5)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--auto-auth-review", action="store_true", help="Use successful login response cookies/tokens in memory for bounded read-only authenticated review")
    parser.add_argument("--auth-max-js", type=int, default=20)
    parser.add_argument("--auth-max-endpoints", type=int, default=30)
    args = parser.parse_args()
    print(json.dumps(
        run_review(
            args.run_dir,
            args.max_targets,
            args.max_pairs,
            args.delay,
            args.timeout,
            args.force,
            auto_auth_review=args.auto_auth_review,
            auth_max_js=args.auth_max_js,
            auth_max_endpoints=args.auth_max_endpoints,
        ),
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
