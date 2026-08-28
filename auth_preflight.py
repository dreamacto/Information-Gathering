"""Offline normalization for authentication material obtained from local Burp MCP history.

This module never connects to Burp or the target and never persists credential values.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit


AUTH_HEADER_NAMES = {"authorization", "cookie", "proxy-authorization"}
_SECRET_RE = re.compile(r"(?i)(bearer\s+|session=|token=|password=)[^\s;,]+")


def _host_key(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(str(url or ""))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        return parsed.scheme.lower(), parsed.hostname.rstrip(".").lower(), port
    except ValueError:
        return None


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _header_map(item: dict) -> dict[str, str]:
    headers = item.get("headers") or item.get("requestHeaders") or {}
    if isinstance(headers, list):
        headers = {str(x.get("name", "")): str(x.get("value", "")) for x in headers if isinstance(x, dict)}
    if not isinstance(headers, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def build_preflight(history: list[dict], target_url: str, *, source: str = "burp_local_history") -> tuple[dict, dict[str, str] | None]:
    target = _host_key(target_url)
    base = {
        "schema_version": "1.0", "source": source,
        "target_host": target[1] if target else "", "status": "pending",
        "request_count": 0, "selected_at": "",
        "credential_fields": [], "credential_value_hashes": [],
        "credential_values_persisted": False, "raw_history_persisted": False,
    }
    if not target or not isinstance(history, list):
        base["status"] = "host_mismatch" if target is None else "not_found"
        return base, None
    candidates: list[tuple[dict, dict[str, str]]] = []
    for item in history:
        if not isinstance(item, dict):
            continue
        url = item.get("url") or item.get("requestUrl") or item.get("request_url")
        if _host_key(str(url)) != target:
            continue
        headers = _header_map(item)
        auth = {key: value for key, value in headers.items() if key in AUTH_HEADER_NAMES and value}
        if auth:
            candidates.append((item, auth))
    if not candidates:
        base["status"] = "not_found"
        return base, None
    item, auth = candidates[-1]
    base.update({
        "status": "found", "request_count": len(candidates),
        "selected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "credential_fields": sorted(auth),
        "credential_value_hashes": [{"field": k, "sha256": _hash_secret(v), "length": len(v)} for k, v in sorted(auth.items())],
    })
    return base, auth


def write_preflight(path: Path, status: dict) -> None:
    safe = dict(status)
    safe.pop("credential_values", None)
    safe["credential_values_persisted"] = False
    safe["raw_history_persisted"] = False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(safe, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def redact_text(value: object) -> str:
    return _SECRET_RE.sub(r"\1[REDACTED]", str(value or ""))[:500]
