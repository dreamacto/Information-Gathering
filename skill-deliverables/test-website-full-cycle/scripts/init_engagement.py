#!/usr/bin/env python3
"""Create or resume a portable website-assessment workspace without network access."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


PHASES = (
    "authorization",
    "scope",
    "preflight",
    "passive_discovery",
    "active_discovery",
    "application_mapping",
    "unauthenticated_testing",
    "authenticated_testing",
    "api_testing",
    "authorization_testing",
    "input_testing",
    "business_logic_testing",
    "client_side_testing",
    "infrastructure_testing",
    "candidate_validation",
    "evidence",
    "cleanup",
    "retest",
    "reporting",
)

SCOPE_FIELDS = (
    "asset_id",
    "asset",
    "asset_type",
    "scope_state",
    "source",
    "ownership_rationale",
    "permitted_actions",
    "confirmed_at",
    "notes",
)

LEDGER_FIELDS = (
    "item_id",
    "active",
    "priority",
    "category",
    "asset",
    "endpoint",
    "parameter",
    "role",
    "candidate_type",
    "status",
    "confidence",
    "summary",
    "source",
    "validation_plan",
    "validation_result",
    "evidence_ref",
    "finding_id",
    "owner",
    "updated_at",
)


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def normalize_host(host: str) -> str:
    value = host.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Host IDNA conversion failed.") from exc
    if len(ascii_host) > 253 or "." not in ascii_host:
        raise ValueError("Target must contain a valid domain or IP host.")
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_re.fullmatch(label) for label in ascii_host.split(".")):
        raise ValueError("Target host contains an invalid label.")
    return ascii_host


def normalize_target(raw: str) -> dict[str, object]:
    value = raw.strip()
    if not value or any(char.isspace() for char in value):
        raise ValueError("Target is empty or contains whitespace.")
    candidate = value if "://" in value else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid target: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS website targets are accepted.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials are not allowed in the target URL.")
    if parsed.query or parsed.fragment:
        raise ValueError("Put query strings and fragments in the endpoint inventory, not the target.")
    host = normalize_host(parsed.hostname or "")
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    netloc = host if port in (None, default_port) else f"{host}:{port}"
    canonical = urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
    return {
        "canonical_url": canonical,
        "scheme": parsed.scheme.lower(),
        "host": host,
        "port": port or default_port,
        "base_path": path,
    }


def write_csv_if_missing(path: Path, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_text_if_missing(path: Path, content: str) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize a website assessment workspace.")
    parser.add_argument("target", help="Authorized website URL, domain, or IP host.")
    parser.add_argument("--output", required=True, help="Engagement workspace directory.")
    parser.add_argument("--name", default="", help="Optional engagement name.")
    parser.add_argument(
        "--authorization-ref",
        default="",
        help="Optional authorization evidence note; user-supplied target is accepted by default.",
    )
    parser.add_argument("--allowed-host", action="append", default=[], help="Additional confirmed host.")
    parser.add_argument("--window", default="", help="Authorized testing window.")
    parser.add_argument("--rules", default="", help="Rules-of-engagement reference.")
    parser.add_argument("--rate", default="", help="Approved request-rate note.")
    parser.add_argument("--resume", action="store_true", help="Resume the same workspace.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        target = normalize_target(args.target)
        extra_hosts = [normalize_host(value.strip()) for value in args.allowed_host]
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    root = Path(args.output).resolve()
    engagement_path = root / "engagement.json"
    if root.exists() and not args.resume:
        print(f"ERROR: Output already exists; use --resume for the same engagement: {root}", file=sys.stderr)
        return 3
    if args.resume and engagement_path.is_file():
        existing = json.loads(engagement_path.read_text(encoding="utf-8-sig"))
        if existing.get("target", {}).get("host") != target["host"]:
            print("ERROR: Resume target does not match the existing engagement.", file=sys.stderr)
            return 3

    for relative in (
        "artifacts",
        "evidence/raw",
        "evidence/redacted",
        "logs",
        "notes",
        "reports",
        "sessions",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)

    created = now()
    authorization_ref = args.authorization_ref.strip() or "user_supplied_initial_target"
    authorization_confirmed = True
    if not engagement_path.exists():
        engagement = {
            "workspace_version": 1,
            "engagement_name": args.name.strip() or str(target["host"]),
            "created_at": created,
            "target_input_sha256": hashlib.sha256(args.target.encode("utf-8")).hexdigest(),
            "target": target,
            "authorization": {
                "status": "confirmed",
                "reference": authorization_ref,
                "basis": "user_supplied_initial_target",
                "window": args.window.strip(),
                "rules_reference": args.rules.strip(),
                "rate_note": args.rate.strip(),
            },
            "safety_controls": {
                "default_automation": "read_only",
                "write_actions": "operator_approval_required",
                "rate_limit": args.rate.strip() or "low_rate_no_disruption_required",
                "service_impact_policy": "stop_on_degradation",
            },
            "network_accessed_by_initializer": False,
        }
        engagement_path.write_text(
            json.dumps(engagement, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    hosts = list(dict.fromkeys([str(target["host"]), *extra_hosts]))
    scope_rows = []
    for host in hosts:
        asset_type = "ip" if _is_ip(host) else "host"
        scope_rows.append(
            {
                "asset_id": hashlib.sha256(host.encode("utf-8")).hexdigest()[:16],
                "asset": host,
                "asset_type": asset_type,
                "scope_state": "in_scope" if authorization_confirmed else "confirmation_required",
                "source": "initial_target" if host == target["host"] else "operator_supplied",
                "ownership_rationale": authorization_ref,
                "permitted_actions": "per rules of engagement" if authorization_confirmed else "none",
                "confirmed_at": created if authorization_confirmed else "",
                "notes": "",
            }
        )
    write_csv_if_missing(root / "scope.csv", SCOPE_FIELDS, scope_rows)

    phase_path = root / "phase_status.json"
    if not phase_path.exists():
        phases = []
        for phase in PHASES:
            status = "complete" if phase == "authorization" and authorization_confirmed else "pending"
            phases.append(
                {
                    "phase": phase,
                    "required": True,
                    "status": status,
                    "reason": authorization_ref if status == "complete" else "",
                    "artifacts": ["engagement.json"] if status == "complete" else [],
                    "updated_at": created if status == "complete" else "",
                }
            )
        phase_path.write_text(
            json.dumps({"phases": phases}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    write_csv_if_missing(root / "review_ledger.csv", LEDGER_FIELDS, [])
    write_csv_if_missing(
        root / "artifacts" / "endpoint-inventory.csv",
        (
            "endpoint_id", "host", "method", "path", "parameters", "content_type",
            "auth_required", "roles", "state_changing", "source", "test_status", "notes",
        ),
        [],
    )
    write_csv_if_missing(
        root / "evidence" / "index.csv",
        (
            "evidence_id", "finding_id", "captured_at", "sha256", "sensitivity",
            "raw_path", "redacted_path", "retention", "notes",
        ),
        [],
    )
    write_text_if_missing(root / "notes" / "tool-inventory.md", "# Tool inventory\n")
    write_text_if_missing(root / "notes" / "coverage.md", "# Coverage\n")
    write_text_if_missing(
        root / "notes" / "safety-controls.md",
        "# Safety controls\n\n"
        "- Default automation: read-only\n"
        "- Write or state-changing actions: operator approval required before execution\n"
        f"- Rate profile: {args.rate.strip() or 'low_rate_no_disruption_required'}\n"
        "- Stop policy: stop on service degradation, error spikes, or normal-user impact risk\n",
    )
    write_text_if_missing(root / "reports" / ".gitkeep", "")
    print(f"workspace={root}")
    print(f"target={target['canonical_url']}")
    print("authorization=confirmed")
    return 0


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
