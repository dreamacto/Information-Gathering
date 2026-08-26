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


def _registered_parent(host: str) -> str:
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    suffix2 = ".".join(parts[-2:])
    if suffix2 in {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn"} and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix2


def find_same_asset_engagements(output_root: Path, host: str) -> list[Path]:
    """同资产工作区发现（2026-08-23）：扫同级 engagements/*/ 的 scope.csv，
    找已登记覆盖本 host 或其注册父域的工作区——保证'同资产不同网站'续用同一工作区，
    昨天的台账/target-model 不丢。"""
    parent = _registered_parent(host)
    hits: list[Path] = []
    base = output_root.parent
    if not base.is_dir():
        return hits
    for sibling in sorted(base.iterdir()):
        scope = sibling / "scope.csv"
        if sibling == output_root or not scope.is_file():
            continue
        try:
            with scope.open(encoding="utf-8-sig", newline="") as f:
                for row in csv.DictReader(f):
                    asset = (row.get("asset") or "").strip().lower().lstrip("*.")
                    if not asset:
                        continue
                    if host == asset or host.endswith("." + asset) or asset == parent or asset.endswith("." + parent):
                        if sibling not in hits:
                            hits.append(sibling)
                        break
        except OSError:
            continue
    return hits


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
    parser.add_argument("--allow-parallel", action="store_true", help="明确允许为同资产另建平行工作区（默认禁止）")
    parser.add_argument("--add-site", dest="add_site", action="store_true", default=None, help="resume 时允许把同父域的新 host 扩展进本工作区（默认允许，需父域已登记域级授权）")
    parser.add_argument("--no-add-site", dest="add_site", action="store_false", help="resume 拒绝站点扩展")
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

    # 同资产发现（2026-08-23）：新建前先找同资产既有工作区
    site_extension = False
    if not args.resume:
        prior = find_same_asset_engagements(root, str(target["host"]))
        if prior and not getattr(args, "allow_parallel", False):
            print("ERROR: 同一资产已有工作区，禁止平行新建（会丢失既有台账/target-model）：", file=sys.stderr)
            for p in prior:
                print(f"  -> {p}", file=sys.stderr)
            print(f"改用：--resume {prior[0]} --add-site {target['host']}（站点扩展，该站独立 L 编号）；"
                  f"确需平行工作区加 --allow-parallel", file=sys.stderr)
            return 4
    if args.resume and engagement_path.is_file():
        existing = json.loads(engagement_path.read_text(encoding="utf-8-sig"))
        existing_host = str(existing.get("target", {}).get("host") or "")
        if existing_host != target["host"]:
            parent_new = _registered_parent(str(target["host"]))
            parent_old = _registered_parent(existing_host)
            if parent_new == parent_old and (args.add_site or args.add_site is None):
                # 同资产站点扩展：要求父域已在 scope 里登记（域级授权），随后追加该 host
                covered = False
                scope_csv = root / "scope.csv"
                if scope_csv.is_file():
                    with scope_csv.open(encoding="utf-8-sig", newline="") as f:
                        for row in csv.DictReader(f):
                            asset = (row.get("asset") or "").strip().lower().lstrip("*.")
                            rationale = " ".join(str(row.get(k, "")) for k in ("source", "notes", "ownership_rationale")).lower()
                            if asset == parent_new or asset == str(target["host"]):
                                covered = True
                                break
                            # 域级授权登记形态：wildcard source/notes 或 *.父域 字样
                            if ("wildcard" in rationale or "整域" in rationale or "*." + parent_new in rationale) and asset.endswith("." + parent_new):
                                covered = True
                                break
                if not covered:
                    print(f"ERROR: {target['host']} 属于本工作区的 {parent_new}，但父域未在 scope.csv "
                          f"登记域级授权；先补登（操作者确认）或用 --no-add-site 明确拒绝扩展。", file=sys.stderr)
                    return 3
                site_extension = True
                print(f"[*] 同资产站点扩展：{existing_host} -> 追加 {target['host']}（{parent_new} 域级授权已登记）")
            else:
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
    authorization_confirmed = False
    if not engagement_path.exists():
        engagement = {
            "workspace_version": 1,
            "engagement_name": args.name.strip() or str(target["host"]),
            "created_at": created,
            "target_input_sha256": hashlib.sha256(args.target.encode("utf-8")).hexdigest(),
            "target": target,
            "authorization": {
                "status": "target_received",
                "reference": authorization_ref,
                "basis": "user_supplied_initial_target",
                "target_received": True,
                "initial_target_recorded": True,
                "authorization_evidence_recorded": bool(args.authorization_ref.strip()),
                "active_testing_authorized": False,
                "high_risk_action_approved": False,
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
                "scope_state": "confirmation_required",
                "source": "initial_target" if host == target["host"] else "operator_supplied",
                "ownership_rationale": authorization_ref,
                "permitted_actions": "none",
                "confirmed_at": "",
                "notes": "",
            }
        )
    write_csv_if_missing(root / "scope.csv", SCOPE_FIELDS, scope_rows)
    if site_extension:
        existing_assets = set()
        with (root / "scope.csv").open(encoding="utf-8-sig", newline="") as f:
            existing_assets = {(r.get("asset") or "").strip().lower() for r in csv.DictReader(f)}
        new_rows = []
        for row in scope_rows:
            if (row.get("asset") or "").lower() not in existing_assets:
                row["source"] = "same_asset_site_extension"
                row["ownership_rationale"] = f"同资产站点扩展：{existing_host} 工作区父域 {parent_new} 已登记域级授权"
                row["notes"] = f"站点扩展：同资产工作区追加，本站独立编号"
                new_rows.append(row)
        if new_rows:
            with (root / "scope.csv").open("a", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=SCOPE_FIELDS, extrasaction="ignore")
                w.writerows(new_rows)
            print(f"[*] scope.csv 追加 {len(new_rows)} 行（source=same_asset_site_extension）")

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
            json.dumps({
                "schema_version": "1.0",
                "current_phase": "authorization",
                "next_phase": "scope",
                "last_completed_phase": "",
                "updated_at": created,
                "phases": phases,
            }, ensure_ascii=False, indent=2) + "\n",
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
    write_text_if_missing(root / "notes" / "target-model.md", "# Target model\n\n## Host map\n\n## Technology stack\n\n## Entrypoints\n\n## Authentication topology\n\n## Attack-surface decisions\n\n## Excluded and untested areas\n")
    write_text_if_missing(root / "notes" / "operator_tasks.md", "# Operator tasks\n\n- [ ] Confirm authorization evidence, testing window, and scope before active testing.\n")
    write_text_if_missing(root / "notes" / "tool-inventory.md", "# Tool inventory\n")
    write_text_if_missing(root / "notes" / "coverage.md", "# Coverage\n")
    (root / "notes" / "phase-history").mkdir(parents=True, exist_ok=True)
    write_text_if_missing(
        root / "notes" / "safety-controls.md",
        "# Safety controls\n\n"
        "- Default automation: read-only\n"
        "- Write or state-changing actions: operator approval required before execution\n"
        f"- Rate profile: {args.rate.strip() or 'low_rate_no_disruption_required'}\n"
        "- Stop policy: stop on service degradation, error spikes, or normal-user impact risk\n",
    )
    write_text_if_missing(
        root / "reports" / "final-report.md",
        "# Final report\n\n"
        "## Executive summary\n\n"
        "## Authorization, scope, and rules\n\n"
        "## Methodology and coverage\n\n"
        "## Confirmed findings\n\n"
        "## Rejected candidates and false positives\n\n"
        "## Blocked, approval-gated, and not-applicable areas\n\n"
        "## Cleanup, retest, and residual risk\n\n"
        "## Evidence index\n\n",
    )
    write_text_if_missing(root / "reports" / ".gitkeep", "")
    print(f"workspace={root}")
    print(f"target={target['canonical_url']}")
    print("authorization=target_received (active testing not authorized)")
    return 0


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
