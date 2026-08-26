#!/usr/bin/env python3
"""Audit a portable website-assessment workspace without network access."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any


os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


CORE_PHASES = {
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
}
VALID_PHASE_STATUSES = {"pending", "in_progress", "complete", "blocked", "not_applicable"}
OPEN_REVIEW_STATUSES = {"candidate", "needs_manual_validation"}
VALID_REVIEW_STATUSES = OPEN_REVIEW_STATUSES | {
    "approval_required",
    "confirmed",
    "rejected",
    "accepted_risk",
    "fixed",
    "retest_failed",
    "retest_passed",
}
RESOLVED_SCOPE_STATES = {"in_scope", "out_of_scope", "third_party", "platform_shared", "invalid"}
KNOWN_SCOPE_STATES = RESOLVED_SCOPE_STATES | {"confirmation_required"}


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def phase_map(root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    payload = read_json(root / "phase_status.json")
    rows = payload.get("phases", [])
    if not isinstance(rows, list):
        return {}, ["phase_status.json does not contain a phases list"]
    result: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not str(row.get("phase", "")).strip():
            errors.append("phase_status.json contains an invalid phase row")
            continue
        name = str(row["phase"]).strip()
        if name in seen:
            errors.append(f"duplicate phase: {name}")
        seen.add(name)
        status = str(row.get("status", "")).strip()
        if status not in VALID_PHASE_STATUSES:
            errors.append(f"{name}: invalid phase status {status!r}")
        if status in {"blocked", "not_applicable"} and not str(row.get("reason", "")).strip():
            errors.append(f"{name}: {status} requires a reason")
        result[name] = row
    return result, errors


def existing_evidence(root: Path, reference: str) -> bool:
    values = [item.strip() for item in reference.replace(";", "|").split("|") if item.strip()]
    if not values:
        return False
    for value in values:
        candidate = Path(value)
        path = candidate if candidate.is_absolute() else root / candidate
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError:
            return False
        if not path.is_file():
            return False
    return True


def audit(root: Path) -> dict[str, Any]:
    engagement = read_json(root / "engagement.json")
    if not engagement:
        return {"workspace": str(root), "state": "NO_INTAKE", "issues": ["engagement.json missing or invalid"]}

    issues: list[str] = []
    authorization = engagement.get("authorization", {})
    auth_status = authorization.get("status", "") if isinstance(authorization, dict) else ""
    auth_confirmed = (
        isinstance(authorization, dict)
        and authorization.get("status") == "confirmed"
        and bool(authorization.get("authorization_evidence_recorded"))
        and bool(authorization.get("active_testing_authorized"))
    )
    if not auth_confirmed:
        issues.append("active testing authorization is not explicitly confirmed")
    safety_controls = engagement.get("safety_controls", {})
    safety_controls_recorded = (
        isinstance(safety_controls, dict)
        and safety_controls.get("default_automation") == "read_only"
        and safety_controls.get("write_actions") == "operator_approval_required"
        and bool(str(safety_controls.get("rate_limit", "")).strip())
    )
    if not safety_controls_recorded:
        issues.append("safety controls missing read-only automation, write approval, or rate limit")
    scope = read_csv(root / "scope.csv")
    in_scope = [row for row in scope if row.get("scope_state", "").strip() == "in_scope"]
    unresolved_scope = [
        row.get("asset_id") or row.get("asset") or "<missing>"
        for row in scope
        if row.get("scope_state", "").strip() == "confirmation_required"
    ]
    invalid_scope = [
        row.get("asset_id") or row.get("asset") or "<missing>"
        for row in scope
        if row.get("scope_state", "").strip() not in KNOWN_SCOPE_STATES
    ]
    issues.extend(f"scope row has invalid state: {item}" for item in invalid_scope)
    issues.extend(f"scope row still needs confirmation: {item}" for item in unresolved_scope)
    phases, phase_errors = phase_map(root)
    issues.extend(phase_errors)

    required = {name: row for name, row in phases.items() if bool(row.get("required", True))}
    blocked = [name for name, row in required.items() if row.get("status") == "blocked"]
    incomplete_core = [
        name for name in CORE_PHASES
        if name not in required or required[name].get("status") not in {"complete", "not_applicable"}
    ]

    ledger = [row for row in read_csv(root / "review_ledger.csv") if row.get("active", "true").lower() != "false"]
    invalid_review = [row.get("item_id", "<missing>") for row in ledger if row.get("status") not in VALID_REVIEW_STATUSES]
    open_review = [row.get("item_id", "<missing>") for row in ledger if row.get("status") in OPEN_REVIEW_STATUSES]
    unreasoned_gates = [
        row.get("item_id", "<missing>") for row in ledger
        if row.get("status") == "approval_required" and not row.get("validation_result", "").strip()
    ]
    missing_evidence = [
        row.get("item_id", "<missing>") for row in ledger
        if row.get("status") in {"confirmed", "fixed", "retest_failed", "retest_passed"}
        and not existing_evidence(root, row.get("evidence_ref", ""))
    ]
    rejected_without_reason = [
        row.get("item_id", "<missing>") for row in ledger
        if row.get("status") == "rejected" and not (row.get("validation_result", "").strip() or row.get("notes", "").strip())
    ]
    issues.extend(f"invalid review status: {item}" for item in invalid_review)
    issues.extend(f"approval gate lacks exact requirement: {item}" for item in unreasoned_gates)
    issues.extend(f"rejected item lacks false-positive reason: {item}" for item in rejected_without_reason)

    def done(name: str) -> bool:
        row = required.get(name)
        return bool(row and row.get("status") in {"complete", "not_applicable"})

    report_files = {
        "primary_docx": [p for p in (root / "reports").glob("*.docx") if p.is_file() and p.stat().st_size > 0],
        "findings_json": root / "reports" / "findings.json",
        "meta_json": root / "reports" / "meta.json",
        "evidence_index": root / "evidence" / "index.csv",
    }
    report_complete = bool(report_files["primary_docx"] and report_files["findings_json"].is_file()
                           and report_files["findings_json"].stat().st_size > 0
                           and report_files["meta_json"].is_file()
                           and report_files["meta_json"].stat().st_size > 0
                           and report_files["evidence_index"].is_file())
    report_exists = report_complete
    if not report_complete:
        issues.append("final DOCX, findings.json, meta.json, and evidence/index.csv are required")
    if not auth_confirmed:
        state = "AUTHORIZATION_PENDING"
    elif not in_scope or unresolved_scope or invalid_scope:
        state = "SCOPE_PENDING"
    elif not safety_controls_recorded:
        state = "SAFETY_CONTROLS_PENDING"
    elif blocked:
        state = "BLOCKED"
    elif incomplete_core or phase_errors:
        state = "EXECUTION_INCOMPLETE"
    elif invalid_review or open_review or unreasoned_gates or not done("candidate_validation"):
        state = "REVIEW_PENDING"
    elif missing_evidence or not done("evidence"):
        state = "EVIDENCE_PENDING"
    elif not done("cleanup"):
        state = "CLEANUP_PENDING"
    elif not done("retest"):
        state = "RETEST_PENDING"
    elif not done("reporting") or not report_exists:
        state = "REPORT_PENDING"
    else:
        state = "CLOSED"

    return {
        "workspace": str(root),
        "state": state,
        "target": engagement.get("target", {}).get("canonical_url"),
        "authorization_confirmed": auth_confirmed,
        "safety_controls_recorded": safety_controls_recorded,
        "scope_records": len(scope),
        "in_scope_records": len(in_scope),
        "unresolved_scope_records": unresolved_scope,
        "invalid_scope_records": invalid_scope,
        "phase_counts": _counts([str(row.get("status", "")) for row in required.values()]),
        "blocked_phases": blocked,
        "incomplete_core_phases": incomplete_core,
        "review_counts": _counts([row.get("status", "") for row in ledger]),
        "open_review_items": open_review,
        "missing_evidence_items": missing_evidence,
        "report_exists": report_exists,
        "issues": issues,
    }


def _counts(values: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        result[value] = result.get(value, 0) + 1
    return dict(sorted(result.items()))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit a website assessment workspace.")
    parser.add_argument("workspace", help="Engagement workspace directory.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.workspace).resolve()
    if not root.is_dir():
        print(f"ERROR: Workspace does not exist: {root}", file=sys.stderr)
        return 2
    result = audit(root)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"state={result['state']}")
        print(f"workspace={result['workspace']}")
        for item in result.get("issues", []):
            print(f"issue={item}")
    return 0 if result["state"] == "CLOSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
