#!/usr/bin/env python3
"""Audit a portable mini-program assessment workspace without network access."""

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
    "authorization", "identity", "platform_identification", "material_acquisition",
    "initial_decoding", "preflight",
    "package_inventory", "package_unpack_decompile", "source_reconstruction", "static_analysis",
    "endpoint_inventory", "host_classification", "dynamic_setup",
    "dynamic_mapping", "authentication_session", "backend_web_api_testing",
    "access_control_testing", "input_file_testing", "business_logic_testing",
    "client_storage_crypto", "webview_bridge_links", "plugins_cloud_third_party",
}
ANALYZABLE_MATERIALS = {"package", "package_cache", "unpacked_source", "traffic_export"}
PACKAGE_MATERIALS = {"package", "package_cache"}
VALID_PHASE_STATUSES = {"pending", "in_progress", "complete", "blocked", "not_applicable"}
OPEN_REVIEW_STATUSES = {"candidate", "needs_manual_validation"}
VALID_REVIEW_STATUSES = OPEN_REVIEW_STATUSES | {
    "approval_required", "confirmed", "rejected", "accepted_risk", "fixed",
    "retest_failed", "retest_passed",
}
RESOLVED_HOST_STATES = {"in_scope", "third_party", "platform", "out_of_scope", "invalid"}


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
    for row in rows:
        if not isinstance(row, dict) or not str(row.get("phase", "")).strip():
            errors.append("phase_status.json contains an invalid phase row")
            continue
        name = str(row["phase"]).strip()
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
    miniapp = read_json(root / "miniapp.json")
    if not engagement:
        return {"workspace": str(root), "state": "NO_INTAKE", "issues": ["engagement.json missing or invalid"]}

    issues: list[str] = []
    authorization = engagement.get("authorization", {})
    auth_status = authorization.get("status", "") if isinstance(authorization, dict) else ""
    initial_target_recorded = bool(engagement.get("input_sha256"))
    auth_confirmed = auth_status == "confirmed" or initial_target_recorded
    safety_controls = engagement.get("safety_controls", {})
    safety_controls_recorded = (
        isinstance(safety_controls, dict)
        and safety_controls.get("default_automation") == "read_only"
        and safety_controls.get("write_actions") == "operator_approval_required"
        and bool(str(safety_controls.get("rate_limit", "")).strip())
    )
    if not safety_controls_recorded:
        issues.append("safety controls missing read-only automation, write approval, or rate limit")
    identity_confirmed = miniapp.get("identity_status") == "confirmed"
    platform = str(miniapp.get("platform", "")).strip()
    platform_known = bool(platform)

    materials = [row for row in read_csv(root / "materials.csv") if row.get("active", "true").lower() != "false"]
    analyzable = [row for row in materials if row.get("material_type") in ANALYZABLE_MATERIALS]
    package_materials = [row for row in materials if row.get("material_type") in PACKAGE_MATERIALS]
    package_inventory = read_csv(root / "artifacts" / "package-inventory.csv")
    source_map = read_csv(root / "artifacts" / "source-map.csv")
    pending_materials = [row.get("material_id", "<missing>") for row in analyzable if row.get("analysis_status") == "pending"]
    invalid_materials = [
        row.get("material_id", "<missing>") for row in materials
        if row.get("analysis_status") not in {"pending", "analyzed", "failed", "superseded", "not_applicable"}
    ]
    failed_without_reason = [
        row.get("material_id", "<missing>") for row in materials
        if row.get("analysis_status") == "failed" and not row.get("notes", "").strip()
    ]

    hosts = [row for row in read_csv(root / "hosts.csv") if row.get("active", "true").lower() != "false"]
    unresolved_hosts = [
        row.get("host_id", row.get("host", "<missing>")) for row in hosts
        if row.get("scope_state") not in RESOLVED_HOST_STATES
    ]
    in_scope_hosts = [row for row in hosts if row.get("scope_state") == "in_scope"]

    phases, phase_errors = phase_map(root)
    issues.extend(phase_errors)
    required = {name: row for name, row in phases.items() if bool(row.get("required", True))}
    blocked = [name for name, row in required.items() if row.get("status") == "blocked"]
    package_phase_names = ("package_inventory", "package_unpack_decompile", "source_reconstruction")
    package_phase_blocked = [
        name for name in package_phase_names
        if package_materials and required.get(name, {}).get("status") == "blocked"
    ]
    package_phase_incomplete = [
        name for name in package_phase_names
        if package_materials and required.get(name, {}).get("status") != "complete"
    ]
    package_phase_invalid_na = [
        name for name in package_phase_names
        if package_materials and required.get(name, {}).get("status") == "not_applicable"
    ]
    if package_phase_invalid_na:
        issues.extend(f"package material makes phase applicable: {name}" for name in package_phase_invalid_na)
    package_material_ids = {row.get("material_id", "") for row in package_materials if row.get("material_id", "")}
    inventoried_material_ids = {row.get("material_id", "") for row in package_inventory if row.get("material_id", "")}
    source_mapped_material_ids = {row.get("material_id", "") for row in source_map if row.get("material_id", "")}
    missing_package_inventory = sorted(package_material_ids - inventoried_material_ids)
    missing_source_map = sorted(package_material_ids - source_mapped_material_ids)
    unfinished_package_records = [
        row.get("package_id", "<missing>") for row in package_inventory
        if row.get("material_id") in package_material_ids
        and row.get("extraction_status") not in {"extracted", "partial", "failed", "unsupported"}
    ]
    failed_package_records = [
        row.get("package_id", "<missing>") for row in package_inventory
        if row.get("material_id") in package_material_ids
        and row.get("extraction_status") in {"failed", "unsupported"}
    ]
    if missing_package_inventory:
        issues.extend(f"package material lacks inventory: {item}" for item in missing_package_inventory)
    if missing_source_map:
        issues.extend(f"package material lacks source-map record: {item}" for item in missing_source_map)
    if unfinished_package_records:
        issues.extend(f"package extraction lacks terminal status: {item}" for item in unfinished_package_records)
    if failed_package_records:
        issues.extend(f"package extraction remains blocked: {item}" for item in failed_package_records)
        package_phase_blocked = sorted(set(package_phase_blocked) | {"package_unpack_decompile"})
    if missing_package_inventory or missing_source_map or unfinished_package_records:
        package_phase_incomplete = sorted(
            set(package_phase_incomplete) | {"package_inventory", "package_unpack_decompile", "source_reconstruction"}
        )
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
    issues.extend(f"invalid material status: {item}" for item in invalid_materials)
    issues.extend(f"failed material lacks reason: {item}" for item in failed_without_reason)
    issues.extend(f"invalid review status: {item}" for item in invalid_review)
    issues.extend(f"approval gate lacks exact requirement: {item}" for item in unreasoned_gates)

    def done(name: str) -> bool:
        row = required.get(name)
        return bool(row and row.get("status") in {"complete", "not_applicable"})

    report_exists = (root / "reports" / "final-report.md").is_file()
    if not auth_confirmed:
        state = "AUTHORIZATION_PENDING"
    elif not safety_controls_recorded:
        state = "SAFETY_CONTROLS_PENDING"
    elif not identity_confirmed or not platform_known:
        state = "IDENTITY_PENDING"
    elif package_phase_blocked:
        state = "BLOCKED"
    elif package_phase_incomplete:
        state = "PACKAGE_ANALYSIS_PENDING"
    elif not analyzable:
        state = "MATERIAL_PENDING"
    elif pending_materials or invalid_materials or failed_without_reason:
        state = "MATERIAL_ANALYSIS_PENDING"
    elif unresolved_hosts:
        state = "HOST_CLASSIFICATION_PENDING"
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
        "platform": platform or None,
        "name": miniapp.get("name") or None,
        "identifier": miniapp.get("identifier") or None,
        "authorization_confirmed": auth_confirmed,
        "safety_controls_recorded": safety_controls_recorded,
        "identity_confirmed": identity_confirmed,
        "material_counts": _counts([row.get("analysis_status", "") for row in materials]),
        "package_materials": len(package_materials),
        "package_inventory_records": len(package_inventory),
        "source_map_records": len(source_map),
        "package_phase_incomplete": package_phase_incomplete,
        "host_counts": _counts([row.get("scope_state", "") for row in hosts]),
        "in_scope_hosts": len(in_scope_hosts),
        "unresolved_hosts": unresolved_hosts,
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
    parser = argparse.ArgumentParser(description="Audit a mini-program assessment workspace.")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
