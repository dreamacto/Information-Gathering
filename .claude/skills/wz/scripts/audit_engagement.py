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

# application_mapping 子阶段审计（实施规格 5.2 + 10.2/10.3；适用性优先）。
# 常量与 src/authorized_assessment/analysis/coverage_matrix.py 契约同源，漂移由
# tests/test_wz_application_mapping.py 锁定。
APPLICATION_MAP_PHASE = "application_mapping"
APPLICATION_MAP_SUBPHASES = (
    "graphql_mapping",
    "websocket_mapping",
    "file_surface_mapping",
    "auth_surface_mapping",
    "webhook_mapping",
)
APPLICATION_MAP_ROW_FIELDS = (
    "applicable",
    "status",
    "source",
    "asset",
    "endpoint_or_surface",
    "reason",
    "evidence_ref",
)
COVERAGE_SUBSTATUSES = {
    "tested",
    "not_applicable",
    "blocked",
    "approval_required",
    "needs_manual_validation",
    "inconclusive",
}
# phase 标记 complete/not_applicable 时，子状态只接受这两个"已落盘可证明"值。
PROVEN_SUBSTATUSES = {"tested", "not_applicable"}
APPLICATION_MAP_ARTIFACTS = {
    "graphql_mapping": "artifacts/application-map/graphql-manifest.json",
    "websocket_mapping": "artifacts/application-map/websocket-inventory.csv",
    "file_surface_mapping": "artifacts/application-map/file-surface-inventory.csv",
    "auth_surface_mapping": "artifacts/application-map/auth-surface-inventory.csv",
    "webhook_mapping": "artifacts/application-map/webhook-inventory.csv",
}


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


def _read_application_map_rows(root: Path, subphase: str) -> tuple[list[dict[str, str]], list[str]]:
    """读取子阶段产物行：JSON manifest 取 rows，CSV 逐行；返回 (rows, errors)。"""
    rel = APPLICATION_MAP_ARTIFACTS[subphase]
    path = root / rel
    if not path.is_file():
        return [], [f"{APPLICATION_MAP_PHASE}: artifact missing for {subphase}: {rel}"]
    if path.suffix == ".json":
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            return [], [f"{APPLICATION_MAP_PHASE}.{subphase}: unparseable manifest {rel}: {exc}"]
        if not isinstance(payload, dict) or not isinstance(payload.get("rows"), list):
            return [], [f"{APPLICATION_MAP_PHASE}.{subphase}: manifest must be an object with a rows list: {rel}"]
        return [row for row in payload["rows"] if isinstance(row, dict)], []
    errors: list[str] = []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        missing = [field for field in APPLICATION_MAP_ROW_FIELDS if field not in fieldnames]
        if missing:
            errors.append(
                f"{APPLICATION_MAP_PHASE}.{subphase}: {rel} header missing required fields: {missing}"
            )
            return [], errors
        return [dict(row) for row in reader], errors


def _application_map_row_issues(subphase: str, rows: list[dict[str, str]]) -> list[str]:
    """application-map 行契约校验（7 字段 + not_applicable/tested 行规则，实施规格 5.2/10.2/10.3）。"""
    issues: list[str] = []
    rel = APPLICATION_MAP_ARTIFACTS[subphase]
    for index, row in enumerate(rows):
        label = f"{APPLICATION_MAP_PHASE}.{subphase}[{index}] ({rel})"
        for field in APPLICATION_MAP_ROW_FIELDS:
            if field not in row:
                issues.append(f"{label}: missing application-map field {field}")
        applicable = str(row.get("applicable", "")).strip()
        status = str(row.get("status", "")).strip()
        if status and status not in COVERAGE_SUBSTATUSES:
            issues.append(f"{label}: invalid status {status!r}")
        if status == "not_applicable":
            if not str(row.get("reason", "")).strip():
                issues.append(f"{label}: not_applicable without reason (silent omission is forbidden)")
            if applicable != "not_applicable":
                issues.append(
                    f"{label}: status=not_applicable requires applicable=not_applicable "
                    "(no applicability decision, no not_applicable claim)"
                )
        if status == "tested" and not str(row.get("evidence_ref", "")).strip():
            issues.append(f"{label}: tested row lacks evidence_ref (completion must be provable)")
    return issues


def _substatus_proof_issues(root: Path, subphase: str, substatus: str) -> list[str]:
    """phase 完成时的可证明性：产物存在且 ≥1 行、≥1 行与子状态一致，tested 行证据可解析。"""
    rel = APPLICATION_MAP_ARTIFACTS[subphase]
    rows, errors = _read_application_map_rows(root, subphase)
    if errors:
        return errors
    issues = _application_map_row_issues(subphase, rows)
    if not rows:
        issues.append(
            f"{APPLICATION_MAP_PHASE}.{subphase}: {rel} has no rows; record the applicability "
            "decision instead of skipping silently"
        )
        return issues
    if not any(str(row.get("status", "")).strip() == substatus for row in rows):
        issues.append(
            f"{APPLICATION_MAP_PHASE}.{subphase}: substatus {substatus!r} has no matching row in {rel}"
        )
    if substatus == "tested":
        for row in rows:
            if str(row.get("status", "")).strip() != "tested":
                continue
            if not existing_evidence(root, str(row.get("evidence_ref", ""))):
                issues.append(
                    f"{APPLICATION_MAP_PHASE}.{subphase}: tested row evidence_ref does not resolve "
                    f"inside the workspace: {row.get('evidence_ref', '')!r} ({rel})"
                )
    return issues


def application_mapping_issues(root: Path, phase_row: dict[str, Any] | None) -> list[str]:
    """application_mapping 子阶段审计：状态映射合法性 + 行契约 + 完成可证明性。"""
    if phase_row is None:
        return []
    issues: list[str] = []
    substatuses = phase_row.get("substatuses")
    if substatuses is not None and not isinstance(substatuses, dict):
        issues.append(f"{APPLICATION_MAP_PHASE}: substatuses must be an object keyed by subphase")
        substatuses = None
    if isinstance(substatuses, dict):
        for key, value in substatuses.items():
            name = str(key).strip()
            if not name:
                issues.append(f"{APPLICATION_MAP_PHASE}: substatuses contains an empty subphase key")
                continue
            if name not in APPLICATION_MAP_SUBPHASES:
                issues.append(f"{APPLICATION_MAP_PHASE}: unknown subphase {name!r} (spec 5.2)")
                continue
            value_text = str(value).strip()
            if not value_text:
                continue  # 空串 = 未记录，仅在 phase 完成时强制
            if value_text not in COVERAGE_SUBSTATUSES:
                issues.append(
                    f"{APPLICATION_MAP_PHASE}.{name}: invalid substatus {value_text!r} "
                    f"(allowed: {sorted(COVERAGE_SUBSTATUSES)})"
                )
                continue
            if (root / APPLICATION_MAP_ARTIFACTS[name]).is_file():
                rows, errors = _read_application_map_rows(root, name)
                if not errors:
                    issues.extend(_application_map_row_issues(name, rows))
    status = str(phase_row.get("status", "")).strip()
    if status in {"complete", "not_applicable"}:
        if not isinstance(substatuses, dict):
            issues.append(
                f"{APPLICATION_MAP_PHASE}: phase {status} but substatuses are not recorded "
                "(all five subphases must be on disk)"
            )
            substatuses = {}
        for subphase in APPLICATION_MAP_SUBPHASES:
            value_text = str(substatuses.get(subphase, "") or "").strip()
            if not value_text:
                issues.append(
                    f"{APPLICATION_MAP_PHASE}: phase {status} but subphase {subphase} has no recorded substatus"
                )
                continue
            if value_text not in PROVEN_SUBSTATUSES:
                issues.append(
                    f"{APPLICATION_MAP_PHASE}: phase {status} but subphase {subphase} is {value_text!r}; "
                    "the mapping phase is only complete with proven tested/not_applicable substatuses"
                )
                continue
            issues.extend(_substatus_proof_issues(root, subphase, value_text))
    return issues


def audit(root: Path) -> dict[str, Any]:
    root = Path(root).resolve()
    if root.name == "postrun_review" or (root / "target_review_queue.csv").is_file():
        return {
            "workspace": str(root),
            "state": "WZ_RUN_DIRECTORY_REJECTED",
            "issues": ["WZ_RUN_DIRECTORY_REJECTED: postrun_review is an FH workspace, not a wz engagement"],
        }
    if (root / "run_summary.json").is_file() or (root / "run_health.json").is_file():
        return {
            "workspace": str(root),
            "state": "WZ_RUN_DIRECTORY_REJECTED",
            "issues": ["WZ_RUN_DIRECTORY_REJECTED: run artifacts are not a wz engagement"],
        }
    engagement = read_json(root / "engagement.json")
    if not engagement:
        return {"workspace": str(root), "state": "NO_INTAKE", "issues": ["engagement.json missing or invalid"]}
    workspace_type = engagement.get("workspace_type")
    workflow = engagement.get("workflow")
    if workspace_type not in (None, "wz_engagement") or workflow not in (None, "wz"):
        return {
            "workspace": str(root),
            "state": "WZ_WORKSPACE_TYPE_MISMATCH",
            "issues": [
                f"WZ_WORKSPACE_TYPE_MISMATCH: workspace_type={workspace_type!r}, workflow={workflow!r}"
            ],
        }
    if workspace_type is None or workflow is None:
        issues = ["legacy wz workspace metadata missing: workspace_type/workflow"]
    else:
        issues = []
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
    app_map_row = phases.get(APPLICATION_MAP_PHASE)
    app_map_substatuses: dict[str, str] = {}
    if app_map_row is not None:
        issues.extend(application_mapping_issues(root, app_map_row))
        raw_substatuses = app_map_row.get("substatuses")
        if isinstance(raw_substatuses, dict):
            app_map_substatuses = {str(key): str(value) for key, value in raw_substatuses.items()}

    required = {name: row for name, row in phases.items() if bool(row.get("required", True))}
    blocked = [name for name, row in required.items() if row.get("status") == "blocked"]
    incomplete_core = [
        name for name in CORE_PHASES
        if name not in required or required[name].get("status") not in {"complete", "not_applicable"}
    ]

    ledger = [row for row in read_csv(root / "review_ledger.csv") if row.get("active", "true").lower() != "false"]
    endpoint_inventory = read_csv(root / "artifacts" / "endpoint-inventory.csv")
    historical_endpoint_rows = [
        row for row in endpoint_inventory
        if row.get("source_class") == "historical_lead"
        or (row.get("source") or "").startswith("run_import:")
    ]
    if historical_endpoint_rows:
        issues.append(
            "WZ_HISTORY_INPUT_REJECTED: current endpoint inventory contains historical run imports; "
            "re-validate them in the current WZ phase before treating them as current facts"
        )
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
        "application_mapping_substatuses": app_map_substatuses,
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
