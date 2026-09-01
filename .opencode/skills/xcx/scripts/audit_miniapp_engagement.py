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

try:
    from phase_status_routing import resolve_phase_status, route_metadata
except ImportError:
    import importlib.util

    _ROUTING_PATH = Path(__file__).with_name("phase_status_routing.py")
    _ROUTING_SPEC = importlib.util.spec_from_file_location("xcx_phase_status_routing", _ROUTING_PATH)
    if _ROUTING_SPEC is None or _ROUTING_SPEC.loader is None:
        raise
    _ROUTING_MODULE = importlib.util.module_from_spec(_ROUTING_SPEC)
    sys.modules[_ROUTING_SPEC.name] = _ROUTING_MODULE
    _ROUTING_SPEC.loader.exec_module(_ROUTING_MODULE)
    resolve_phase_status = _ROUTING_MODULE.resolve_phase_status
    route_metadata = _ROUTING_MODULE.route_metadata


os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


CORE_PHASES = {
    "authorization", "identity", "platform_identification", "material_acquisition",
    "initial_decoding", "preflight",
    "package_inventory", "package_unpack_decompile", "source_reconstruction",
    "package_integrity_update_review", "static_analysis",
    "endpoint_inventory", "host_classification", "dynamic_setup",
    "dynamic_mapping", "static_dynamic_reconciliation",
    "platform_login_exchange", "session_token_lifecycle", "signature_replay",
    "backend_web_api_testing",
    "access_control_testing", "input_file_testing", "business_logic_testing",
    "local_data_exposure", "crypto_and_secret_handling", "webview_bridge_links",
    "cloud_function_testing", "cloud_storage_acl_testing", "third_party_platform_boundary",
}
# authentication_session 认证拆分（Batch 10，实施规格 6.2/6.5）：三 phase 复核分支与
# 产物路径，常量与 contracts/miniapp_auth_schema.json、init 脚本同源，漂移由
# tests/test_xcx_auth_phase_split.py 锁定。六值枚举与 proving 子集单一来源引用
# coverage_substatus_schema（此处为自包含复制）。
AUTH_REVIEW_BRANCHES = {
    "platform_login_exchange": (
        "login_code_one_time",
        "login_code_expiry",
        "appid_binding",
        "session_key_custody",
        "openid_authorization_basis",
    ),
    "session_token_lifecycle": (
        "token_rotation",
        "token_revocation_logout",
        "multi_device_login",
        "stale_token_new_api",
        "device_user_tenant_binding",
    ),
    "signature_replay": (
        "nonce_timestamp",
        "signature_canonicalization",
        "replay_window",
        "binding_scope",
    ),
}
AUTH_REVIEW_ARTIFACTS = {
    "platform_login_exchange": "artifacts/miniapp/auth/platform-login-review.json",
    "session_token_lifecycle": "artifacts/miniapp/auth/session-lifecycle-review.json",
    "signature_replay": "artifacts/miniapp/auth/signature-replay-review.json",
}
COVERAGE_SUBSTATUSES = {
    "tested", "not_applicable", "blocked", "approval_required", "needs_manual_validation", "inconclusive",
}
PROVEN_SUBSTATUSES = {"tested", "not_applicable"}
FINDING_STATUS_VALUES = {
    "signal", "candidate", "needs_manual_validation", "confirmed",
    "inconclusive", "blocked", "rejected", "duplicate",
}
AUTHORIZATION_BASIS_VALUES = {"operator_supplied_material", "local_traffic"}
# client_storage_crypto 存储拆分 + 包完整性插入（Batch 11，实施规格 6.2/6.3/6.6）：
# 三 phase 复核分支与产物路径，常量与 contracts/miniapp_storage_package_schema.json、
# init 脚本同源，漂移由 tests/test_xcx_storage_package_phase_split.py 锁定。
STORAGE_PACKAGE_REVIEW_BRANCHES = {
    "package_integrity_update_review": (
        "package_version_inventory",
        "manifest_resource_diff",
        "update_endpoint_environment",
        "debug_switches",
        "source_map_exposure",
        "version_drift",
        "trusted_update_config",
    ),
    "local_data_exposure": (
        "token_persistence",
        "logout_cleanup",
        "local_cache_database",
        "logs_clipboard_screenshots",
        "temp_files",
    ),
    "crypto_and_secret_handling": (
        "hardcoded_secrets",
        "custom_crypto",
        "weak_random_key_derivation",
        "debug_config_env_keys",
    ),
}
STORAGE_PACKAGE_REVIEW_ARTIFACTS = {
    "package_integrity_update_review": "artifacts/miniapp/package/package-integrity-review.json",
    "local_data_exposure": "artifacts/miniapp/storage/local-data-review.json",
    "crypto_and_secret_handling": "artifacts/miniapp/crypto/secret-review.json",
}
# static/dynamic 对账 + 云拆分（Batch 12，实施规格 6.2/6.4/6.7）：四 phase 复核分支
# 与产物路径，常量与 contracts/miniapp_reconciliation_schema.json、
# contracts/miniapp_cloud_schema.json、init 脚本同源，漂移由
# tests/test_xcx_cloud_reconciliation_phase_split.py 锁定。
RECONCILIATION_REVIEW_BRANCHES = {
    "static_dynamic_reconciliation": (
        "static_endpoint_base",
        "dynamic_endpoint_base",
        "match_status_classification",
        "hidden_flow_identification",
        "stale_entry_disposition",
    ),
}
RECONCILIATION_REVIEW_ARTIFACTS = {
    "static_dynamic_reconciliation": "artifacts/miniapp/reconciliation/static-dynamic-endpoints.csv",
}
# 十值端点状态（规格 6.4 1570-1581 行）：CSV 行级状态，与 COVERAGE_SUBSTATUSES
# 六值不同源（phase 覆盖枚举 vs 对账行状态；互不映射）。
RECONCILIATION_ENDPOINT_STATES = (
    "static_only",
    "dynamic_only",
    "both_seen",
    "feature_gated",
    "stale",
    "version_specific",
    "third_party",
    "platform_shared",
    "unreachable",
    "needs_manual_validation",
)
RECONCILIATION_CSV_FIELDS = (
    "endpoint_id", "host", "method", "path", "source_material",
    "static_evidence_ref", "dynamic_evidence_ref", "status", "reason", "notes",
)
RECONCILIATION_JUDGMENT_STATES = ("stale", "unreachable", "needs_manual_validation")
CLOUD_REVIEW_BRANCHES = {
    "cloud_function_testing": (
        "anonymous_invocation",
        "function_parameter_role_validation",
        "cloud_env_id_mixing",
    ),
    "cloud_storage_acl_testing": (
        "cloud_database_rules",
        "object_storage_acl",
        "signed_url_binding",
    ),
    "third_party_platform_boundary": (
        "third_party_service_boundary",
        "platform_shared_asset_attribution",
    ),
}
CLOUD_REVIEW_ARTIFACTS = {
    "cloud_function_testing": "artifacts/miniapp/cloud/cloud-function-review.json",
    "cloud_storage_acl_testing": "artifacts/miniapp/cloud/object-storage-review.json",
    "third_party_platform_boundary": "artifacts/miniapp/cloud/third-party-boundary.csv",
}
THIRD_PARTY_CSV_FIELDS = (
    "row_id", "service_name", "service_type", "host", "attribution",
    "boundary_status", "evidence_ref", "reason", "notes",
)
THIRD_PARTY_SERVICE_TYPES = (
    "map", "payment", "push", "analytics", "plugin", "sdk", "other",
)
# 归属枚举与 KNOWN_HOST_STATES 同源对齐（单一来源：hosts 分类状态）。
THIRD_PARTY_ATTRIBUTION_VALUES = (
    "in_scope", "third_party", "platform", "platform_shared",
    "out_of_scope", "invalid", "confirmation_required", "unclassified",
)
# WebView/Bridge/Deep Link（Batch 13，实施规格 6.8）：既有 webview_bridge_links
# phase 七复核分支与三个固定 CSV 产物路径，常量与 contracts/miniapp_webview_schema.
# json、init 脚本同源，漂移由 tests/test_xcx_webview_artifacts.py 锁定。分支→产物
# 1:1（共享完成语义的 tested ≥1 行按分支所属产物计）。
WEBVIEW_REVIEW_BRANCHES = {
    "webview_bridge_links": (
        "webview_allowed_domains",
        "postmessage_origin",
        "bridge_method_exposure",
        "custom_scheme",
        "deep_link_sensitive_params",
        "external_app_browser_jump",
        "cookie_token_sharing_boundary",
    ),
}
WEBVIEW_ORIGIN_INVENTORY_CSV = "artifacts/miniapp/webview/webview-origin-inventory.csv"
WEBVIEW_BRIDGE_METHOD_CSV = "artifacts/miniapp/webview/bridge-method-inventory.csv"
WEBVIEW_DEEP_LINK_QUEUE_CSV = "artifacts/miniapp/webview/deep-link-review-queue.csv"
WEBVIEW_BRANCH_ARTIFACTS = {
    "webview_allowed_domains": WEBVIEW_ORIGIN_INVENTORY_CSV,
    "postmessage_origin": WEBVIEW_ORIGIN_INVENTORY_CSV,
    "cookie_token_sharing_boundary": WEBVIEW_ORIGIN_INVENTORY_CSV,
    "bridge_method_exposure": WEBVIEW_BRIDGE_METHOD_CSV,
    "custom_scheme": WEBVIEW_DEEP_LINK_QUEUE_CSV,
    "deep_link_sensitive_params": WEBVIEW_DEEP_LINK_QUEUE_CSV,
    "external_app_browser_jump": WEBVIEW_DEEP_LINK_QUEUE_CSV,
}
WEBVIEW_ORIGIN_CSV_FIELDS = (
    "row_id", "webview_origin", "business_purpose", "source_material",
    "source_location", "postmessage_target_origin", "cookie_token_shared",
    "boundary_status", "evidence_ref", "reason", "notes",
)
WEBVIEW_COOKIE_TOKEN_SHARED_VALUES = (
    "none", "session_cookie", "auth_token", "both", "unknown",
)
WEBVIEW_BRIDGE_CSV_FIELDS = (
    "row_id", "method_name", "exposed_scope", "capability", "source_material",
    "boundary_status", "evidence_ref", "reason", "notes",
)
WEBVIEW_CAPABILITY_VALUES = (
    "navigation", "read_data", "write_data", "sensitive_token_access",
    "file_access", "payment", "other",
)
# capability 判定子集（规格 1682 行四影响面）；命中行需非空 reason。
WEBVIEW_BRIDGE_REASON_CAPABILITIES = (
    "write_data", "sensitive_token_access", "file_access", "payment",
)
WEBVIEW_DEEP_LINK_CSV_FIELDS = (
    "row_id", "deep_link_pattern", "scheme_type", "sensitive_params", "jump_target",
    "boundary_status", "evidence_ref", "reason", "notes",
)
WEBVIEW_SCHEME_TYPES = ("custom_scheme", "https_link", "other")
WEBVIEW_JUMP_TARGETS = ("in_app", "external_app", "browser", "unknown")
# 跳转判定子集（外部控制面/未确认）；命中行需非空 reason；sensitive_params 非空
# 同样需 reason（对象 ID/tenant ID/scene 参数为规格 1678 行点名关注项）。
WEBVIEW_REASON_JUMP_TARGETS = ("external_app", "browser", "unknown")
ANALYZABLE_MATERIALS = {"package", "package_cache", "unpacked_source", "traffic_export"}
PACKAGE_MATERIALS = {"package", "package_cache"}
VALID_PHASE_STATUSES = {"pending", "in_progress", "complete", "blocked", "not_applicable"}
OPEN_REVIEW_STATUSES = {"candidate", "needs_manual_validation"}
VALID_REVIEW_STATUSES = OPEN_REVIEW_STATUSES | {
    "approval_required", "confirmed", "rejected", "accepted_risk", "fixed",
    "retest_failed", "retest_passed", "duplicate", "out_of_scope", "needs_login", "blocked",
}
RESOLVED_HOST_STATES = {"in_scope", "third_party", "platform", "platform_shared", "out_of_scope", "invalid"}
KNOWN_HOST_STATES = RESOLVED_HOST_STATES | {"confirmation_required", "unclassified"}


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


def phase_map(root: Path) -> tuple[dict[str, dict[str, Any]], list[str], dict[str, Any]]:
    route = resolve_phase_status(root)
    if route.error or route.path is None:
        return {}, [route.error or "xcx phase status file is unavailable"], route_metadata(route)
    payload = read_json(route.path)
    rows = payload.get("phases", [])
    status_name = route.path.name
    if not isinstance(rows, list):
        return {}, [f"{status_name} does not contain a phases list"], route_metadata(route)
    result: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not str(row.get("phase", "")).strip():
            errors.append(f"{status_name} contains an invalid phase row")
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
    return result, errors, route_metadata(route)


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


def _review_phase_issues(
    root: Path,
    phase: str,
    phase_row: dict[str, Any] | None,
    branches: tuple[str, ...],
    artifact_rel: str,
    contract_name: str,
) -> list[str]:
    """review phase 通用审计（Batch 10 认证 + Batch 11 存储/包完整性共用；
    wz application_mapping_issues 同款语义）：substatuses 合法性 + review 产物形状 +
    完成可证明性。红线：完成必须逐分支可证明（tested/not_applicable），
    not_applicable 需 reason，tested 需 evidence_ref 可解析，且 authorization_basis
    必须是授权材料/本地流量（不自动创建或滥用登录凭证）。"""
    if phase_row is None:
        return []
    issues: list[str] = []
    substatuses = phase_row.get("substatuses")
    if substatuses is not None and not isinstance(substatuses, dict):
        issues.append(f"{phase}: substatuses must be an object keyed by review branch")
        substatuses = None
    if isinstance(substatuses, dict):
        for key, value in substatuses.items():
            name = str(key).strip()
            if not name:
                issues.append(f"{phase}: substatuses contains an empty branch key")
                continue
            if name not in branches:
                issues.append(f"{phase}: unknown review branch {name!r} ({contract_name})")
                continue
            value_text = str(value).strip()
            if not value_text:
                continue  # 空串 = 未记录，仅在 phase 完成时强制
            if value_text not in COVERAGE_SUBSTATUSES:
                issues.append(
                    f"{phase}.{name}: invalid substatus {value_text!r} "
                    f"(allowed: {sorted(COVERAGE_SUBSTATUSES)})"
                )
    artifact: dict[str, Any] = {}
    if (root / artifact_rel).is_file():
        artifact = read_json(root / artifact_rel)
        if not artifact:
            issues.append(f"{phase}: {artifact_rel} is not a valid JSON object")
        else:
            if str(artifact.get("contract", "")).strip() != contract_name:
                issues.append(f"{phase}: {artifact_rel} contract must be {contract_name}")
            if str(artifact.get("phase", "")).strip() != phase:
                issues.append(f"{phase}: {artifact_rel} phase field mismatch: {artifact.get('phase')!r}")
            rows = artifact.get("rows")
            if not isinstance(rows, list):
                issues.append(f"{phase}: {artifact_rel} rows must be a list")
            else:
                for row in rows:
                    if not isinstance(row, dict):
                        issues.append(f"{phase}: {artifact_rel} contains a non-object row")
                        continue
                    branch = str(row.get("branch", "")).strip()
                    if branch not in branches:
                        issues.append(f"{phase}: {artifact_rel} row has unknown branch {branch!r}")
                    row_status = str(row.get("status", "")).strip()
                    if row_status and row_status not in FINDING_STATUS_VALUES:
                        issues.append(f"{phase}: {artifact_rel} row has invalid status {row_status!r}")
            summaries = artifact.get("summaries")
            if not isinstance(summaries, list):
                issues.append(f"{phase}: {artifact_rel} summaries must be a list")
            else:
                seen_branches: set[str] = set()
                for summary in summaries:
                    if not isinstance(summary, dict):
                        issues.append(f"{phase}: {artifact_rel} contains a non-object summary")
                        continue
                    branch = str(summary.get("branch", "")).strip()
                    if branch not in branches:
                        issues.append(f"{phase}: {artifact_rel} summary has unknown branch {branch!r}")
                        continue
                    if branch in seen_branches:
                        issues.append(f"{phase}: {artifact_rel} duplicate summary for branch {branch!r}")
                    seen_branches.add(branch)
                    branch_status = str(summary.get("branch_status", "")).strip()
                    if branch_status and branch_status not in COVERAGE_SUBSTATUSES:
                        issues.append(
                            f"{phase}.{branch}: invalid branch_status {branch_status!r} "
                            f"(allowed: {sorted(COVERAGE_SUBSTATUSES)})"
                        )
            basis = str(artifact.get("authorization_basis", "")).strip()
            if basis and basis not in AUTHORIZATION_BASIS_VALUES:
                issues.append(
                    f"{phase}: {artifact_rel} authorization_basis {basis!r} is not one of "
                    f"{sorted(AUTHORIZATION_BASIS_VALUES)} (no auto-created credentials)"
                )
    status = str(phase_row.get("status", "")).strip()
    if status in {"complete", "not_applicable"}:
        if not isinstance(substatuses, dict):
            issues.append(
                f"{phase}: phase {status} but substatuses are not recorded "
                "(all review branches must be on disk)"
            )
            substatuses = {}
        for branch in branches:
            value_text = str(substatuses.get(branch, "") or "").strip()
            if not value_text:
                issues.append(
                    f"{phase}: phase {status} but branch {branch} has no recorded substatus"
                )
                continue
            if value_text not in PROVEN_SUBSTATUSES:
                issues.append(
                    f"{phase}: phase {status} but branch {branch} is {value_text!r}; "
                    "the auth phase is only complete with proven tested/not_applicable branch statuses"
                )
                continue
            if not artifact:
                issues.append(f"{phase}: phase {status} but {artifact_rel} is missing or invalid")
                continue
            summaries = artifact.get("summaries")
            branch_summaries = []
            if isinstance(summaries, list):
                branch_summaries = [
                    row for row in summaries
                    if isinstance(row, dict) and str(row.get("branch", "")).strip() == branch
                ]
            if not branch_summaries:
                issues.append(
                    f"{phase}.{branch}: substatus {value_text!r} has no matching summary in {artifact_rel}"
                )
                continue
            summary = branch_summaries[0]
            if str(summary.get("branch_status", "")).strip() != value_text:
                issues.append(
                    f"{phase}.{branch}: substatus {value_text!r} does not match artifact "
                    f"branch_status {summary.get('branch_status')!r} ({artifact_rel})"
                )
            if value_text == "not_applicable" and not str(summary.get("reason", "")).strip():
                issues.append(
                    f"{phase}.{branch}: not_applicable summary lacks reason (silent omission is forbidden)"
                )
            if value_text == "tested" and not existing_evidence(root, str(summary.get("evidence_ref", ""))):
                issues.append(
                    f"{phase}.{branch}: tested summary evidence_ref does not resolve inside the "
                    f"workspace: {summary.get('evidence_ref', '')!r} ({artifact_rel})"
                )
    return issues


def authentication_review_issues(
    root: Path, phase: str, phase_row: dict[str, Any] | None
) -> list[str]:
    """认证拆分三 phase 审计（Batch 10，实施规格 6.2/6.5；通用 helper 的 auth 绑定）。"""
    return _review_phase_issues(
        root,
        phase,
        phase_row,
        AUTH_REVIEW_BRANCHES[phase],
        AUTH_REVIEW_ARTIFACTS[phase],
        "miniapp_auth_schema",
    )


def storage_package_review_issues(
    root: Path, phase: str, phase_row: dict[str, Any] | None
) -> list[str]:
    """存储/包完整性三 phase 审计（Batch 11，实施规格 6.2/6.3/6.6；通用 helper 的
    storage/package 绑定；红线：不做重打包/篡改/绕过 pinning，secret_candidate 红线
    由契约 red_lines 与模块常量承载）。"""
    return _review_phase_issues(
        root,
        phase,
        phase_row,
        STORAGE_PACKAGE_REVIEW_BRANCHES[phase],
        STORAGE_PACKAGE_REVIEW_ARTIFACTS[phase],
        "miniapp_storage_package_schema",
    )


def cloud_json_review_issues(
    root: Path, phase: str, phase_row: dict[str, Any] | None
) -> list[str]:
    """云函数/对象存储 review phase 审计（Batch 12，实施规格 6.2/6.7；通用 helper 的
    cloud 绑定；红线：默认只做材料、配置、授权流量和最小读验证，任何写入、批量读取
    和真实支付必须审批——由契约 red_lines 与模块常量承载）。"""
    return _review_phase_issues(
        root,
        phase,
        phase_row,
        CLOUD_REVIEW_BRANCHES[phase],
        CLOUD_REVIEW_ARTIFACTS[phase],
        "miniapp_cloud_schema",
    )


def _recorded_substatus_issues(
    phase: str,
    phase_row: dict[str, Any],
    branches: tuple[str, ...],
) -> tuple[list[str], dict[str, Any] | None]:
    """substatus 记录合法性校验（batch13_1 从 _csv_phase_issues 提取的共享块 A，
    消息文本与提取前字节一致）：未知分支键/非法值记违例，空串=未记录（仅完成时
    强制）。返回 (issues, substatuses)——substatuses 规范化为 dict 或 None。"""
    issues: list[str] = []
    substatuses = phase_row.get("substatuses")
    if substatuses is not None and not isinstance(substatuses, dict):
        issues.append(f"{phase}: substatuses must be an object keyed by review branch")
        substatuses = None
    if isinstance(substatuses, dict):
        for key, value in substatuses.items():
            name = str(key).strip()
            if not name:
                issues.append(f"{phase}: substatuses contains an empty branch key")
                continue
            if name not in branches:
                issues.append(f"{phase}: unknown review branch {name!r}")
                continue
            value_text = str(value).strip()
            if not value_text:
                continue  # 空串 = 未记录，仅在 phase 完成时强制
            if value_text not in COVERAGE_SUBSTATUSES:
                issues.append(
                    f"{phase}.{name}: invalid substatus {value_text!r} "
                    f"(allowed: {sorted(COVERAGE_SUBSTATUSES)})"
                )
    return issues, substatuses


def _csv_artifact_issues(
    root: Path,
    phase: str,
    artifact_rel: str,
    columns: tuple[str, ...],
    check_row,
) -> tuple[list[str], list[dict[str, str]]]:
    """CSV 产物表头精确匹配 + 行级校验（batch13_1 从 _csv_phase_issues 提取的共享
    块 B，消息文本与提取前字节一致）。表头直接从文件首行读取（DictReader 对表头-
    only 文件不产出行，仅靠行键校验会漏检空 CSV 的表头漂移）。"""
    issues: list[str] = []
    rows: list[dict[str, str]] = []
    csv_path = root / artifact_rel
    if csv_path.is_file():
        try:
            with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                first = next(csv.reader(handle), None)
            header = tuple(item.strip() for item in first) if first is not None else ()
        except OSError:
            header = ()
        if header != columns:
            issues.append(
                f"{phase}: {artifact_rel} header must be exactly {list(columns)} "
                f"(got {list(header)})"
            )
        rows = read_csv(csv_path)
        for index, row in enumerate(rows, start=1):
            issues.extend(check_row(phase, artifact_rel, index, row))
    return issues, rows


def _csv_completion_issues(
    phase: str,
    phase_row: dict[str, Any],
    substatuses: dict[str, Any] | None,
    branches: tuple[str, ...],
    rows_by_artifact: dict[str, list[dict[str, str]]],
    artifact_by_branch: dict[str, str],
) -> list[str]:
    """完成可证明性（batch13_1 从 _csv_phase_issues 提取的共享块 C，消息文本与
    提取前字节一致）：全分支 proven；tested 分支要求其所属产物存在且 ≥1 数据行
    （tested ≥1 行按 branch→artifact 映射计，支持单产物与多产物 phase）；
    not_applicable 分支要求 phase 行 reason 非空。"""
    issues: list[str] = []
    status = str(phase_row.get("status", "")).strip()
    if status not in {"complete", "not_applicable"}:
        return issues
    if not isinstance(substatuses, dict):
        issues.append(
            f"{phase}: phase {status} but substatuses are not recorded "
            "(all review branches must be on disk)"
        )
        substatuses = {}
    for branch in branches:
        value_text = str(substatuses.get(branch, "") or "").strip()
        if not value_text:
            issues.append(
                f"{phase}: phase {status} but branch {branch} has no recorded substatus"
            )
            continue
        if value_text not in PROVEN_SUBSTATUSES:
            issues.append(
                f"{phase}: phase {status} but branch {branch} is {value_text!r}; "
                "the phase is only complete with proven tested/not_applicable branch statuses"
            )
            continue
        if value_text == "tested":
            artifact_rel = artifact_by_branch[branch]
            if not rows_by_artifact.get(artifact_rel):
                issues.append(
                    f"{phase}: phase {status} but tested branch {branch} requires at "
                    f"least one recorded row in {artifact_rel}"
                )
        elif value_text == "not_applicable" and not str(
            phase_row.get("reason", "")
        ).strip():
            issues.append(
                f"{phase}: not_applicable branch {branch} requires a phase reason "
                "(silent omission is forbidden)"
            )
    return issues


def _csv_phase_issues(
    root: Path,
    phase: str,
    phase_row: dict[str, Any] | None,
    branches: tuple[str, ...],
    artifact_rel: str,
    columns: tuple[str, ...],
    check_row,
) -> list[str]:
    """CSV 产物 phase 通用审计（Batch 12；batch13_1 重构为三共享块组合，签名与
    消息文本字节不变）：substatuses 合法性 + CSV 表头精确匹配 + 行级枚举/判定行
    reason + 完成可证明性（全分支 proven；tested 分支要求 CSV 存在且 ≥1 数据行；
    not_applicable 分支要求 phase 行 reason 非空）。"""
    if phase_row is None:
        return []
    sub_issues, substatuses = _recorded_substatus_issues(phase, phase_row, branches)
    row_issues, rows = _csv_artifact_issues(root, phase, artifact_rel, columns, check_row)
    completion_issues = _csv_completion_issues(
        phase,
        phase_row,
        substatuses,
        branches,
        {artifact_rel: rows},
        {branch: artifact_rel for branch in branches},
    )
    return sub_issues + row_issues + completion_issues


def _check_reconciliation_row(
    phase: str, artifact_rel: str, index: int, row: dict[str, str]
) -> list[str]:
    """对账 CSV 行校验：十值端点状态枚举 + 判定行（stale/unreachable/needs_manual_
    validation）需非空 reason（过期/不可达不得静默充数，人工验证需留痕）。"""
    issues: list[str] = []
    status = str(row.get("status", "")).strip()
    if not status:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty status")
    elif status not in RECONCILIATION_ENDPOINT_STATES:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid status {status!r} "
            f"(allowed: {list(RECONCILIATION_ENDPOINT_STATES)})"
        )
    reason = str(row.get("reason", "")).strip()
    if status in RECONCILIATION_JUDGMENT_STATES and not reason:
        issues.append(
            f"{phase}: {artifact_rel} row {index} status {status!r} requires a "
            "non-empty reason (silent omission is forbidden)"
        )
    return issues


def _check_third_party_row(
    phase: str, artifact_rel: str, index: int, row: dict[str, str]
) -> list[str]:
    """第三方边界 CSV 行校验：service_type/attribution 枚举（归属与 hosts 分类状态
    同源）+ boundary_status ∈ finding 8 状态 + 待确认归属行需非空 reason。"""
    issues: list[str] = []
    service_type = str(row.get("service_type", "")).strip()
    if not service_type:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty service_type")
    elif service_type not in THIRD_PARTY_SERVICE_TYPES:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid service_type "
            f"{service_type!r} (allowed: {list(THIRD_PARTY_SERVICE_TYPES)})"
        )
    attribution = str(row.get("attribution", "")).strip()
    if not attribution:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty attribution")
    elif attribution not in THIRD_PARTY_ATTRIBUTION_VALUES:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid attribution "
            f"{attribution!r} (allowed: {list(THIRD_PARTY_ATTRIBUTION_VALUES)})"
        )
    boundary_status = str(row.get("boundary_status", "")).strip()
    if boundary_status and boundary_status not in FINDING_STATUS_VALUES:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid boundary_status "
            f"{boundary_status!r}"
        )
    reason = str(row.get("reason", "")).strip()
    if attribution in {"confirmation_required", "unclassified"} and not reason:
        issues.append(
            f"{phase}: {artifact_rel} row {index} attribution {attribution!r} requires "
            "a non-empty reason (silent omission is forbidden)"
        )
    return issues


def static_dynamic_reconciliation_issues(
    root: Path, phase: str, phase_row: dict[str, Any] | None
) -> list[str]:
    """static/dynamic 对账 phase 审计（Batch 12，实施规格 6.2/6.4；CSV 产物形状，
    十值端点状态为行级状态、与 coverage_substatus 六值不同源）。"""
    return _csv_phase_issues(
        root,
        phase,
        phase_row,
        RECONCILIATION_REVIEW_BRANCHES[phase],
        RECONCILIATION_REVIEW_ARTIFACTS[phase],
        RECONCILIATION_CSV_FIELDS,
        _check_reconciliation_row,
    )


def third_party_boundary_issues(
    root: Path, phase: str, phase_row: dict[str, Any] | None
) -> list[str]:
    """第三方边界 phase 审计（Batch 12，实施规格 6.2/6.7；CSV 产物形状，attribution
    与 hosts 分类状态同源对齐；平台共享资产不得误报为自有资产）。"""
    return _csv_phase_issues(
        root,
        phase,
        phase_row,
        CLOUD_REVIEW_BRANCHES[phase],
        CLOUD_REVIEW_ARTIFACTS[phase],
        THIRD_PARTY_CSV_FIELDS,
        _check_third_party_row,
    )


def _check_webview_origin_row(
    phase: str, artifact_rel: str, index: int, row: dict[str, str]
) -> list[str]:
    """origin 清单行校验（Batch 13，实施规格 6.8）：webview_origin/cookie_token_
    shared 非空 + cookie_token_shared 枚举（判定值非 none 需非空 reason——共享已
    观察到/未确认边界须留痕）+ boundary_status 可空、非空须 ∈ finding 8 状态。"""
    issues: list[str] = []
    webview_origin = str(row.get("webview_origin", "")).strip()
    if not webview_origin:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty webview_origin")
    cookie_token_shared = str(row.get("cookie_token_shared", "")).strip()
    if not cookie_token_shared:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty cookie_token_shared")
    elif cookie_token_shared not in WEBVIEW_COOKIE_TOKEN_SHARED_VALUES:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid cookie_token_shared "
            f"{cookie_token_shared!r} (allowed: {list(WEBVIEW_COOKIE_TOKEN_SHARED_VALUES)})"
        )
    elif cookie_token_shared != "none" and not str(row.get("reason", "")).strip():
        issues.append(
            f"{phase}: {artifact_rel} row {index} cookie_token_shared "
            f"{cookie_token_shared!r} requires a non-empty reason "
            "(silent omission is forbidden)"
        )
    boundary_status = str(row.get("boundary_status", "")).strip()
    if boundary_status and boundary_status not in FINDING_STATUS_VALUES:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid boundary_status "
            f"{boundary_status!r}"
        )
    return issues


def _check_bridge_method_row(
    phase: str, artifact_rel: str, index: int, row: dict[str, str]
) -> list[str]:
    """bridge 方法行校验（Batch 13，实施规格 6.8）：method_name/exposed_scope/
    capability 非空 + capability 枚举（规格 1682 行四影响面判定子集命中需非空
    reason）+ boundary_status 可空、非空须 ∈ finding 8 状态。"""
    issues: list[str] = []
    method_name = str(row.get("method_name", "")).strip()
    if not method_name:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty method_name")
    exposed_scope = str(row.get("exposed_scope", "")).strip()
    if not exposed_scope:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty exposed_scope")
    capability = str(row.get("capability", "")).strip()
    if not capability:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty capability")
    elif capability not in WEBVIEW_CAPABILITY_VALUES:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid capability "
            f"{capability!r} (allowed: {list(WEBVIEW_CAPABILITY_VALUES)})"
        )
    elif (
        capability in WEBVIEW_BRIDGE_REASON_CAPABILITIES
        and not str(row.get("reason", "")).strip()
    ):
        issues.append(
            f"{phase}: {artifact_rel} row {index} capability {capability!r} requires "
            "a non-empty reason (silent omission is forbidden)"
        )
    boundary_status = str(row.get("boundary_status", "")).strip()
    if boundary_status and boundary_status not in FINDING_STATUS_VALUES:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid boundary_status "
            f"{boundary_status!r}"
        )
    return issues


def _check_deep_link_row(
    phase: str, artifact_rel: str, index: int, row: dict[str, str]
) -> list[str]:
    """深链复核队列行校验（Batch 13，实施规格 6.8）：deep_link_pattern/scheme_type/
    jump_target 非空 + scheme_type/jump_target 枚举（外部跳转/未确认跳转或携带
    敏感参数——对象 ID/tenant ID/scene——的行需非空 reason）+ boundary_status
    可空、非空须 ∈ finding 8 状态。"""
    issues: list[str] = []
    deep_link_pattern = str(row.get("deep_link_pattern", "")).strip()
    if not deep_link_pattern:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty deep_link_pattern")
    scheme_type = str(row.get("scheme_type", "")).strip()
    if not scheme_type:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty scheme_type")
    elif scheme_type not in WEBVIEW_SCHEME_TYPES:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid scheme_type "
            f"{scheme_type!r} (allowed: {list(WEBVIEW_SCHEME_TYPES)})"
        )
    jump_target = str(row.get("jump_target", "")).strip()
    if not jump_target:
        issues.append(f"{phase}: {artifact_rel} row {index} has empty jump_target")
    elif jump_target not in WEBVIEW_JUMP_TARGETS:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid jump_target "
            f"{jump_target!r} (allowed: {list(WEBVIEW_JUMP_TARGETS)})"
        )
    sensitive_params = str(row.get("sensitive_params", "")).strip()
    if (
        (sensitive_params or jump_target in WEBVIEW_REASON_JUMP_TARGETS)
        and not str(row.get("reason", "")).strip()
    ):
        issues.append(
            f"{phase}: {artifact_rel} row {index} deep link with sensitive params or "
            "external/unconfirmed jump requires a non-empty reason "
            "(silent omission is forbidden)"
        )
    boundary_status = str(row.get("boundary_status", "")).strip()
    if boundary_status and boundary_status not in FINDING_STATUS_VALUES:
        issues.append(
            f"{phase}: {artifact_rel} row {index} has invalid boundary_status "
            f"{boundary_status!r}"
        )
    return issues


WEBVIEW_ARTIFACT_CHECKS = (
    (WEBVIEW_ORIGIN_INVENTORY_CSV, WEBVIEW_ORIGIN_CSV_FIELDS, _check_webview_origin_row),
    (WEBVIEW_BRIDGE_METHOD_CSV, WEBVIEW_BRIDGE_CSV_FIELDS, _check_bridge_method_row),
    (WEBVIEW_DEEP_LINK_QUEUE_CSV, WEBVIEW_DEEP_LINK_CSV_FIELDS, _check_deep_link_row),
)


def webview_bridge_links_issues(
    root: Path, phase: str, phase_row: dict[str, Any] | None
) -> list[str]:
    """WebView/Bridge/Deep Link phase 审计（Batch 13，实施规格 6.8；七分支×三 CSV
    固定产物，branch→artifact 1:1）：共享块 A 对全七分支校验一次（三产物共享一份
    phase substatuses，不得按产物子集各自校验——否则其他产物的分支会被误报为未知
    分支）；块 B 按产物 ×3；块 C 的 tested ≥1 行按分支所属产物计。红线：Cookie/
    token 共享边界分析只做离线材料与授权流量，不自动注入或重放；深链验证不自动
    拉起外部 App/浏览器。"""
    if phase_row is None:
        return []
    branches = WEBVIEW_REVIEW_BRANCHES[phase]
    sub_issues, substatuses = _recorded_substatus_issues(phase, phase_row, branches)
    row_issues: list[str] = []
    rows_by_artifact: dict[str, list[dict[str, str]]] = {}
    for artifact_rel, columns, check_row in WEBVIEW_ARTIFACT_CHECKS:
        artifact_issues, rows = _csv_artifact_issues(root, phase, artifact_rel, columns, check_row)
        row_issues.extend(artifact_issues)
        rows_by_artifact[artifact_rel] = rows
    completion_issues = _csv_completion_issues(
        phase,
        phase_row,
        substatuses,
        branches,
        rows_by_artifact,
        WEBVIEW_BRANCH_ARTIFACTS,
    )
    return sub_issues + row_issues + completion_issues


def audit(root: Path) -> dict[str, Any]:
    engagement = read_json(root / "engagement.json")
    miniapp = read_json(root / "miniapp.json")
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
        if row.get("scope_state") not in KNOWN_HOST_STATES
    ]
    in_scope_hosts = [row for row in hosts if row.get("scope_state") == "in_scope"]

    phases, phase_errors, phase_route_meta = phase_map(root)
    issues.extend(phase_errors)
    for auth_phase in AUTH_REVIEW_BRANCHES:
        issues.extend(authentication_review_issues(root, auth_phase, phases.get(auth_phase)))
    for storage_phase in STORAGE_PACKAGE_REVIEW_BRANCHES:
        issues.extend(storage_package_review_issues(root, storage_phase, phases.get(storage_phase)))
    for reconciliation_phase in RECONCILIATION_REVIEW_BRANCHES:
        issues.extend(
            static_dynamic_reconciliation_issues(
                root, reconciliation_phase, phases.get(reconciliation_phase)
            )
        )
    for cloud_phase in CLOUD_REVIEW_BRANCHES:
        if CLOUD_REVIEW_ARTIFACTS[cloud_phase].endswith(".csv"):
            issues.extend(third_party_boundary_issues(root, cloud_phase, phases.get(cloud_phase)))
        else:
            issues.extend(cloud_json_review_issues(root, cloud_phase, phases.get(cloud_phase)))
    for webview_phase in WEBVIEW_REVIEW_BRANCHES:
        issues.extend(webview_bridge_links_issues(root, webview_phase, phases.get(webview_phase)))
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
    rejected_without_reason = [
        row.get("item_id", "<missing>") for row in ledger
        if row.get("status") == "rejected" and not (row.get("validation_result", "").strip() or row.get("notes", "").strip())
    ]
    issues.extend(f"invalid material status: {item}" for item in invalid_materials)
    issues.extend(f"failed material lacks reason: {item}" for item in failed_without_reason)
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
        "phase_status_file": phase_route_meta["phase_status_file"],
        "stream": phase_route_meta["stream"],
        "legacy_single_stream": phase_route_meta["legacy_single_stream"],
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
    return 0 if result["state"] == "CLOSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
