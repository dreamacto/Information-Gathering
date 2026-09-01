#!/usr/bin/env python3
"""Create or resume a portable mini-program assessment workspace without network access."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

try:
    from phase_status_routing import MINIAPP_PHASE_STATUS_FILENAME, resolve_phase_status, route_metadata
except ImportError:
    import importlib.util

    _ROUTING_PATH = Path(__file__).with_name("phase_status_routing.py")
    _ROUTING_SPEC = importlib.util.spec_from_file_location("xcx_phase_status_routing", _ROUTING_PATH)
    if _ROUTING_SPEC is None or _ROUTING_SPEC.loader is None:
        raise
    _ROUTING_MODULE = importlib.util.module_from_spec(_ROUTING_SPEC)
    sys.modules[_ROUTING_SPEC.name] = _ROUTING_MODULE
    _ROUTING_SPEC.loader.exec_module(_ROUTING_MODULE)
    MINIAPP_PHASE_STATUS_FILENAME = _ROUTING_MODULE.MINIAPP_PHASE_STATUS_FILENAME
    resolve_phase_status = _ROUTING_MODULE.resolve_phase_status
    route_metadata = _ROUTING_MODULE.route_metadata


os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


PLATFORMS = ("auto", "wechat", "alipay", "douyin", "baidu", "quickapp", "other")
WECHAT_APPID_RE = re.compile(r"^wx[0-9a-fA-F]{16}$")
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif"}
PACKAGE_SUFFIXES = {".wxapkg", ".hap", ".rpk", ".pkg", ".zip"}

PHASES = (
    "authorization",
    "identity",
    "platform_identification",
    "material_acquisition",
    "initial_decoding",
    "preflight",
    "package_inventory",
    "package_unpack_decompile",
    "source_reconstruction",
    "package_integrity_update_review",
    "static_analysis",
    "endpoint_inventory",
    "host_classification",
    "dynamic_setup",
    "dynamic_mapping",
    "static_dynamic_reconciliation",
    "platform_login_exchange",
    "session_token_lifecycle",
    "signature_replay",
    "backend_web_api_testing",
    "access_control_testing",
    "input_file_testing",
    "business_logic_testing",
    "local_data_exposure",
    "crypto_and_secret_handling",
    "webview_bridge_links",
    "cloud_function_testing",
    "cloud_storage_acl_testing",
    "third_party_platform_boundary",
    "candidate_validation",
    "evidence",
    "cleanup",
    "retest",
    "reporting",
)

# authentication_session 认证拆分（实施规格 6.2/6.5，Batch 10）：三个 phase 的复核
# 分支（coverage_substatus 种子键，值空串=未记录，完成时审计强制）与 auth review
# 产物骨架路径。常量与 contracts/miniapp_auth_schema.json 同源，漂移由
# tests/test_xcx_auth_phase_split.py 与 tests/test_miniapp_auth_lifecycle.py 锁定。
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
AUTH_REVIEW_SKELETON_FIELDS = {
    "row_fields": (
        "row_id", "branch", "status", "evidence_kinds", "source", "evidence_ref",
        "precondition", "reason",
    ),
    "summary_fields": (
        "branch", "branch_status", "applicability_counts", "status_counts",
        "tested_count", "reason", "source", "precondition",
    ),
}

# client_storage_crypto 存储拆分 + 包完整性插入（实施规格 6.2/6.3/6.6，Batch 11）：
# 三个 phase 的复核分支（coverage_substatus 种子键，值空串=未记录，完成时审计强制）
# 与 review 产物骨架路径。常量与 contracts/miniapp_storage_package_schema.json 同源，
# 漂移由 tests/test_xcx_storage_package_phase_split.py 与 tests/test_miniapp_storage_
# crypto.py、tests/test_package_integrity_update.py 锁定。
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

# static/dynamic 对账 + 云拆分（实施规格 6.2/6.4/6.7，Batch 12）：四个 phase 的复核
# 分支（coverage_substatus 种子键，值空串=未记录，完成时审计强制）与产物路径。常量
# 与 contracts/miniapp_reconciliation_schema.json、contracts/miniapp_cloud_schema.json
# 同源，漂移由 tests/test_xcx_cloud_reconciliation_phase_split.py 与四个模块测试锁定。
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
# 十值端点状态（规格 6.4 1570-1581 行）：CSV 行级状态，与 coverage_substatus 六值
# 不同源（substatus 是 phase 覆盖枚举，endpoint_states 是对账行状态；互不映射）。
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
# 判定行状态：这些行必须有非空 reason（过期/不可达不得静默充数，人工验证需留痕）。
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
# 第三方边界 CSV（规格 6.7 产物 1645 行）。attribution 枚举与 audit 的 hosts 分类
# 状态（KNOWN_HOST_STATES）同源对齐：平台共享资产按平台分类记录，不得误报为自有。
THIRD_PARTY_CSV_FIELDS = (
    "row_id", "service_name", "service_type", "host", "attribution",
    "boundary_status", "evidence_ref", "reason", "notes",
)
THIRD_PARTY_SERVICE_TYPES = (
    "map", "payment", "push", "analytics", "plugin", "sdk", "other",
)
THIRD_PARTY_ATTRIBUTION_VALUES = (
    "in_scope", "third_party", "platform", "platform_shared",
    "out_of_scope", "invalid", "confirmation_required", "unclassified",
)

# WebView/Bridge/Deep Link（实施规格 6.8，Batch 13）：既有 webview_bridge_links
# phase 的七个复核分支（coverage_substatus 种子键，一一对应规格 1674-1680 行七项
# 覆盖）与三个固定 CSV 产物路径（规格 1667-1669 行逐字）。常量与
# contracts/miniapp_webview_schema.json（第 14 契约）、audit 脚本同源，漂移由
# tests/test_xcx_webview_artifacts.py 锁定。分支→产物 1:1（batch12 CSV 完成语义
# tested 需 ≥1 行按分支所属产物计）。
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
WEBVIEW_REVIEW_ARTIFACTS = {
    "webview_bridge_links": (
        WEBVIEW_ORIGIN_INVENTORY_CSV,
        WEBVIEW_BRIDGE_METHOD_CSV,
        WEBVIEW_DEEP_LINK_QUEUE_CSV,
    ),
}
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
# cookie/token 共享边界枚举（per-origin）；判定行（!= none）需非空 reason。
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
# capability 判定子集（规格 1682 行四影响面：越权/外部控制、敏感 token 暴露、
# 跨域数据读取、越权资损）；命中行需非空 reason。
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
WEBVIEW_CSV_FIELDS_BY_ARTIFACT = {
    WEBVIEW_ORIGIN_INVENTORY_CSV: WEBVIEW_ORIGIN_CSV_FIELDS,
    WEBVIEW_BRIDGE_METHOD_CSV: WEBVIEW_BRIDGE_CSV_FIELDS,
    WEBVIEW_DEEP_LINK_QUEUE_CSV: WEBVIEW_DEEP_LINK_CSV_FIELDS,
}


def auth_review_skeleton(phase: str) -> dict:
    branches = AUTH_REVIEW_BRANCHES[phase]
    return {
        "schema_version": "1.0",
        "contract": "miniapp_auth_schema",
        "phase": phase,
        "observation_schema_version": "1.0",
        "row_fields": list(AUTH_REVIEW_SKELETON_FIELDS["row_fields"]),
        "summary_fields": list(AUTH_REVIEW_SKELETON_FIELDS["summary_fields"]),
        "substatuses": {branch: "" for branch in branches},
        "rows": [],
        "summaries": [],
        "violations": [],
        "authorization_basis": "",
        "updated_at": "",
    }


def storage_package_review_skeleton(phase: str) -> dict:
    branches = STORAGE_PACKAGE_REVIEW_BRANCHES[phase]
    return {
        "schema_version": "1.0",
        "contract": "miniapp_storage_package_schema",
        "phase": phase,
        "observation_schema_version": "1.0",
        "row_fields": list(AUTH_REVIEW_SKELETON_FIELDS["row_fields"]),
        "summary_fields": list(AUTH_REVIEW_SKELETON_FIELDS["summary_fields"]),
        "substatuses": {branch: "" for branch in branches},
        "rows": [],
        "summaries": [],
        "violations": [],
        "authorization_basis": "",
        "updated_at": "",
    }


def cloud_review_skeleton(phase: str) -> dict:
    """云函数/对象存储 review JSON 骨架（规格 6.7 产物 1643/1644 行；契约
    miniapp_cloud_schema）。第三方 CSV 产物不走本骨架（表头种子见 main）。"""
    branches = CLOUD_REVIEW_BRANCHES[phase]
    return {
        "schema_version": "1.0",
        "contract": "miniapp_cloud_schema",
        "phase": phase,
        "observation_schema_version": "1.0",
        "row_fields": list(AUTH_REVIEW_SKELETON_FIELDS["row_fields"]),
        "summary_fields": list(AUTH_REVIEW_SKELETON_FIELDS["summary_fields"]),
        "substatuses": {branch: "" for branch in branches},
        "rows": [],
        "summaries": [],
        "violations": [],
        "authorization_basis": "",
        "updated_at": "",
    }

MATERIAL_FIELDS = (
    "material_id", "active", "material_type", "platform", "path_or_value", "size",
    "sha256", "provenance", "version", "analysis_status", "derived_from", "notes",
)

HOST_FIELDS = (
    "host_id", "active", "host", "service_type", "scope_state", "owner",
    "source_material", "source_location", "ownership_rationale", "permitted_actions",
    "confirmed_at", "notes",
)

ENDPOINT_FIELDS = (
    "endpoint_id", "active", "host", "method", "path", "parameters", "content_type",
    "auth_required", "roles", "state_changing", "client_route", "source_material",
    "source_location", "test_status", "notes",
)

DECODING_FIELDS = (
    "decoding_id", "material_id", "input_type", "input_ref", "input_sha256", "tool",
    "tool_version", "mode", "status", "output_path", "recovered_clues", "notes",
)

LEDGER_FIELDS = (
    "item_id", "active", "priority", "category", "platform", "asset", "client_route",
    "endpoint", "parameter", "role", "candidate_type", "status", "confidence", "summary",
    "source", "validation_plan", "validation_result", "evidence_ref", "finding_id", "owner",
    "updated_at",
)


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def directory_manifest_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        try:
            relative = item.relative_to(path).as_posix()
            size = item.stat().st_size
        except OSError:
            continue
        digest.update(f"{relative}\0{size}\0{sha256_file(item)}\n".encode("utf-8", errors="replace"))
    return digest.hexdigest()


def classify_path(path: Path) -> tuple[str, str]:
    if path.is_dir():
        packages = [item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in PACKAGE_SUFFIXES]
        source_markers = any((path / name).is_file() for name in ("app.json", "app.js", "manifest.json", "project.config.json"))
        source_files = any(path.rglob("*.wxml")) or any(path.rglob("*.axml")) or any(path.rglob("*.ttml"))
        if packages and not source_markers:
            return "package_cache", detect_platform_from_suffix(packages[0].suffix.lower())
        if source_markers or source_files:
            return "unpacked_source", "unknown"
        return "directory", "unknown"
    suffix = path.suffix.lower()
    if suffix in PACKAGE_SUFFIXES:
        return "package", detect_platform_from_suffix(suffix)
    if suffix in IMAGE_SUFFIXES:
        return "qr_image", "unknown"
    if suffix == ".har":
        return "traffic_export", "unknown"
    if suffix in {".xml", ".txt", ".json"}:
        sample = path.read_text(encoding="utf-8-sig", errors="replace")[:65536].lower()
        if any(token in sample for token in ("http/1.", '"request"', "<request", "\thttps://", "\thttp://")):
            return "traffic_export", "unknown"
        return "structured_or_text_artifact", "unknown"
    return "file", "unknown"


def detect_platform_from_suffix(suffix: str) -> str:
    return {".wxapkg": "wechat", ".hap": "quickapp", ".rpk": "quickapp"}.get(suffix, "unknown")


def classify_input(value: str) -> tuple[str, str, dict[str, str]]:
    candidate = Path(value)
    if candidate.exists():
        material_type, platform = classify_path(candidate)
        size = str(candidate.stat().st_size) if candidate.is_file() else ""
        digest = sha256_file(candidate) if candidate.is_file() else directory_manifest_sha256(candidate)
        return material_type, platform, {
            "path_or_value": str(candidate.resolve()), "size": size, "sha256": digest,
        }
    stripped = value.strip()
    if WECHAT_APPID_RE.fullmatch(stripped):
        return "identifier", "wechat", {"identifier": stripped.lower(), "path_or_value": stripped.lower()}
    if "://" in stripped:
        parsed = urlsplit(stripped)
        if parsed.scheme and parsed.netloc:
            return "entry_url", "unknown", {"path_or_value": stripped}
    return "name", "unknown", {"name": stripped, "path_or_value": stripped}


def write_csv_if_missing(path: Path, fields: tuple[str, ...], rows: Iterable[dict[str, str]]) -> None:
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


def _upgrade_phase_status_auth_split(phase_path: Path) -> None:
    """resume 升级（Batch 10，实施规格 6.2）：既有工作区的 authentication_session 行
    拆为三个认证 phase 行。细粒度拆分后旧 complete 不可证明，新行一律 status=pending
    并在 reason 留痕迁移来源（不携带旧状态）；幂等；文件损坏时跳过不阻塞。"""
    try:
        payload = json.loads(phase_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict) or not isinstance(payload.get("phases"), list):
        return
    names = [
        str(row.get("phase", "")).strip()
        for row in payload["phases"]
        if isinstance(row, dict)
    ]
    if "authentication_session" not in names or "platform_login_exchange" in names:
        return
    migrated: list[dict] = []
    for row in payload["phases"]:
        if isinstance(row, dict) and str(row.get("phase", "")).strip() == "authentication_session":
            old_status = str(row.get("status", "")).strip() or "unknown"
            for phase in AUTH_REVIEW_BRANCHES:
                migrated.append(
                    {
                        "phase": phase,
                        "required": bool(row.get("required", True)),
                        "status": "pending",
                        "reason": f"migrated_from_authentication_session(old_status={old_status}); "
                        "re-verify per-phase, the old aggregate completion is not proof",
                        "artifacts": [],
                        "substatuses": {name: "" for name in AUTH_REVIEW_BRANCHES[phase]},
                        "updated_at": "",
                    }
                )
        else:
            migrated.append(row)
    payload["phases"] = migrated
    phase_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _upgrade_phase_status_storage_split(phase_path: Path) -> None:
    """resume 升级（Batch 11，实施规格 6.2）：既有工作区的 client_storage_crypto 行
    拆为 local_data_exposure / crypto_and_secret_handling 两行（状态回 pending、reason
    留痕、不携带旧 complete），并在缺失时于 source_reconstruction 后插入
    package_integrity_update_review 行。幂等；文件损坏时跳过不阻塞。"""
    try:
        payload = json.loads(phase_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict) or not isinstance(payload.get("phases"), list):
        return
    names = [
        str(row.get("phase", "")).strip()
        for row in payload["phases"]
        if isinstance(row, dict)
    ]
    changed = False
    migrated: list[dict] = []
    if "client_storage_crypto" in names and "local_data_exposure" not in names:
        for row in payload["phases"]:
            if (
                isinstance(row, dict)
                and str(row.get("phase", "")).strip() == "client_storage_crypto"
            ):
                old_status = str(row.get("status", "")).strip() or "unknown"
                for phase in ("local_data_exposure", "crypto_and_secret_handling"):
                    migrated.append(
                        {
                            "phase": phase,
                            "required": bool(row.get("required", True)),
                            "status": "pending",
                            "reason": f"migrated_from_client_storage_crypto(old_status={old_status}); "
                            "re-verify per-phase, the old aggregate completion is not proof",
                            "artifacts": [],
                            "substatuses": {
                                name: "" for name in STORAGE_PACKAGE_REVIEW_BRANCHES[phase]
                            },
                            "updated_at": "",
                        }
                    )
                changed = True
            else:
                migrated.append(row)
    if not changed:
        migrated = list(payload["phases"])
    if "package_integrity_update_review" not in names:
        insert_at = len(migrated)
        for index, row in enumerate(migrated):
            if (
                isinstance(row, dict)
                and str(row.get("phase", "")).strip() == "source_reconstruction"
            ):
                insert_at = index + 1
                break
        migrated.insert(
            insert_at,
            {
                "phase": "package_integrity_update_review",
                "required": True,
                "status": "pending",
                "reason": "inserted_by_package_integrity_split; "
                "re-verify per-phase, absence of the legacy row is not proof",
                "artifacts": [],
                "substatuses": {
                    name: ""
                    for name in STORAGE_PACKAGE_REVIEW_BRANCHES[
                        "package_integrity_update_review"
                    ]
                },
                "updated_at": "",
            },
        )
        changed = True
    if not changed:
        return
    payload["phases"] = migrated
    phase_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _upgrade_phase_status_cloud_split(phase_path: Path) -> None:
    """resume 升级（Batch 12，实施规格 6.2）：既有工作区的 plugins_cloud_third_party
    行拆为 cloud_function_testing / cloud_storage_acl_testing / third_party_platform_
    boundary 三行（状态回 pending、reason 留痕、不携带旧状态），并在缺失时于
    dynamic_mapping 后插入 static_dynamic_reconciliation 行（无该锚点时兜底追加）。
    幂等；文件损坏时跳过不阻塞。"""
    try:
        payload = json.loads(phase_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict) or not isinstance(payload.get("phases"), list):
        return
    names = [
        str(row.get("phase", "")).strip()
        for row in payload["phases"]
        if isinstance(row, dict)
    ]
    changed = False
    migrated: list[dict] = []
    if "plugins_cloud_third_party" in names and "cloud_function_testing" not in names:
        for row in payload["phases"]:
            if (
                isinstance(row, dict)
                and str(row.get("phase", "")).strip() == "plugins_cloud_third_party"
            ):
                old_status = str(row.get("status", "")).strip() or "unknown"
                for phase in CLOUD_REVIEW_BRANCHES:
                    migrated.append(
                        {
                            "phase": phase,
                            "required": bool(row.get("required", True)),
                            "status": "pending",
                            "reason": f"migrated_from_plugins_cloud_third_party(old_status={old_status}); "
                            "re-verify per-phase, the old aggregate completion is not proof",
                            "artifacts": [],
                            "substatuses": {name: "" for name in CLOUD_REVIEW_BRANCHES[phase]},
                            "updated_at": "",
                        }
                    )
                changed = True
            else:
                migrated.append(row)
    if not changed:
        migrated = list(payload["phases"])
    if "static_dynamic_reconciliation" not in names:
        insert_at = len(migrated)
        for index, row in enumerate(migrated):
            if (
                isinstance(row, dict)
                and str(row.get("phase", "")).strip() == "dynamic_mapping"
            ):
                insert_at = index + 1
                break
        migrated.insert(
            insert_at,
            {
                "phase": "static_dynamic_reconciliation",
                "required": True,
                "status": "pending",
                "reason": "inserted_by_static_dynamic_reconciliation_split; "
                "re-verify per-phase, absence of the legacy row is not proof",
                "artifacts": [],
                "substatuses": {
                    name: ""
                    for name in RECONCILIATION_REVIEW_BRANCHES[
                        "static_dynamic_reconciliation"
                    ]
                },
                "updated_at": "",
            },
        )
        changed = True
    if not changed:
        return
    payload["phases"] = migrated
    phase_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _upgrade_phase_status_webview_artifacts(phase_path: Path) -> None:
    """resume 升级（Batch 13，实施规格 6.8）：既有工作区的 webview_bridge_links 行
    补种七个复核分支 substatuses（batch13_0 D6）；旧 complete/not_applicable 聚合
    完成对新分支不可证明，一并回置 pending 并在 reason 留痕（不携带旧状态）。已有
    substatuses 键的工作区零改动（幂等）；文件损坏时跳过不阻塞。"""
    try:
        payload = json.loads(phase_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict) or not isinstance(payload.get("phases"), list):
        return
    changed = False
    for row in payload["phases"]:
        if not isinstance(row, dict) or str(row.get("phase", "")).strip() != "webview_bridge_links":
            continue
        if isinstance(row.get("substatuses"), dict):
            continue
        old_status = str(row.get("status", "")).strip() or "unknown"
        row["substatuses"] = {
            name: "" for name in WEBVIEW_REVIEW_BRANCHES["webview_bridge_links"]
        }
        if old_status in {"complete", "not_applicable"}:
            row["status"] = "pending"
            row["reason"] = (
                f"migrated_pre_webview_artifacts(old_status={old_status}); "
                "re-verify per-branch, the old aggregate completion is not proof"
            )
        changed = True
    if not changed:
        return
    phase_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize a mini-program assessment workspace.")
    parser.add_argument("input", help="Name, identifier, QR, package, source, traffic, or URL.")
    parser.add_argument("--output", required=True, help="Engagement workspace directory.")
    parser.add_argument("--platform", choices=PLATFORMS, default="auto")
    parser.add_argument("--name", default="", help="Confirmed or candidate mini-program name.")
    parser.add_argument("--appid", default="", help="AppID or equivalent platform identifier.")
    parser.add_argument("--operator", default="", help="Operating entity.")
    parser.add_argument("--version", default="", help="Observed mini-program version.")
    parser.add_argument(
        "--authorization-ref",
        default="",
        help="Optional authorization evidence note; user-supplied input is accepted by default.",
    )
    parser.add_argument("--window", default="", help="Authorized testing window.")
    parser.add_argument("--rules", default="", help="Rules-of-engagement reference.")
    parser.add_argument("--rate", default="", help="Approved request-rate note.")
    parser.add_argument("--resume", action="store_true", help="Resume the same workspace.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        input_type, detected_platform, details = classify_input(args.input)
    except OSError as exc:
        print(f"ERROR: Cannot inspect input: {exc}", file=sys.stderr)
        return 2
    if not details.get("path_or_value", "").strip():
        print("ERROR: Input is empty.", file=sys.stderr)
        return 2

    platform = detected_platform if args.platform == "auto" else args.platform
    platform = platform if platform != "unknown" else "other"
    inferred_name = details.get("name", "")
    inferred_id = details.get("identifier", "")
    name = args.name.strip() or inferred_name
    identifier = args.appid.strip() or inferred_id
    identity_confirmed = bool(name and identifier and args.operator.strip() and platform)
    root = Path(args.output).resolve()
    engagement_path = root / "engagement.json"
    if root.exists() and not args.resume:
        print(f"ERROR: Output already exists; use --resume for the same engagement: {root}", file=sys.stderr)
        return 3
    if args.resume and engagement_path.is_file():
        existing = json.loads(engagement_path.read_text(encoding="utf-8-sig"))
        old_hash = existing.get("input_sha256")
        new_hash = hashlib.sha256(args.input.encode("utf-8")).hexdigest()
        if old_hash and old_hash != new_hash:
            print("ERROR: Resume input does not match the existing engagement.", file=sys.stderr)
            return 3

    for relative in (
        "artifacts", "evidence/raw", "evidence/redacted", "logs", "materials/original",
        "materials/working", "notes", "reports", "sessions",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)

    created = now()
    authorization_ref = args.authorization_ref.strip() or "user_supplied_initial_target"
    if not engagement_path.exists():
        engagement = {
            "workspace_version": 1,
            "created_at": created,
            "input_type": input_type,
            "input_sha256": hashlib.sha256(args.input.encode("utf-8")).hexdigest(),
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

    miniapp_path = root / "miniapp.json"
    if not miniapp_path.exists():
        miniapp = {
            "platform": platform,
            "name": name,
            "identifier": identifier,
            "operator": args.operator.strip(),
            "version": args.version.strip(),
            "identity_status": "confirmed" if identity_confirmed else "pending",
            "identity_evidence": "",
            "updated_at": created,
        }
        miniapp_path.write_text(
            json.dumps(miniapp, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    material_rows: list[dict[str, str]] = []
    if input_type not in {"name", "identifier"}:
        material_identity = "|".join(
            (input_type, details.get("path_or_value", ""), details.get("sha256", ""))
        )
        material_rows.append(
            {
                "material_id": hashlib.sha256(material_identity.encode("utf-8")).hexdigest()[:16],
                "active": "true",
                "material_type": input_type,
                "platform": platform,
                "path_or_value": details.get("path_or_value", ""),
                "size": details.get("size", ""),
                "sha256": details.get("sha256", ""),
                "provenance": "operator_supplied",
                "version": args.version.strip(),
                "analysis_status": "pending",
                "derived_from": "",
                "notes": "",
            }
        )
    write_csv_if_missing(root / "materials.csv", MATERIAL_FIELDS, material_rows)
    write_csv_if_missing(root / "hosts.csv", HOST_FIELDS, [])
    write_csv_if_missing(root / "endpoints.csv", ENDPOINT_FIELDS, [])
    write_csv_if_missing(root / "artifacts" / "decoding-ledger.csv", DECODING_FIELDS, [])
    write_csv_if_missing(root / "review_ledger.csv", LEDGER_FIELDS, [])
    write_csv_if_missing(
        root / "artifacts" / "package-inventory.csv",
        (
            "package_id", "material_id", "package_path", "package_type", "subpackage",
            "size", "sha256", "extractor", "extractor_version", "extraction_status",
            "output_dir", "notes",
        ),
        [],
    )
    write_csv_if_missing(
        root / "artifacts" / "source-map.csv",
        (
            "source_id", "material_id", "package_id", "source_path", "source_type",
            "recovered_from", "sha256", "parse_status", "notes",
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

    phase_route = resolve_phase_status(root, for_write=not args.resume)
    if phase_route.error:
        print(f"ERROR: {phase_route.error}", file=sys.stderr)
        return 3
    phase_path = phase_route.path
    assert phase_path is not None
    if not phase_path.exists():
        phases = []
        for phase in PHASES:
            status = "pending"
            reason = ""
            artifacts: list[str] = []
            if phase == "authorization":
                status, reason, artifacts = "complete", authorization_ref, ["engagement.json"]
            elif phase == "identity" and identity_confirmed:
                status, reason, artifacts = "complete", "Identity fields supplied", ["miniapp.json"]
            elif phase == "platform_identification" and platform:
                status, reason, artifacts = "complete", f"Platform classified as {platform}", ["miniapp.json"]
            phase_row = {
                "phase": phase, "required": True, "status": status, "reason": reason,
                "artifacts": artifacts, "updated_at": created if status == "complete" else "",
            }
            if phase in AUTH_REVIEW_BRANCHES:
                phase_row["substatuses"] = {name: "" for name in AUTH_REVIEW_BRANCHES[phase]}
            elif phase in STORAGE_PACKAGE_REVIEW_BRANCHES:
                phase_row["substatuses"] = {
                    name: "" for name in STORAGE_PACKAGE_REVIEW_BRANCHES[phase]
                }
            elif phase in RECONCILIATION_REVIEW_BRANCHES:
                phase_row["substatuses"] = {
                    name: "" for name in RECONCILIATION_REVIEW_BRANCHES[phase]
                }
            elif phase in CLOUD_REVIEW_BRANCHES:
                phase_row["substatuses"] = {
                    name: "" for name in CLOUD_REVIEW_BRANCHES[phase]
                }
            elif phase in WEBVIEW_REVIEW_BRANCHES:
                phase_row["substatuses"] = {
                    name: "" for name in WEBVIEW_REVIEW_BRANCHES[phase]
                }
            phases.append(phase_row)
        phase_path.write_text(
            json.dumps({
                "schema_version": "1.0",
                "stream": "miniapp_xcx",
                "status_file": MINIAPP_PHASE_STATUS_FILENAME,
                "current_phase": "authorization",
                "next_phase": "identity",
                "last_completed_phase": "",
                "updated_at": created,
                "phases": phases,
            }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    else:
        _upgrade_phase_status_auth_split(phase_path)
        _upgrade_phase_status_storage_split(phase_path)
        _upgrade_phase_status_cloud_split(phase_path)
        _upgrade_phase_status_webview_artifacts(phase_path)

    # auth + storage/package + reconciliation/cloud/webview review 产物骨架（Batch
    # 10/11/12/13，实施规格 6.5 产物路径 1591-1593 行 + 6.3/6.6 产物路径 1542/1619/
    # 1620 行 + 6.4/6.7 产物路径 1564/1643/1644/1645 行 + 6.8 产物路径 1667-1669 行）：
    # write_if_missing 幂等（resume 路径同样执行，旧工作区缺骨架由此补种）；substatuses
    # 空串=未记录，审计在 phase 完成时强制。CSV 产物仅种表头。
    for _auth_phase, _rel_artifact in AUTH_REVIEW_ARTIFACTS.items():
        write_text_if_missing(
            root / _rel_artifact,
            json.dumps(auth_review_skeleton(_auth_phase), ensure_ascii=False, indent=2) + "\n",
        )
    for _sp_phase, _rel_artifact in STORAGE_PACKAGE_REVIEW_ARTIFACTS.items():
        write_text_if_missing(
            root / _rel_artifact,
            json.dumps(
                storage_package_review_skeleton(_sp_phase), ensure_ascii=False, indent=2
            ) + "\n",
        )
    for _rc_phase, _rel_artifact in RECONCILIATION_REVIEW_ARTIFACTS.items():
        write_csv_if_missing(root / _rel_artifact, RECONCILIATION_CSV_FIELDS, [])
    for _cloud_phase, _rel_artifact in CLOUD_REVIEW_ARTIFACTS.items():
        if _rel_artifact.endswith(".csv"):
            write_csv_if_missing(root / _rel_artifact, THIRD_PARTY_CSV_FIELDS, [])
        else:
            write_text_if_missing(
                root / _rel_artifact,
                json.dumps(
                    cloud_review_skeleton(_cloud_phase), ensure_ascii=False, indent=2
                ) + "\n",
            )
    for _webview_rel, _webview_fields in WEBVIEW_CSV_FIELDS_BY_ARTIFACT.items():
        write_csv_if_missing(root / _webview_rel, _webview_fields, [])

    write_text_if_missing(root / "notes" / "target-model.md", "# Target model\n\n## Host map\n\n## Technology stack\n\n## Entrypoints\n\n## Authentication topology\n\n## Attack-surface decisions\n\n## Excluded and untested areas\n")
    write_text_if_missing(root / "notes" / "operator_tasks.md", "# Operator tasks\n\n- [ ] Confirm authorization evidence, testing window, and scope before active testing.\n")
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
        "## Mini-program identity, scope, and rules\n\n"
        "## Client/package analysis coverage\n\n"
        "## Backend host and API classification\n\n"
        "## Confirmed findings\n\n"
        "## Rejected candidates and false positives\n\n"
        "## Blocked, approval-gated, and not-applicable areas\n\n"
        "## Cleanup, retest, and residual risk\n\n"
        "## Evidence index\n\n",
    )
    write_text_if_missing(root / "reports" / ".gitkeep", "")
    print(f"workspace={root}")
    print(f"phase_status_file={phase_path.name}")
    print(f"stream={phase_route.stream}")
    print(f"legacy_single_stream={str(phase_route.legacy_single_stream).lower()}")
    print(f"input_type={input_type}")
    print(f"platform={platform}")
    print(f"identity={'confirmed' if identity_confirmed else 'pending'}")
    print("authorization=target_received (active testing not authorized)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
