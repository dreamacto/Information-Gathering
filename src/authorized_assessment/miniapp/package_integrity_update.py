"""包完整性和更新信任复核域（实施规格 6.3 1536-1556 行 + 6.2 拆分 1499-1534 行，
Batch 11）+ miniapp_storage_package 三模块共享引擎宿主。

只读离线：沿用统一筛选模式（观察键→证据形态确定性映射→rule_satisfied 升级判定→
8 状态分级），不发任何请求、不重打包、不篡改包、不绕过 pinning、不攻击设备
（规格 6.3 红线："不做重打包、篡改、绕过 pinning 或设备攻击"）。观察输入为复核
会话从操作员提供的包副本与既有清单证据提炼的结构化记录。

七分支（与 contracts/miniapp_storage_package_schema.json phases.package_integrity_
update_review.branches 同源；规格 6.3 离线检查清单七项逐一对应）：
- package_version_inventory：主包、子包、插件包版本；
- manifest_resource_diff：清单和资源差异；
- update_endpoint_environment：更新地址和环境切换；
- debug_switches：调试开关；
- source_map_exposure：Source Map；
- version_drift：版本漂移；
- trusted_update_config：前端是否信任可控更新配置。

升级边界（实现定义供操作者复核）：仅对应分支的确认证据（*_confirmed，来自既有
只读证据的复核判定且可复现）可升级 candidate；"版本标记/差异线索/更新地址存在/
调试标记存在"等形态与支持性观察永不升级（signal 不是漏洞）。观察到的控制或
残留调试工件只是线索；confirmed 五门判定仍归 finding_quality_gate；本模块只做
候选层分级校验。

共享引擎（Batch 11 三模块复用；batch10 platform_login_exchange 承载的通用实现
经中性别名复用，单一实现不复制），本模块同时承载 miniapp_storage_package 契约
形状的 artifact 构建/校验实现。local_data_exposure / crypto_secret_review 两模块
经扇形 import 复用并在各自模块内只定义分支/证据形态/映射/升级规则常量。skill
脚本常量（init/audit）与契约的一致性由 tests/test_xcx_storage_package_phase_split.py
锁定；模块常量与契约的一致性由 tests/test_package_integrity_update.py 与
tests/test_miniapp_storage_crypto.py 锁定。

产物形状契约：contracts/miniapp_storage_package_schema.json artifact_fields（12 键
JSON，rows=统一筛选候选行，summaries=分支级汇总 branch_status 六值——由
injection_candidates.aggregate_category_status 单一引擎聚合）。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.miniapp import platform_login_exchange as auth_engine
from authorized_assessment.triage import injection_candidates as ic

# 契约标识与版本（miniapp_storage_package_schema.schema_version/contract 同源）。
MINIAPP_STORAGE_PACKAGE_CONTRACT = "miniapp_storage_package_schema"
MINIAPP_STORAGE_PACKAGE_SCHEMA_VERSION = "1.0"

# 存储拆分 + 包完整性插入三 phase 与产物路径（规格 6.2 1499-1534 行 + 6.3/6.6 产物
# 1542/1619/1620 行；与 xcx skill init/audit 常量、miniapp_storage_package_schema
# 三方同源）。
STORAGE_PACKAGE_PHASES: tuple[str, ...] = (
    "package_integrity_update_review",
    "local_data_exposure",
    "crypto_and_secret_handling",
)
STORAGE_PACKAGE_REVIEW_ARTIFACTS: dict[str, str] = {
    "package_integrity_update_review": "artifacts/miniapp/package/package-integrity-review.json",
    "local_data_exposure": "artifacts/miniapp/storage/local-data-review.json",
    "crypto_and_secret_handling": "artifacts/miniapp/crypto/secret-review.json",
}

# 共享形状契约（miniapp_storage_package_schema.artifact_fields 同源；与 batch9/batch10
# 候选行同形状、category→branch 改名）。
REVIEW_ROW_FIELDS: tuple[str, ...] = auth_engine.AUTH_REVIEW_ROW_FIELDS
REVIEW_SUMMARY_FIELDS: tuple[str, ...] = auth_engine.AUTH_REVIEW_SUMMARY_FIELDS
REVIEW_ARTIFACT_KEYS: tuple[str, ...] = auth_engine.AUTH_REVIEW_ARTIFACT_KEYS

# 授权材料来源（artifact.authorization_basis 允许值；skill audit 常量同源）。
AUTHORIZATION_BASIS_VALUES: tuple[str, ...] = auth_engine.AUTHORIZATION_BASIS_VALUES

# ---------------------------------------------------------------------------
# 共享引擎（Batch 11 三模块复用；通用实现单一来源 = miniapp_auth 引擎，中性别名
# 避免 batch11 调用点出现 auth 字样误导，不复制实现）
# ---------------------------------------------------------------------------

derive_evidence_kinds = auth_engine.derive_auth_evidence_kinds
grade_observation = auth_engine.grade_auth_observation
validate_review_row = auth_engine.validate_auth_review_row
validate_branch_summary = auth_engine.validate_auth_branch_summary
screen_observations = auth_engine.screen_auth_observations
derive_substatuses = auth_engine.derive_substatuses


def build_storage_package_review_artifact(
    phase: str,
    rows: Iterable[Mapping[str, object]],
    summaries: Iterable[Mapping[str, object]],
    violations: Iterable[str],
    authorization_basis: str,
    updated_at: str,
    substatuses: Mapping[str, str] | None = None,
) -> dict:
    """契约形状 artifact dict（12 键，miniapp_storage_package_schema.artifact_fields
    同源；Batch 11 契约的唯一构建实现，auth 契约的构建实现仍在 batch10 引擎）。"""
    summary_list = [dict(s) for s in summaries]
    return {
        "schema_version": MINIAPP_STORAGE_PACKAGE_SCHEMA_VERSION,
        "contract": MINIAPP_STORAGE_PACKAGE_CONTRACT,
        "phase": phase,
        "observation_schema_version": ic.OBSERVATION_SCHEMA_VERSION,
        "row_fields": list(REVIEW_ROW_FIELDS),
        "summary_fields": list(REVIEW_SUMMARY_FIELDS),
        "substatuses": dict(substatuses) if substatuses is not None else derive_substatuses(summary_list),
        "rows": [dict(r) for r in rows],
        "summaries": summary_list,
        "violations": list(violations),
        "authorization_basis": authorization_basis,
        "updated_at": updated_at,
    }


def validate_storage_package_review_artifact(
    artifact: Mapping[str, object],
    phase: str,
    branches: tuple[str, ...],
    evidence_kinds_all: tuple[str, ...],
    insufficient_kinds: tuple[str, ...],
    upgrade_rules: Mapping[str, Mapping[str, object]],
    label: str = "storage_package_review_artifact",
) -> list[str]:
    """契约形状 artifact 校验（与 skill audit 语义一致；模块侧供会话落盘前自检）。"""
    violations: list[str] = []
    if not isinstance(artifact, Mapping):
        return [f"{label}: artifact 必须是键值映射"]
    for key in REVIEW_ARTIFACT_KEYS:
        if key not in artifact:
            violations.append(f"{label}: 缺少必需键 {key}")
    if str(artifact.get("contract") or "") != MINIAPP_STORAGE_PACKAGE_CONTRACT:
        violations.append(f"{label}: contract 必须为 {MINIAPP_STORAGE_PACKAGE_CONTRACT}")
    if str(artifact.get("phase") or "") != phase:
        violations.append(f"{label}: phase 必须为 {phase}，实际 {artifact.get('phase')!r}")
    if str(artifact.get("schema_version") or "") != MINIAPP_STORAGE_PACKAGE_SCHEMA_VERSION:
        violations.append(
            f"{label}: schema_version 必须为 {MINIAPP_STORAGE_PACKAGE_SCHEMA_VERSION}"
        )
    basis = str(artifact.get("authorization_basis") or "").strip()
    if basis and basis not in AUTHORIZATION_BASIS_VALUES:
        violations.append(
            f"{label}: authorization_basis {basis!r} 非法（允许值 {list(AUTHORIZATION_BASIS_VALUES)}）"
        )
    substatuses = artifact.get("substatuses")
    if not isinstance(substatuses, dict):
        violations.append(f"{label}: substatuses 必须为键值对象")
    else:
        for key, value in substatuses.items():
            if str(key) not in branches:
                violations.append(f"{label}.substatuses 未知分支: {key!r}")
            if str(value).strip() and str(value) not in ic.CATEGORY_STATUS_VALUES:
                violations.append(
                    f"{label}.substatuses.{key} 非法: {value!r}"
                    f"（允许值 {list(ic.CATEGORY_STATUS_VALUES)}）"
                )
    rows = artifact.get("rows")
    if not isinstance(rows, list):
        violations.append(f"{label}: rows 必须为列表")
    else:
        for row in rows:
            violations += validate_review_row(
                row,
                branches,
                evidence_kinds_all,
                insufficient_kinds,
                upgrade_rules,
                label=f"{label}.rows",
            )
    summaries = artifact.get("summaries")
    if not isinstance(summaries, list):
        violations.append(f"{label}: summaries 必须为列表")
    else:
        for summary in summaries:
            violations += validate_branch_summary(
                summary, branches, label=f"{label}.summaries"
            )
    return violations


# ---------------------------------------------------------------------------
# package_integrity_update_review 分支常量与筛选入口
# ---------------------------------------------------------------------------

# 七分支（契约 phases.package_integrity_update_review.branches 同源；规格 6.3 清单
# 七项逐一对应）。
PACKAGE_INTEGRITY_BRANCHES: tuple[str, ...] = (
    "package_version_inventory",
    "manifest_resource_diff",
    "update_endpoint_environment",
    "debug_switches",
    "source_map_exposure",
    "version_drift",
    "trusted_update_config",
)

# 证据形态（21：14 形态/支持性永不升级 + 7 确认形态与分支一一对应）。
PACKAGE_INTEGRITY_EVIDENCE_KINDS: tuple[str, ...] = (
    "package_version_labels_observed",
    "subpackage_version_mismatch_observed",
    "manifest_diff_clue_observed",
    "resource_diff_clue_observed",
    "update_address_observed",
    "environment_switch_marker_observed",
    "debug_flag_marker_observed",
    "debug_toggle_code_observed",
    "source_map_file_present_observed",
    "source_map_reference_observed",
    "stale_version_marker_observed",
    "version_drift_clue_observed",
    "remote_config_trust_clue_observed",
    "update_config_reference_observed",
    "subpackage_version_divergence_confirmed",
    "manifest_resource_divergence_confirmed",
    "controllable_update_address_confirmed",
    "debug_switch_active_confirmed",
    "source_map_recovered_confirmed",
    "stale_version_active_confirmed",
    "client_trusts_remote_update_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察，未证明完整性/信任边界失效。
PACKAGE_INTEGRITY_INSUFFICIENT_KINDS: tuple[str, ...] = (
    "package_version_labels_observed",
    "subpackage_version_mismatch_observed",
    "manifest_diff_clue_observed",
    "resource_diff_clue_observed",
    "update_address_observed",
    "environment_switch_marker_observed",
    "debug_flag_marker_observed",
    "debug_toggle_code_observed",
    "source_map_file_present_observed",
    "source_map_reference_observed",
    "stale_version_marker_observed",
    "version_drift_clue_observed",
    "remote_config_trust_clue_observed",
    "update_config_reference_observed",
)

# 升级规则（实现定义，固定语义；确认形态与分支一一对应、不跨分支升级）：
# "确认"语义要求观察来自既有只读证据（包副本/清单/流量）的复核判定且可复现；
# 禁止为取得确认而重打包、篡改、绕过 pinning 或攻击设备（规格 6.3 红线，
# precondition 必须留痕）。
PACKAGE_INTEGRITY_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "package_version_inventory": {
        "required_any_groups": (("subpackage_version_divergence_confirmed",),)
    },
    "manifest_resource_diff": {
        "required_any_groups": (("manifest_resource_divergence_confirmed",),)
    },
    "update_endpoint_environment": {
        "required_any_groups": (("controllable_update_address_confirmed",),)
    },
    "debug_switches": {
        "required_any_groups": (("debug_switch_active_confirmed",),)
    },
    "source_map_exposure": {
        "required_any_groups": (("source_map_recovered_confirmed",),)
    },
    "version_drift": {
        "required_any_groups": (("stale_version_active_confirmed",),)
    },
    "trusted_update_config": {
        "required_any_groups": (("client_trusts_remote_update_confirmed",),)
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
PACKAGE_INTEGRITY_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    key: key for key in PACKAGE_INTEGRITY_EVIDENCE_KINDS
}

PACKAGE_INTEGRITY_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "package_version_labels_observed": "观察到主包/子包/插件包版本标记（支持性）",
    "subpackage_version_mismatch_observed": "观察到子包/插件包版本与主包不一致线索"
    "（仅形态，不代表加载行为受影响）",
    "manifest_diff_clue_observed": "观察到清单声明与实际内容差异线索（仅形态）",
    "resource_diff_clue_observed": "观察到资源文件跨包/跨版本差异线索（仅形态）",
    "update_address_observed": "观察到更新/下载地址（支持性）",
    "environment_switch_marker_observed": "观察到测试/预发/正式环境切换标记（仅形态）",
    "debug_flag_marker_observed": "观察到调试开关标记（仅形态）",
    "debug_toggle_code_observed": "观察到调试开关相关代码路径（支持性）",
    "source_map_file_present_observed": "观察到 Source Map 文件存在（仅形态）",
    "source_map_reference_observed": "观察到 Source Map 引用/ sourceMappingURL 标记"
    "（支持性）",
    "stale_version_marker_observed": "观察到旧版本/缓存版本标记（仅形态）",
    "version_drift_clue_observed": "观察到材料与声明版本漂移线索（仅形态）",
    "remote_config_trust_clue_observed": "观察到远程配置影响客户端行为线索（仅形态）",
    "update_config_reference_observed": "观察到更新配置引用/加载点（支持性）",
    "subpackage_version_divergence_confirmed": "已确认子包/插件包与主包版本不一致且"
    "加载行为受其影响（既有只读证据复核且可复现）",
    "manifest_resource_divergence_confirmed": "已确认清单声明与实际资源差异可复现且"
    "影响行为（既有只读证据复核且可复现）",
    "controllable_update_address_confirmed": "已确认更新/下载地址可被外部内容影响或"
    "指向非预期环境（既有只读证据复核且可复现；不发起请求验证）",
    "debug_switch_active_confirmed": "已确认发布包调试开关处于可用状态且改变行为"
    "（既有只读证据复核且可复现）",
    "source_map_recovered_confirmed": "已确认可从包副本离线恢复出映射完整源码"
    "（既有只读证据复核且可复现）",
    "stale_version_active_confirmed": "已确认旧版本包仍被加载/执行（既有只读证据"
    "复核且可复现）",
    "client_trusts_remote_update_confirmed": "已确认客户端无条件信任可控更新配置并"
    "据此改变代码/数据流（既有只读证据复核且可复现；不做重打包或篡改验证）",
}

# 红线常量（规格 6.3 红线；写入 artifact 与候选 precondition 语义）。
PACKAGE_NO_REPACKING_RULE: str = (
    "不做重打包、篡改、绕过 pinning 或设备攻击；包完整性复核只分析操作员提供的"
    "包副本与既有清单证据"
)


def screen_package_integrity_observations(
    observations: Iterable[Mapping[str, object]],
    all_branches: bool = True,
    label: str = "package_integrity_update_review",
) -> tuple[list[dict], list[dict], list[str]]:
    """包完整性和更新信任复核筛选 → (候选行, 分支汇总行, 违例)。"""
    return screen_observations(
        observations,
        PACKAGE_INTEGRITY_BRANCHES,
        PACKAGE_INTEGRITY_OBSERVATION_EVIDENCE_MAP,
        PACKAGE_INTEGRITY_EVIDENCE_KINDS,
        PACKAGE_INTEGRITY_INSUFFICIENT_KINDS,
        PACKAGE_INTEGRITY_UPGRADE_RULES,
        all_branches=all_branches,
        label=label,
    )


def validate_package_integrity_candidate(
    row: Mapping[str, object], label: str = "package_integrity_candidate"
) -> list[str]:
    return validate_review_row(
        row,
        PACKAGE_INTEGRITY_BRANCHES,
        PACKAGE_INTEGRITY_EVIDENCE_KINDS,
        PACKAGE_INTEGRITY_INSUFFICIENT_KINDS,
        PACKAGE_INTEGRITY_UPGRADE_RULES,
        label=label,
    )


def build_package_integrity_review_artifact(
    rows: Iterable[Mapping[str, object]],
    summaries: Iterable[Mapping[str, object]],
    violations: Iterable[str],
    authorization_basis: str,
    updated_at: str,
    substatuses: Mapping[str, str] | None = None,
) -> dict:
    return build_storage_package_review_artifact(
        "package_integrity_update_review",
        rows,
        summaries,
        violations,
        authorization_basis,
        updated_at,
        substatuses=substatuses,
    )


def validate_package_integrity_review_artifact(
    artifact: Mapping[str, object], label: str = "package_integrity_review_artifact"
) -> list[str]:
    return validate_storage_package_review_artifact(
        artifact,
        "package_integrity_update_review",
        PACKAGE_INTEGRITY_BRANCHES,
        PACKAGE_INTEGRITY_EVIDENCE_KINDS,
        PACKAGE_INTEGRITY_INSUFFICIENT_KINDS,
        PACKAGE_INTEGRITY_UPGRADE_RULES,
        label=label,
    )


def _cli() -> int:
    """离线 CLI：观察 JSON 文件 → review artifact JSON（纯文件到文件）。"""
    import argparse
    import json
    from datetime import datetime
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Offline package integrity and update trust review "
        "(no network, no repacking/tampering)."
    )
    parser.add_argument("--observations", required=True, help="Observations JSON file (list or {observations: [...]})")
    parser.add_argument("--out", required=True, help="Output artifact JSON path")
    parser.add_argument(
        "--authorization-basis",
        default="operator_supplied_material",
        choices=list(AUTHORIZATION_BASIS_VALUES),
    )
    args = parser.parse_args()
    payload = json.loads(Path(args.observations).read_text(encoding="utf-8-sig"))
    observations = payload.get("observations", []) if isinstance(payload, dict) else payload
    if not isinstance(observations, list):
        print("ERROR: observations must be a list", flush=True)
        return 2
    rows, summaries, violations = screen_package_integrity_observations(observations)
    artifact = build_package_integrity_review_artifact(
        rows,
        summaries,
        violations,
        authorization_basis=args.authorization_basis,
        updated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"rows={len(artifact['rows'])} summaries={len(artifact['summaries'])} "
          f"violations={len(artifact['violations'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
