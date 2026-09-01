"""云函数测试复核域（实施规格 6.7 1635-1660 行 + 6.2 拆分 1528-1534 行，
Batch 12）+ miniapp_cloud 三模块共享引擎宿主。

只读离线：沿用统一筛选模式（观察键→证据形态确定性映射→rule_satisfied 升级判定→
8 状态分级），不发任何请求、不调用云函数、不触发任何写型云函数。规格 1660 行红线：
默认只做材料、配置、授权流量和最小读验证，任何写入、批量读取和真实支付必须审批
（红线常量 CLOUD_MINIMAL_READ_RULE 留痕）。观察输入为复核会话从操作员提供的授权
材料、本地流量或云配置副本提炼的结构化记录。

三分支（与 contracts/miniapp_cloud_schema.json phases.cloud_function_testing.branches
同源；规格 6.7 覆盖清单前三项逐一对应；云环境 ID 混用属云环境归属问题，归本 phase，
卡片 batch12_0 出入留痕 3）：
- anonymous_invocation：云函数匿名调用；
- function_parameter_role_validation：函数参数和角色校验；
- cloud_env_id_mixing：云环境 ID 混用。

升级边界（实现定义供操作者复核）：仅对应分支的确认证据（*_confirmed，来自既有
只读证据的复核判定且可复现）可升级 candidate；"匿名标记存在/参数校验代码存在/
环境 ID 出现"等形态与支持性观察永不升级（signal 不是漏洞）。confirmed 五门判定
仍归 finding_quality_gate；本模块只做候选层分级校验。

共享引擎（Batch 12 三模块复用；batch10 通用实现经 batch11 宿主中性别名复用，单一
实现不复制），本模块同时承载 miniapp_cloud 契约形状的 review JSON artifact 构建/
校验实现。cloud_storage_review / third_party_boundary_review 两模块经扇形 import
复用并在各自模块内只定义分支/证据形态/映射/升级规则常量（第三方 CSV 形状的构建/
校验在 third_party_boundary_review 内实现，不经本宿主的 review JSON 形状）。

产物形状契约：contracts/miniapp_cloud_schema.json artifact_fields（12 键 JSON，
仅 review_json_phases 两个 phase；CSV phase 形状混用被 build/validate 拒绝——
契约 invariant"两种形状由 artifact_format 区分"的实现侧强制）。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.miniapp import package_integrity_update as sp_engine
from authorized_assessment.triage import injection_candidates as ic

# 契约标识与版本（miniapp_cloud_schema.schema_version/contract 同源）。
MINIAPP_CLOUD_CONTRACT = "miniapp_cloud_schema"
MINIAPP_CLOUD_SCHEMA_VERSION = "1.0"

# 云拆分三 phase 与产物路径（规格 6.2 1528-1534 行 + 6.7 产物 1643/1644/1645 行；
# 与 xcx skill init/audit 常量、miniapp_cloud_schema 三方同源）。
CLOUD_PHASES: tuple[str, ...] = (
    "cloud_function_testing",
    "cloud_storage_acl_testing",
    "third_party_platform_boundary",
)
CLOUD_REVIEW_ARTIFACTS: dict[str, str] = {
    "cloud_function_testing": "artifacts/miniapp/cloud/cloud-function-review.json",
    "cloud_storage_acl_testing": "artifacts/miniapp/cloud/object-storage-review.json",
    "third_party_platform_boundary": "artifacts/miniapp/cloud/third-party-boundary.csv",
}

# review JSON 形状 phase（第 13 契约 artifact_fields.review_json_phases 同源；
# build/validate 只接受这两个 phase，CSV 形状 phase 混用即违例）。
CLOUD_REVIEW_JSON_PHASES: tuple[str, ...] = (
    "cloud_function_testing",
    "cloud_storage_acl_testing",
)

# 共享形状契约（与 batch10/11 review JSON 12 键同形状）。
CLOUD_REVIEW_ROW_FIELDS: tuple[str, ...] = sp_engine.REVIEW_ROW_FIELDS
CLOUD_REVIEW_SUMMARY_FIELDS: tuple[str, ...] = sp_engine.REVIEW_SUMMARY_FIELDS
CLOUD_REVIEW_ARTIFACT_KEYS: tuple[str, ...] = sp_engine.REVIEW_ARTIFACT_KEYS

# 授权材料来源（artifact.authorization_basis 允许值；skill audit 常量同源）。
AUTHORIZATION_BASIS_VALUES: tuple[str, ...] = sp_engine.AUTHORIZATION_BASIS_VALUES

# ---------------------------------------------------------------------------
# 共享引擎（Batch 12 三模块复用；通用实现单一来源 = batch10 引擎经 batch11 宿主
# 中性别名，避免 cloud 调用点出现 storage/auth 字样误导，不复制实现）
# ---------------------------------------------------------------------------

derive_evidence_kinds = sp_engine.derive_evidence_kinds
grade_observation = sp_engine.grade_observation
validate_review_row = sp_engine.validate_review_row
validate_branch_summary = sp_engine.validate_branch_summary
screen_observations = sp_engine.screen_observations
derive_substatuses = sp_engine.derive_substatuses


def build_cloud_review_artifact(
    phase: str,
    rows: Iterable[Mapping[str, object]],
    summaries: Iterable[Mapping[str, object]],
    violations: Iterable[str],
    authorization_basis: str,
    updated_at: str,
    substatuses: Mapping[str, str] | None = None,
) -> dict:
    """契约形状 artifact dict（12 键，miniapp_cloud_schema.artifact_fields 同源；
    仅接受 review_json_phases 两个 phase——CSV 形状 phase 混用即 ValueError）。"""
    if phase not in CLOUD_REVIEW_JSON_PHASES:
        raise ValueError(
            f"phase {phase!r} 的产物是 CSV 形状（third-party-boundary.csv），"
            "不接受 review JSON 形状构建（契约 artifact_format 区分）"
        )
    summary_list = [dict(s) for s in summaries]
    return {
        "schema_version": MINIAPP_CLOUD_SCHEMA_VERSION,
        "contract": MINIAPP_CLOUD_CONTRACT,
        "phase": phase,
        "observation_schema_version": ic.OBSERVATION_SCHEMA_VERSION,
        "row_fields": list(CLOUD_REVIEW_ROW_FIELDS),
        "summary_fields": list(CLOUD_REVIEW_SUMMARY_FIELDS),
        "substatuses": dict(substatuses) if substatuses is not None else derive_substatuses(summary_list),
        "rows": [dict(r) for r in rows],
        "summaries": summary_list,
        "violations": list(violations),
        "authorization_basis": authorization_basis,
        "updated_at": updated_at,
    }


def validate_cloud_review_artifact(
    artifact: Mapping[str, object],
    phase: str,
    branches: tuple[str, ...],
    evidence_kinds_all: tuple[str, ...],
    insufficient_kinds: tuple[str, ...],
    upgrade_rules: Mapping[str, Mapping[str, object]],
    label: str = "cloud_review_artifact",
) -> list[str]:
    """契约形状 artifact 校验（与 skill audit 语义一致；模块侧供会话落盘前自检）；
    仅接受 review_json_phases 两个 phase。"""
    if phase not in CLOUD_REVIEW_JSON_PHASES:
        return [
            f"{label}: phase {phase!r} 的产物是 CSV 形状，不接受 review JSON 形状校验"
        ]
    violations: list[str] = []
    if not isinstance(artifact, Mapping):
        return [f"{label}: artifact 必须是键值映射"]
    for key in CLOUD_REVIEW_ARTIFACT_KEYS:
        if key not in artifact:
            violations.append(f"{label}: 缺少必需键 {key}")
    if str(artifact.get("contract") or "") != MINIAPP_CLOUD_CONTRACT:
        violations.append(f"{label}: contract 必须为 {MINIAPP_CLOUD_CONTRACT}")
    if str(artifact.get("phase") or "") != phase:
        violations.append(f"{label}: phase 必须为 {phase}，实际 {artifact.get('phase')!r}")
    if str(artifact.get("schema_version") or "") != MINIAPP_CLOUD_SCHEMA_VERSION:
        violations.append(
            f"{label}: schema_version 必须为 {MINIAPP_CLOUD_SCHEMA_VERSION}"
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
# cloud_function_testing 分支常量与筛选入口
# ---------------------------------------------------------------------------

# 三分支（契约 phases.cloud_function_testing.branches 同源；规格 6.7 覆盖清单
# 前三项逐一对应）。
CLOUD_FUNCTION_BRANCHES: tuple[str, ...] = (
    "anonymous_invocation",
    "function_parameter_role_validation",
    "cloud_env_id_mixing",
)

# 证据形态（12：8 形态/支持性永不升级 + 4 确认形态与分支对应）。
CLOUD_FUNCTION_EVIDENCE_KINDS: tuple[str, ...] = (
    "cloud_function_anonymous_flag_observed",
    "anonymous_call_clue_observed",
    "function_param_validation_code_observed",
    "function_role_check_code_observed",
    "unvalidated_param_flow_clue_observed",
    "cloud_env_id_observed",
    "cloud_env_id_shared_clue_observed",
    "cross_app_config_marker_observed",
    "anonymous_invocation_processed_confirmed",
    "function_param_role_bypass_confirmed",
    "cloud_env_id_cross_tenant_confirmed",
    "env_id_tenant_reachability_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察，未证明匿名/校验/归属边界失效。
CLOUD_FUNCTION_INSUFFICIENT_KINDS: tuple[str, ...] = (
    "cloud_function_anonymous_flag_observed",
    "anonymous_call_clue_observed",
    "function_param_validation_code_observed",
    "function_role_check_code_observed",
    "unvalidated_param_flow_clue_observed",
    "cloud_env_id_observed",
    "cloud_env_id_shared_clue_observed",
    "cross_app_config_marker_observed",
)

# 升级规则（实现定义，固定语义；确认形态与分支对应、不跨分支升级）：
# "确认"语义要求观察来自既有只读证据（授权材料/本地流量/配置副本）的复核判定且
# 可复现；禁止为取得确认而调用云函数或触发任何写入（规格 1660 红线，precondition
# 必须留痕）。
CLOUD_FUNCTION_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "anonymous_invocation": {
        "required_any_groups": (("anonymous_invocation_processed_confirmed",),)
    },
    "function_parameter_role_validation": {
        "required_any_groups": (("function_param_role_bypass_confirmed",),)
    },
    "cloud_env_id_mixing": {
        "required_any_groups": (
            ("cloud_env_id_cross_tenant_confirmed", "env_id_tenant_reachability_confirmed"),
        )
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
CLOUD_FUNCTION_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    key: key for key in CLOUD_FUNCTION_EVIDENCE_KINDS
}

CLOUD_FUNCTION_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "cloud_function_anonymous_flag_observed": "观察到云函数配置/代码含可匿名调用标记"
    "（仅形态，不代表未认证调用被处理）",
    "anonymous_call_clue_observed": "观察到无需登录即可调用云函数的线索（仅形态）",
    "function_param_validation_code_observed": "观察到函数内参数校验代码路径（支持性，"
    "正向线索）",
    "function_role_check_code_observed": "观察到函数内角色/身份校验代码路径（支持性，"
    "正向线索）",
    "unvalidated_param_flow_clue_observed": "观察到外部参数未校验直接进入数据访问线索"
    "（仅形态）",
    "cloud_env_id_observed": "观察到云环境 ID（支持性）",
    "cloud_env_id_shared_clue_observed": "观察到同一环境 ID 出现在多个应用/租户配置中"
    "线索（仅形态）",
    "cross_app_config_marker_observed": "观察到跨应用配置引用标记（仅形态）",
    "anonymous_invocation_processed_confirmed": "已确认未认证调用被服务端处理且返回"
    "业务数据（既有只读证据复核且可复现；不新发起调用验证）",
    "function_param_role_bypass_confirmed": "已确认参数伪造或角色缺失导致越权行为"
    "（既有只读证据复核且可复现）",
    "cloud_env_id_cross_tenant_confirmed": "已确认环境 ID 跨应用/租户混用（既有只读"
    "证据复核且可复现）",
    "env_id_tenant_reachability_confirmed": "已确认经混用环境 ID 可达其他租户数据面"
    "（既有只读证据复核且可复现；仅最小读，不批量读取）",
}

# 红线常量（规格 1660 行；写入 artifact 与候选 precondition 语义）。
CLOUD_MINIMAL_READ_RULE: str = (
    "默认只做材料、配置、授权流量和最小读验证，任何写入、批量读取和真实支付必须"
    "审批；云函数调用验证仅限最小读，不触发写型云函数"
)


def screen_cloud_function_observations(
    observations: Iterable[Mapping[str, object]],
    all_branches: bool = True,
    label: str = "cloud_function_testing",
) -> tuple[list[dict], list[dict], list[str]]:
    """云函数测试复核筛选 → (候选行, 分支汇总行, 违例)。"""
    return screen_observations(
        observations,
        CLOUD_FUNCTION_BRANCHES,
        CLOUD_FUNCTION_OBSERVATION_EVIDENCE_MAP,
        CLOUD_FUNCTION_EVIDENCE_KINDS,
        CLOUD_FUNCTION_INSUFFICIENT_KINDS,
        CLOUD_FUNCTION_UPGRADE_RULES,
        all_branches=all_branches,
        label=label,
    )


def validate_cloud_function_candidate(
    row: Mapping[str, object], label: str = "cloud_function_candidate"
) -> list[str]:
    return validate_review_row(
        row,
        CLOUD_FUNCTION_BRANCHES,
        CLOUD_FUNCTION_EVIDENCE_KINDS,
        CLOUD_FUNCTION_INSUFFICIENT_KINDS,
        CLOUD_FUNCTION_UPGRADE_RULES,
        label=label,
    )


def build_cloud_function_review_artifact(
    rows: Iterable[Mapping[str, object]],
    summaries: Iterable[Mapping[str, object]],
    violations: Iterable[str],
    authorization_basis: str,
    updated_at: str,
    substatuses: Mapping[str, str] | None = None,
) -> dict:
    return build_cloud_review_artifact(
        "cloud_function_testing",
        rows,
        summaries,
        violations,
        authorization_basis,
        updated_at,
        substatuses=substatuses,
    )


def validate_cloud_function_review_artifact(
    artifact: Mapping[str, object], label: str = "cloud_function_review_artifact"
) -> list[str]:
    return validate_cloud_review_artifact(
        artifact,
        "cloud_function_testing",
        CLOUD_FUNCTION_BRANCHES,
        CLOUD_FUNCTION_EVIDENCE_KINDS,
        CLOUD_FUNCTION_INSUFFICIENT_KINDS,
        CLOUD_FUNCTION_UPGRADE_RULES,
        label=label,
    )


def _cli() -> int:
    """离线 CLI：观察 JSON 文件 → review artifact JSON（纯文件到文件）。"""
    import argparse
    import json
    from datetime import datetime
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Offline cloud function testing review (no network, no cloud "
        "function invocation; writes/bulk reads/real payments are approval-gated)."
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
    rows, summaries, violations = screen_cloud_function_observations(observations)
    artifact = build_cloud_function_review_artifact(
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
