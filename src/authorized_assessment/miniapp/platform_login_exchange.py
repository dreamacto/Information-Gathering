"""平台登录交换复核域（实施规格 6.5 第一模块 1588 行 + 6.2 认证拆分 1503-1519
行，Batch 10）+ miniapp_auth 三模块共享引擎。

只读离线：沿用统一筛选模式（观察键→证据形态确定性映射→rule_satisfied 升级判定→
8 状态分级），不发任何请求、不创建/滥用登录凭证（规格 1610 行红线："仅在有人工
提供的授权材料或本地流量时分析，不自动创建或滥用登录凭证"）。观察输入为复核会话
从操作员提供的授权材料或本地流量（HAR/抓包导出/客户端本地文件）提炼的结构化记录。

五分支（与 contracts/miniapp_auth_schema.json phases.platform_login_exchange.branches
同源；规格 6.5 覆盖清单：wx.login() code 一次性和过期；AppID 绑定；session_key 是否
只由服务端保管；OpenID 是否被错误当成授权依据）：
- login_code_one_time：登录 code 一次性（同一 code 二次兑换）；
- login_code_expiry：登录 code 过期（过期 code 仍可兑换）；
- appid_binding：AppID 绑定（跨 AppID 交换/绑定缺失）；
- session_key_custody：session_key 保管（是否只由服务端保管）；
- openid_authorization_basis：OpenID 被错误当成授权依据。

升级边界（实现定义供操作者复核）：仅对应分支的确认证据（*_confirmed，来自既有
只读证据的复核判定且可复现）可升级 candidate；"请求被接受/TTL 或绑定标记存在/
客户端可见线索"等形态与支持性观察永不升级（signal 不是漏洞）。OpenID/AppID 等
公开平台标识不是授权依据。confirmed 五门判定仍归 finding_quality_gate；本模块只
做候选层分级校验。

共享引擎：本模块同时承载 miniapp_auth 三模块（platform_login_exchange/
session_token_lifecycle/signature_replay_review）共享的行校验/分支汇总/筛选/
artifact 构建/校验实现（单一实现，避免三份复制漂移），其余两模块复用并在各自
模块内只定义分支/证据形态/映射/升级规则常量。skill 脚本常量（init/audit）与
契约的一致性由 tests/test_xcx_auth_phase_split.py 锁定；模块常量与契约的一致性
由 tests/test_miniapp_auth_lifecycle.py 锁定。

产物形状契约：contracts/miniapp_auth_schema.json artifact_fields（12 键 JSON，
rows=统一筛选候选行，summaries=分支级汇总 branch_status 六值——由
injection_candidates.aggregate_category_status 单一引擎聚合，分支汇总校验经
category 键适配复用 validate_category_summary 全语义）。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.triage import injection_candidates as ic

# 契约标识与版本（miniapp_auth_schema.schema_version/contract 同源）。
MINIAPP_AUTH_CONTRACT = "miniapp_auth_schema"
MINIAPP_AUTH_SCHEMA_VERSION = "1.0"

# 认证拆分三 phase 与产物路径（规格 6.2 1513-1519 行 + 6.5 产物 1591-1593 行；
# 与 xcx skill init/audit 常量、miniapp_auth_schema.phases 三方同源）。
AUTH_PHASES: tuple[str, ...] = (
    "platform_login_exchange",
    "session_token_lifecycle",
    "signature_replay",
)
AUTH_REVIEW_ARTIFACTS: dict[str, str] = {
    "platform_login_exchange": "artifacts/miniapp/auth/platform-login-review.json",
    "session_token_lifecycle": "artifacts/miniapp/auth/session-lifecycle-review.json",
    "signature_replay": "artifacts/miniapp/auth/signature-replay-review.json",
}

# 共享形状契约（miniapp_auth_schema.artifact_fields 同源；row 与 batch9 候选行
# 同形状、category→branch 改名）。
AUTH_REVIEW_ROW_FIELDS: tuple[str, ...] = (
    "row_id",
    "branch",
    "status",
    "evidence_kinds",
    "source",
    "evidence_ref",
    "precondition",
    "reason",
)
AUTH_REVIEW_SUMMARY_FIELDS: tuple[str, ...] = (
    "branch",
    "branch_status",
    "applicability_counts",
    "status_counts",
    "tested_count",
    "reason",
    "source",
    "precondition",
)
AUTH_REVIEW_ARTIFACT_KEYS: tuple[str, ...] = (
    "schema_version",
    "contract",
    "phase",
    "observation_schema_version",
    "row_fields",
    "summary_fields",
    "substatuses",
    "rows",
    "summaries",
    "violations",
    "authorization_basis",
    "updated_at",
)

# 授权材料来源（artifact.authorization_basis 允许值；skill audit 常量同源）。
AUTHORIZATION_BASIS_VALUES: tuple[str, ...] = (
    "operator_supplied_material",
    "local_traffic",
)

# 红线常量（规格 1610 行；写入 artifact 与候选 precondition 语义）。
NO_CREDENTIAL_CREATION_RULE: str = (
    "仅在有人工提供的授权材料或本地流量时分析，不自动创建或滥用登录凭证"
)
OPENID_NOT_AUTHORIZATION_RULE: str = (
    "OpenID/AppID 等公开平台标识不是授权依据，不得作为授权判定"
)


# ---------------------------------------------------------------------------
# 共享引擎（三模块复用；分支常量由调用方传入）
# ---------------------------------------------------------------------------

def derive_auth_evidence_kinds(
    evidence: Mapping[str, object], observation_evidence_map: Mapping[str, str]
) -> list[str]:
    """观察键 → 证据形态（按映射表顺序，确定性；与 batch8_0/batch9 约定一致）。"""
    return [
        kind
        for key, kind in observation_evidence_map.items()
        if evidence.get(key)
    ]


def grade_auth_observation(
    branch: str,
    evidence_kinds: Iterable[str],
    upgrade_rules: Mapping[str, Mapping[str, object]],
    evidence_kinds_all: Iterable[str],
    insufficient_kinds: Iterable[str],
    status_hint: str | None = None,
) -> str:
    """认证观察分级：确认形态满足 → candidate；否则 signal。status_hint 尊重人工
    判定（8 状态合法值原样返回）。"""
    if status_hint in ic.CANDIDATE_STATUS_VALUES:
        return status_hint
    rule = upgrade_rules.get(branch)
    if rule is None:
        return "signal"
    satisfied, _ = ic.rule_satisfied(
        rule, list(evidence_kinds), list(evidence_kinds_all), list(insufficient_kinds)
    )
    return "candidate" if satisfied else "signal"


def validate_auth_review_row(
    row: Mapping[str, object],
    branches: Iterable[str],
    evidence_kinds_all: Iterable[str],
    insufficient_kinds: Iterable[str],
    upgrade_rules: Mapping[str, Mapping[str, object]],
    label: str = "auth_review_row",
) -> list[str]:
    """认证候选行校验：8 状态 + 分支枚举 + 证据形态 + 升级规则（复用 ic 引擎）。"""
    violations: list[str] = []
    if not isinstance(row, Mapping):
        return [f"{label}: 行必须是键值映射"]
    for field in AUTH_REVIEW_ROW_FIELDS:
        if field not in row:
            violations.append(f"{label}: 缺少必需字段 {field}")
    branch = str(row.get("branch") or "")
    branch_list = list(branches)
    if branch and branch not in branch_list:
        violations.append(f"{label}.branch 非法: {branch!r}（允许值 {branch_list}）")
    status = str(row.get("status") or "")
    if status and status not in ic.CANDIDATE_STATUS_VALUES:
        violations.append(
            f"{label}.status 非法: {status!r}（允许值 {list(ic.CANDIDATE_STATUS_VALUES)}）"
        )
    kinds = row.get("evidence_kinds")
    if kinds is not None:
        if not isinstance(kinds, (list, tuple)):
            violations.append(f"{label}.evidence_kinds 必须为列表")
        else:
            kind_list = [str(k) for k in kinds]
            if not kind_list:
                violations.append(f"{label}.evidence_kinds 不能为空（signal 也需记录观察形态）")
            unknown = sorted({k for k in kind_list if k not in set(evidence_kinds_all)})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if len(set(kind_list)) != len(kind_list):
                violations.append(f"{label}.evidence_kinds 存在重复项")
            if status in ("candidate", "confirmed"):
                rule = upgrade_rules.get(branch)
                if rule is None:
                    violations.append(
                        f"{label}: branch={branch} 永不升级（契约 never_upgrade_rule）"
                    )
                else:
                    satisfied, why = ic.rule_satisfied(
                        rule,
                        kind_list,
                        evidence_kinds_all,
                        insufficient_kinds,
                    )
                    if not satisfied:
                        violations.append(
                            f"{label}: status={status} 但升级证据不满足——{why}"
                        )
    if status in ("candidate", "confirmed", "needs_manual_validation") and not str(
        row.get("evidence_ref") or ""
    ).strip():
        violations.append(f"{label}: status={status} 但 evidence_ref 为空（候选必须可证明）")
    return violations


def validate_auth_branch_summary(
    summary: Mapping[str, object],
    branches: Iterable[str],
    label: str = "auth_branch_summary",
) -> list[str]:
    """分支汇总行校验：经 category 键适配复用 ic.validate_category_summary 全语义
    （三统计概念分离/tested_count 一致性/candidate>0 需 source+precondition/
    not_applicable 需 reason 且无计数）。"""
    if not isinstance(summary, Mapping):
        return [f"{label}: 汇总行必须是键值映射"]
    mapped = {
        "category": summary.get("branch"),
        "category_status": summary.get("branch_status"),
        "applicability_counts": summary.get("applicability_counts"),
        "status_counts": summary.get("status_counts"),
        "tested_count": summary.get("tested_count"),
        "reason": summary.get("reason"),
        "source": summary.get("source"),
        "precondition": summary.get("precondition"),
    }
    return ic.validate_category_summary(mapped, label=label, categories=list(branches))


def screen_auth_observations(
    observations: Iterable[Mapping[str, object]],
    branches: tuple[str, ...],
    observation_evidence_map: Mapping[str, str],
    evidence_kinds_all: tuple[str, ...],
    insufficient_kinds: tuple[str, ...],
    upgrade_rules: Mapping[str, Mapping[str, object]],
    all_branches: bool = True,
    label: str = "auth_review_screening",
) -> tuple[list[dict], list[dict], list[str]]:
    """认证观察筛选 → (候选行, 分支汇总行, 违例)。

    观察必需键：branch（本域分支之一）、applicability；可选：
    observation_schema_version（缺失按当前版本，显式不符记违例）、endpoint/
    object_ref/source/evidence/evidence_ref/reason/precondition/status_hint。
    """
    rows: list[dict] = []
    na_counts: dict[str, int] = {}
    na_reasons: dict[str, list[str]] = {}
    applicable_counts_acc: dict[str, int] = {}
    unknown_counts_acc: dict[str, int] = {}
    violations: list[str] = []
    for index, observation in enumerate(observations, start=1):
        if not isinstance(observation, Mapping):
            violations.append(f"{label}: 第 {index} 条观察必须是键值映射")
            continue
        obs_version = observation.get("observation_schema_version")
        if obs_version is not None and str(obs_version) != ic.OBSERVATION_SCHEMA_VERSION:
            violations.append(
                f"{label}: 第 {index} 条观察 observation_schema_version={obs_version!r} "
                f"与当前版本 {ic.OBSERVATION_SCHEMA_VERSION!r} 不符"
            )
        branch = str(observation.get("branch") or "")
        if branch not in branches:
            violations.append(
                f"{label}: 第 {index} 条观察 branch 非法 {branch!r}（允许值 {list(branches)}）"
            )
            continue
        applicability = str(observation.get("applicability") or "unknown")
        if applicability not in ic.APPLICABLE_VALUES:
            violations.append(
                f"{label}: 第 {index} 条观察 applicability 非法 {applicability!r}"
                f"（允许值 {list(ic.APPLICABLE_VALUES)}）"
            )
            continue
        reason = str(observation.get("reason") or "").strip()
        if applicability == "not_applicable":
            na_counts[branch] = na_counts.get(branch, 0) + 1
            if reason:
                na_reasons.setdefault(branch, []).append(reason)
            else:
                violations.append(
                    f"{label}: 第 {index} 条观察 branch={branch} not_applicable 但 reason 为空"
                    "（没有理由的 not_applicable 是违例，coverage_substatus_schema 不变量）"
                )
            continue
        if applicability == "applicable":
            applicable_counts_acc[branch] = applicable_counts_acc.get(branch, 0) + 1
        else:
            unknown_counts_acc[branch] = unknown_counts_acc.get(branch, 0) + 1
        kinds = derive_auth_evidence_kinds(observation.get("evidence") or {}, observation_evidence_map)
        status = grade_auth_observation(
            branch,
            kinds,
            upgrade_rules,
            evidence_kinds_all,
            insufficient_kinds,
            str(observation.get("status_hint") or "") or None,
        )
        source = str(observation.get("source") or "").strip()
        if not source:
            violations.append(f"{label}: 第 {index} 条观察缺少来源 source")
        row = {
            "row_id": f"{label.split('.')[-1]}-{index:04d}",
            "branch": branch,
            "status": status,
            "evidence_kinds": kinds,
            "source": source,
            "evidence_ref": str(observation.get("evidence_ref") or ""),
            "precondition": str(observation.get("precondition") or ""),
            "reason": reason,
        }
        rows.append(row)
        violations += validate_auth_review_row(
            row,
            branches,
            evidence_kinds_all,
            insufficient_kinds,
            upgrade_rules,
            label=f"{label}[{row['row_id']}]",
        )

    summary_branches = (
        list(branches)
        if all_branches
        else sorted(
            {str(r["branch"]) for r in rows}
            | set(na_counts)
            | set(applicable_counts_acc)
            | set(unknown_counts_acc)
        )
    )
    summaries: list[dict] = []
    for branch in summary_branches:
        branch_rows = [r for r in rows if r["branch"] == branch]
        status_counts = {s: 0 for s in ic.CANDIDATE_STATUS_VALUES}
        for r in branch_rows:
            status_counts[r["status"]] += 1
        applicability_counts = {
            "applicable": applicable_counts_acc.get(branch, 0),
            "not_applicable": na_counts.get(branch, 0),
            "unknown": unknown_counts_acc.get(branch, 0),
        }
        tested_count = sum(status_counts[s] for s in ic.DEFINITIVE_RESULT_STATUSES)
        branch_status = ic.aggregate_category_status(
            [r["status"] for r in branch_rows], na_counts.get(branch, 0) > 0
        )
        reasons = [str(r.get("reason") or "") for r in branch_rows if r.get("reason")]
        if na_reasons.get(branch):
            reasons += na_reasons[branch]
        summaries.append(
            {
                "branch": branch,
                "branch_status": branch_status,
                "applicability_counts": applicability_counts,
                "status_counts": status_counts,
                "tested_count": tested_count,
                "reason": "; ".join(reasons[:1]) if reasons else "本次筛选无该分支升级观察",
                "source": next((str(r["source"]) for r in branch_rows if r.get("source")), ""),
                "precondition": next(
                    (str(r["precondition"]) for r in branch_rows if r.get("precondition")), ""
                ),
            }
        )
        violations += validate_auth_branch_summary(
            summaries[-1], branches, label=f"{label}.summary[{branch}]"
        )
    return rows, summaries, violations


def derive_substatuses(summaries: Iterable[Mapping[str, object]]) -> dict[str, str]:
    """分支汇总 → phase substatuses 投影（branch_status 六值；approval_required 仅
    由复核显式设置，聚合不产生）。"""
    return {str(s["branch"]): str(s["branch_status"]) for s in summaries}


def build_auth_review_artifact(
    phase: str,
    rows: Iterable[Mapping[str, object]],
    summaries: Iterable[Mapping[str, object]],
    violations: Iterable[str],
    authorization_basis: str,
    updated_at: str,
    substatuses: Mapping[str, str] | None = None,
) -> dict:
    """契约形状 artifact dict（12 键，miniapp_auth_schema.artifact_fields 同源）。"""
    summary_list = [dict(s) for s in summaries]
    return {
        "schema_version": MINIAPP_AUTH_SCHEMA_VERSION,
        "contract": MINIAPP_AUTH_CONTRACT,
        "phase": phase,
        "observation_schema_version": ic.OBSERVATION_SCHEMA_VERSION,
        "row_fields": list(AUTH_REVIEW_ROW_FIELDS),
        "summary_fields": list(AUTH_REVIEW_SUMMARY_FIELDS),
        "substatuses": dict(substatuses) if substatuses is not None else derive_substatuses(summary_list),
        "rows": [dict(r) for r in rows],
        "summaries": summary_list,
        "violations": list(violations),
        "authorization_basis": authorization_basis,
        "updated_at": updated_at,
    }


def validate_auth_review_artifact(
    artifact: Mapping[str, object],
    phase: str,
    branches: tuple[str, ...],
    evidence_kinds_all: tuple[str, ...],
    insufficient_kinds: tuple[str, ...],
    upgrade_rules: Mapping[str, Mapping[str, object]],
    label: str = "auth_review_artifact",
) -> list[str]:
    """契约形状 artifact 校验（与 skill audit 语义一致；模块侧供会话落盘前自检）。"""
    violations: list[str] = []
    if not isinstance(artifact, Mapping):
        return [f"{label}: artifact 必须是键值映射"]
    for key in AUTH_REVIEW_ARTIFACT_KEYS:
        if key not in artifact:
            violations.append(f"{label}: 缺少必需键 {key}")
    if str(artifact.get("contract") or "") != MINIAPP_AUTH_CONTRACT:
        violations.append(f"{label}: contract 必须为 {MINIAPP_AUTH_CONTRACT}")
    if str(artifact.get("phase") or "") != phase:
        violations.append(f"{label}: phase 必须为 {phase}，实际 {artifact.get('phase')!r}")
    if str(artifact.get("schema_version") or "") != MINIAPP_AUTH_SCHEMA_VERSION:
        violations.append(f"{label}: schema_version 必须为 {MINIAPP_AUTH_SCHEMA_VERSION}")
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
            violations += validate_auth_review_row(
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
            violations += validate_auth_branch_summary(
                summary, branches, label=f"{label}.summaries"
            )
    return violations


# ---------------------------------------------------------------------------
# platform_login_exchange 分支常量与筛选入口
# ---------------------------------------------------------------------------

# 五分支（契约 phases.platform_login_exchange.branches 同源）。
PLATFORM_LOGIN_BRANCHES: tuple[str, ...] = (
    "login_code_one_time",
    "login_code_expiry",
    "appid_binding",
    "session_key_custody",
    "openid_authorization_basis",
)

# 证据形态（13：8 形态/支持性永不升级 + 5 确认形态与分支一一对应）。
PLATFORM_LOGIN_EVIDENCE_KINDS: tuple[str, ...] = (
    "code_reuse_accepted_observed",
    "code_single_use_marker_observed",
    "expired_code_accepted_observed",
    "code_ttl_marker_observed",
    "appid_mismatch_observed",
    "binding_check_marker_observed",
    "session_key_client_visible_observed",
    "openid_as_authz_observed",
    "login_code_replay_confirmed",
    "expired_code_exchange_confirmed",
    "cross_appid_exchange_confirmed",
    "session_key_transmitted_confirmed",
    "openid_authz_bypass_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察，未证明服务端认证边界失效。
PLATFORM_LOGIN_INSUFFICIENT_KINDS: tuple[str, ...] = (
    "code_reuse_accepted_observed",
    "code_single_use_marker_observed",
    "expired_code_accepted_observed",
    "code_ttl_marker_observed",
    "appid_mismatch_observed",
    "binding_check_marker_observed",
    "session_key_client_visible_observed",
    "openid_as_authz_observed",
)

# 升级规则（实现定义，固定语义；确认形态与分支一一对应、不跨分支升级）：
# "确认"语义要求观察来自既有只读证据的复核判定且可复现；禁止为取得确认而真实
# 登录、重放 code 或跨 AppID 兑换（规格红线，precondition 必须留痕）。
PLATFORM_LOGIN_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "login_code_one_time": {"required_any_groups": (("login_code_replay_confirmed",),)},
    "login_code_expiry": {"required_any_groups": (("expired_code_exchange_confirmed",),)},
    "appid_binding": {"required_any_groups": (("cross_appid_exchange_confirmed",),)},
    "session_key_custody": {
        "required_any_groups": (("session_key_transmitted_confirmed",),)
    },
    "openid_authorization_basis": {
        "required_any_groups": (("openid_authz_bypass_confirmed",),)
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
PLATFORM_LOGIN_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "code_reuse_accepted_observed": "code_reuse_accepted_observed",
    "code_single_use_marker_observed": "code_single_use_marker_observed",
    "expired_code_accepted_observed": "expired_code_accepted_observed",
    "code_ttl_marker_observed": "code_ttl_marker_observed",
    "appid_mismatch_observed": "appid_mismatch_observed",
    "binding_check_marker_observed": "binding_check_marker_observed",
    "login_code_replay_confirmed": "login_code_replay_confirmed",
    "expired_code_exchange_confirmed": "expired_code_exchange_confirmed",
    "cross_appid_exchange_confirmed": "cross_appid_exchange_confirmed",
    "session_key_client_visible_observed": "session_key_client_visible_observed",
    "session_key_transmitted_confirmed": "session_key_transmitted_confirmed",
    "openid_as_authz_observed": "openid_as_authz_observed",
    "openid_authz_bypass_confirmed": "openid_authz_bypass_confirmed",
}

PLATFORM_LOGIN_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "code_reuse_accepted_observed": "观察到同一登录 code 的二次兑换请求被服务端接受"
    "（仅形态，不代表边界失效）",
    "code_single_use_marker_observed": "客户端代码/文档显示 code 一次性使用标记"
    "（支持性，正向线索）",
    "expired_code_accepted_observed": "观察到过期 code 兑换请求被接受（仅形态）",
    "code_ttl_marker_observed": "观察到 code TTL/有效期标记（支持性，正向线索）",
    "appid_mismatch_observed": "观察到请求/响应中 AppID 与目标应用不一致线索（仅形态）",
    "binding_check_marker_observed": "观察到服务端 AppID 绑定校验标记（支持性，正向线索）",
    "session_key_client_visible_observed": "观察到 session_key 出现在客户端可见流量/"
    "本地存储线索（仅形态）",
    "session_key_transmitted_confirmed": "已确认 session_key 下发到客户端或由客户端"
    "持有（既有只读证据复核且可复现；不发起真实登录/兑换验证）",
    "openid_as_authz_observed": "观察到 OpenID 被用作服务端授权判定线索（仅形态）",
    "openid_authz_bypass_confirmed": "已确认替换/伪造 OpenID 可获得越权访问（既有只读"
    "证据复核且可复现；不自动创建或滥用登录凭证）",
    "login_code_replay_confirmed": "已确认同一登录 code 可重复兑换出有效会话（既有"
    "只读证据复核且可复现；不重放 code）",
    "expired_code_exchange_confirmed": "已确认过期 code 仍可兑换出有效会话（既有只读"
    "证据复核且可复现）",
    "cross_appid_exchange_confirmed": "已确认跨 AppID 交换可复现（既有只读证据复核且"
    "可复现）",
}

# 补充分支证据形态已并入 PLATFORM_LOGIN_EVIDENCE_KINDS / PLATFORM_LOGIN_INSUFFICIENT_KINDS
# 单表定义（不再拼接）。


def screen_platform_login_observations(
    observations: Iterable[Mapping[str, object]],
    all_branches: bool = True,
    label: str = "platform_login_exchange",
) -> tuple[list[dict], list[dict], list[str]]:
    """平台登录交换复核筛选 → (候选行, 分支汇总行, 违例)。"""
    return screen_auth_observations(
        observations,
        PLATFORM_LOGIN_BRANCHES,
        PLATFORM_LOGIN_OBSERVATION_EVIDENCE_MAP,
        PLATFORM_LOGIN_EVIDENCE_KINDS,
        PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        PLATFORM_LOGIN_UPGRADE_RULES,
        all_branches=all_branches,
        label=label,
    )


def validate_platform_login_candidate(
    row: Mapping[str, object], label: str = "platform_login_candidate"
) -> list[str]:
    return validate_auth_review_row(
        row,
        PLATFORM_LOGIN_BRANCHES,
        PLATFORM_LOGIN_EVIDENCE_KINDS,
        PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        PLATFORM_LOGIN_UPGRADE_RULES,
        label=label,
    )


def build_platform_login_review_artifact(
    rows: Iterable[Mapping[str, object]],
    summaries: Iterable[Mapping[str, object]],
    violations: Iterable[str],
    authorization_basis: str,
    updated_at: str,
    substatuses: Mapping[str, str] | None = None,
) -> dict:
    return build_auth_review_artifact(
        "platform_login_exchange",
        rows,
        summaries,
        violations,
        authorization_basis,
        updated_at,
        substatuses=substatuses,
    )


def _cli() -> int:
    """离线 CLI：观察 JSON 文件 → auth review artifact JSON（纯文件到文件）。"""
    import argparse
    import json
    from datetime import datetime
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Offline platform login exchange review (no network, no credential use)."
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
    rows, summaries, violations = screen_platform_login_observations(observations)
    artifact = build_platform_login_review_artifact(
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
