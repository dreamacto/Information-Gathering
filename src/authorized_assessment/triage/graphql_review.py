"""GraphQL 复核筛选（实施规格 5.3 graphql_testing 子阶段 + 3.1 模块清单）。

只读离线：沿用 Batch 6 统一筛选模式（观察键→证据形态确定性映射→rule_satisfied
升级判定→8 状态分级），不发任何请求、不执行 introspection/操作查询。类别汇总行
三统计概念分离，复用 injection_candidates.validate_category_summary（categories=
本域四类）与 rule_satisfied（单一升级引擎）。

升级边界（契约 never_upgrade_rule，规格 11.3 细微发现处置）：introspection 开启、
GraphiQL 暴露、schema 文件可见、错误字段建议属"公开文档类"线索——永不升级，
只能得 signal（signal 不是漏洞）；只有确认越过授权边界（跨用户对象访问、匿名
取回需认证数据、受限操作实际执行成功）才可升级 candidate。GraphQL 面内发现的
注入类观察（sql/ssti 等）归 injection_candidate_screening，本域声明注入类别记
路由违例（不双计，契约 routing_rule）。

confirmed 的完整五门判定仍归 finding_quality_gate；本模块只做候选层分级校验。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.triage import injection_candidates as ic

# graphql 复核类别（契约 review_categories 同源）。
GRAPHQL_CATEGORIES: tuple[str, ...] = (
    "introspection_exposure",
    "field_suggestion",
    "object_authorization",
    "operation_authorization",
)

# graphql 证据形态（契约 evidence_kinds 同源）。
GRAPHQL_EVIDENCE_KINDS: tuple[str, ...] = (
    "introspection_enabled",
    "graphiql_exposed",
    "schema_file_visible",
    "field_suggestion_seen",
    "cross_user_object_access",
    "unauthenticated_data_access",
    "operation_allowed",
    "differential",
    "semantic_anomaly",
)

# "不算漏洞"证据形态（规格 11.3：公开文档类/错误提示类线索永不升级）。
GRAPHQL_INSUFFICIENT_EVIDENCE_KINDS: tuple[str, ...] = (
    "introspection_enabled",
    "graphiql_exposed",
    "schema_file_visible",
    "field_suggestion_seen",
)

# 升级规则：只给两个授权边界类别。不在本表 = 该类别永不升级（契约 never_upgrade_rule）。
# object_authorization：跨用户对象访问确认，或匿名取回需认证数据确认（差分/语义异常
# 仅是支持性观察，单独不满足——用户访问自己的对象不是漏洞，规格 2.7/11.3）。
# operation_authorization：受限操作实际执行成功确认。
GRAPHQL_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "object_authorization": {
        "required_any_branches": (
            ("cross_user_object_access",),
            ("unauthenticated_data_access",),
        )
    },
    "operation_authorization": {"required_any_groups": (("operation_allowed",),)},
}

# v1 观察键 → 证据形态（确定性映射；键名集合版本化演进同 OBSERVATION_SCHEMA_VERSION）。
GRAPHQL_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "introspection_enabled_observed": "introspection_enabled",
    "graphiql_exposed_observed": "graphiql_exposed",
    "schema_file_visible_observed": "schema_file_visible",
    "field_suggestion_observed": "field_suggestion_seen",
    "cross_user_object_access_confirmed": "cross_user_object_access",
    "unauthenticated_data_access_confirmed": "unauthenticated_data_access",
    "operation_allowed_confirmed": "operation_allowed",
    "differential_observed": "differential",
    "semantic_anomaly_observed": "semantic_anomaly",
}

OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "introspection_enabled_observed": "观察到 introspection 开启（公开文档类线索，永不升级）",
    "graphiql_exposed_observed": "观察到 GraphiQL/playground 暴露（公开文档类线索，永不升级）",
    "schema_file_visible_observed": "观察到 schema 文件/下载可见（公开文档类线索，永不升级）",
    "field_suggestion_observed": "观察到错误信息建议字段名（线索，永不升级）",
    "cross_user_object_access_confirmed": "已确认以低权限上下文访问他人对象成功且可复现",
    "unauthenticated_data_access_confirmed": "已确认匿名上下文取回需认证数据且可复现",
    "operation_allowed_confirmed": "已确认受角色限制的操作在无权上下文实际执行成功",
    "differential_observed": "观察到可控差分（仅支持性观察，单独不升级）",
    "semantic_anomaly_observed": "观察到语义异常（仅支持性观察，单独不升级）",
}


def derive_graphql_evidence_kinds(evidence: Mapping[str, object]) -> list[str]:
    """观察键 → graphql 证据形态（按 GRAPHQL_EVIDENCE_KINDS 顺序，确定性）。"""
    return [kind for key, kind in GRAPHQL_OBSERVATION_EVIDENCE_MAP.items() if evidence.get(key)]


def grade_graphql_observation(
    category: str, evidence_kinds: Iterable[str], status_hint: str | None = None
) -> str:
    """graphql 观察分级：升级证据满足 → candidate；否则 signal。status_hint 尊重人工判定。"""
    if status_hint in ic.CANDIDATE_STATUS_VALUES:
        return status_hint
    rule = GRAPHQL_UPGRADE_RULES.get(category)
    if rule is None:
        return "signal"
    satisfied, _ = ic.rule_satisfied(
        rule, evidence_kinds, GRAPHQL_EVIDENCE_KINDS, GRAPHQL_INSUFFICIENT_EVIDENCE_KINDS
    )
    return "candidate" if satisfied else "signal"


def validate_graphql_candidate(candidate: Mapping[str, object], label: str = "graphql_candidate") -> list[str]:
    """graphql 候选行校验：8 状态 + 证据形态 + 升级规则（复用 injection_candidates 引擎）。"""
    violations: list[str] = []
    if not isinstance(candidate, Mapping):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "category", "status", "evidence_kinds", "source"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    category = str(candidate.get("category") or "")
    if category and category not in GRAPHQL_CATEGORIES:
        violations.append(
            f"{label}.category 非法: {category!r}（允许值 {list(GRAPHQL_CATEGORIES)}）"
        )
    status = str(candidate.get("status") or "")
    if status and status not in ic.CANDIDATE_STATUS_VALUES:
        violations.append(
            f"{label}.status 非法: {status!r}（允许值 {list(ic.CANDIDATE_STATUS_VALUES)}）"
        )
    kinds = candidate.get("evidence_kinds")
    if kinds is not None:
        if not isinstance(kinds, (list, tuple)):
            violations.append(f"{label}.evidence_kinds 必须为列表")
        else:
            kind_list = [str(k) for k in kinds]
            if not kind_list:
                violations.append(f"{label}.evidence_kinds 不能为空")
            unknown = sorted({k for k in kind_list if k not in GRAPHQL_EVIDENCE_KINDS})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if status in ("candidate", "confirmed"):
                rule = GRAPHQL_UPGRADE_RULES.get(category)
                if rule is None:
                    violations.append(
                        f"{label}: category={category} 永不升级（公开文档类线索，契约 never_upgrade_rule），"
                        "不得标记 candidate/confirmed"
                    )
                else:
                    satisfied, why = ic.rule_satisfied(
                        rule, kind_list, GRAPHQL_EVIDENCE_KINDS, GRAPHQL_INSUFFICIENT_EVIDENCE_KINDS
                    )
                    if not satisfied:
                        violations.append(f"{label}: status={status} 但升级证据不满足——{why}")
    if status in ("candidate", "confirmed", "needs_manual_validation") and not str(
        candidate.get("evidence_ref") or ""
    ).strip():
        violations.append(f"{label}: status={status} 但 evidence_ref 为空（候选必须可证明）")
    return violations


def _observation_source(observation: Mapping[str, object]) -> str:
    explicit = str(observation.get("source") or "").strip()
    if explicit:
        return explicit
    parts = (
        str(observation.get("endpoint") or "").strip(),
        str(observation.get("operation_name") or "").strip(),
        str(observation.get("input_location") or "").strip(),
        str(observation.get("parameter_name") or "").strip(),
    )
    return " ".join(p for p in parts if p)


def screen_graphql_observations(
    observations: Iterable[Mapping[str, object]],
    all_categories: bool = True,
    label: str = "graphql_review",
) -> tuple[list[dict], list[dict], list[str]]:
    """graphql 复核筛选 → (候选行, 类别汇总行, 违例)。

    观察必需键：category（本域四类之一）、applicability（applicable/not_applicable/unknown）；
    可选：observation_schema_version（缺失按当前版本，显式不符记违例）、
    endpoint/operation_name/input_location/parameter_name/source/evidence/evidence_ref/
    reason/precondition/status_hint。

    路由规则（契约 routing_rule）：category 属注入域 15 类时记路由违例并跳过
    （归 injection_candidate_screening，不双计）；其它未知类别记非法违例。
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
        category = str(observation.get("category") or "")
        if category in ic.INJECTION_CATEGORIES:
            violations.append(
                f"{label}: 第 {index} 条观察 category={category!r} 属注入域"
                "（GraphQL 面内注入归 injection_candidate_screening，契约 routing_rule 不双计）"
            )
            continue
        if category not in GRAPHQL_CATEGORIES:
            violations.append(
                f"{label}: 第 {index} 条观察 category 非法 {category!r}"
                f"（允许值 {list(GRAPHQL_CATEGORIES)}）"
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
            na_counts[category] = na_counts.get(category, 0) + 1
            if reason:
                na_reasons.setdefault(category, []).append(reason)
            continue
        if applicability == "applicable":
            applicable_counts_acc[category] = applicable_counts_acc.get(category, 0) + 1
        else:
            unknown_counts_acc[category] = unknown_counts_acc.get(category, 0) + 1
        kinds = derive_graphql_evidence_kinds(observation.get("evidence") or {})
        status = grade_graphql_observation(
            category, kinds, str(observation.get("status_hint") or "") or None
        )
        source = _observation_source(observation)
        if not source:
            violations.append(
                f"{label}: 第 {index} 条观察缺少来源（source 或 endpoint/parameter_name 均为空，"
                "契约 observation_schema.source_required）"
            )
        row = {
            "candidate_id": f"gql-{index:04d}",
            "category": category,
            "status": status,
            "evidence_kinds": kinds,
            "source": source,
            "evidence_ref": str(observation.get("evidence_ref") or ""),
            "precondition": str(observation.get("precondition") or ""),
            "reason": reason,
        }
        rows.append(row)
        violations += validate_graphql_candidate(row, label=f"{label}[{row['candidate_id']}]")

    categories = (
        list(GRAPHQL_CATEGORIES)
        if all_categories
        else sorted(
            {str(r["category"]) for r in rows}
            | set(na_counts)
            | set(applicable_counts_acc)
            | set(unknown_counts_acc)
        )
    )
    summaries: list[dict] = []
    for category in categories:
        cat_rows = [r for r in rows if r["category"] == category]
        status_counts = {s: 0 for s in ic.CANDIDATE_STATUS_VALUES}
        for r in cat_rows:
            status_counts[r["status"]] += 1
        applicability_counts = {
            "applicable": applicable_counts_acc.get(category, 0),
            "not_applicable": na_counts.get(category, 0),
            "unknown": unknown_counts_acc.get(category, 0),
        }
        tested_count = sum(status_counts[s] for s in ic.DEFINITIVE_RESULT_STATUSES)
        category_status = ic.aggregate_category_status(
            [r["status"] for r in cat_rows], na_counts.get(category, 0) > 0
        )
        reasons = [str(r.get("reason") or "") for r in cat_rows if r.get("reason")]
        if na_reasons.get(category):
            reasons += na_reasons[category]
        summaries.append(
            {
                "category": category,
                "category_status": category_status,
                "applicability_counts": applicability_counts,
                "status_counts": status_counts,
                "tested_count": tested_count,
                "reason": "; ".join(reasons[:1]) if reasons else "本次筛选无该类别升级观察",
                "source": next((str(r["source"]) for r in cat_rows if r.get("source")), ""),
                "precondition": next(
                    (str(r["precondition"]) for r in cat_rows if r.get("precondition")), ""
                ),
            }
        )
        violations += ic.validate_category_summary(
            summaries[-1], label=f"{label}.summary[{category}]", categories=GRAPHQL_CATEGORIES
        )
    return rows, summaries, violations
