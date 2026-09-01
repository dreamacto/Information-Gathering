"""WebSocket 复核筛选（实施规格 5.3 websocket_testing 子阶段 + 3.1 模块清单）。

只读离线：沿用统一筛选模式（观察键→证据形态确定性映射→rule_satisfied 升级判定→
8 状态分级），不发任何请求、不建立任何 WebSocket 连接。三类别：origin_validation
（跨 Origin 连接校验）、cleartext_transport（明文 ws 承载敏感通道）、channel_
authentication（通道认证）；WebSocket 消息内注入（sql/ssti 等）归
injection_candidate_screening（路由违例，不双计）。

升级边界（模块 docstring 为记录，规格 2.7/11.3 细微发现处置）：Origin 回显、明文 ws
形态属"观察到的现象"——永不升级（只有确认跨 Origin 连接实际收到数据 / 明文通道实际
承载敏感数据才可升级）；匿名连接收到需认证消息 / 跨用户消息访问确认后可升级。
candidate_summary 复用 injection_candidates.validate_category_summary（三统计概念
分离）；confirmed 五门判定仍归 finding_quality_gate。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.triage import injection_candidates as ic

# websocket 复核类别。
WEBSOCKET_CATEGORIES: tuple[str, ...] = (
    "origin_validation",
    "cleartext_transport",
    "channel_authentication",
)

# websocket 证据形态。
WEBSOCKET_EVIDENCE_KINDS: tuple[str, ...] = (
    "origin_echo",
    "cross_origin_connect",
    "cleartext_ws",
    "cleartext_sensitive_data",
    "unauthenticated_message_access",
    "cross_user_message_access",
    "differential",
    "semantic_anomaly",
)

# "不算漏洞"证据形态：仅形态观察（Origin 回显/明文 ws 存在），未证明边界越过。
WEBSOCKET_INSUFFICIENT_EVIDENCE_KINDS: tuple[str, ...] = ("origin_echo", "cleartext_ws")

# 升级规则：origin_validation 需确认跨 Origin 连接实际建立并收到数据；
# cleartext_transport 需确认明文通道实际承载敏感数据；channel_authentication 需
# 匿名取回需认证消息或跨用户消息访问确认。
WEBSOCKET_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "origin_validation": {"required_any_groups": (("cross_origin_connect",),)},
    "cleartext_transport": {"required_any_groups": (("cleartext_sensitive_data",),)},
    "channel_authentication": {
        "required_any_branches": (
            ("unauthenticated_message_access",),
            ("cross_user_message_access",),
        )
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
WEBSOCKET_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "origin_echo_observed": "origin_echo",
    "cross_origin_connect_confirmed": "cross_origin_connect",
    "cleartext_ws_observed": "cleartext_ws",
    "cleartext_sensitive_data_confirmed": "cleartext_sensitive_data",
    "unauthenticated_message_access_confirmed": "unauthenticated_message_access",
    "cross_user_message_access_confirmed": "cross_user_message_access",
    "differential_observed": "differential",
    "semantic_anomaly_observed": "semantic_anomaly",
}

OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "origin_echo_observed": "观察到服务端回显任意 Origin 头（仅形态观察，永不升级）",
    "cross_origin_connect_confirmed": "已确认跨 Origin 建立连接并实际收到业务数据",
    "cleartext_ws_observed": "观察到明文 ws 通道存在（仅形态观察，永不升级）",
    "cleartext_sensitive_data_confirmed": "已确认明文通道实际承载敏感数据/凭据",
    "unauthenticated_message_access_confirmed": "已确认匿名连接收到需认证的业务消息",
    "cross_user_message_access_confirmed": "已确认以低权限上下文订阅/收到他人消息",
    "differential_observed": "观察到可控差分（仅支持性观察，单独不升级）",
    "semantic_anomaly_observed": "观察到语义异常（仅支持性观察，单独不升级）",
}


def derive_websocket_evidence_kinds(evidence: Mapping[str, object]) -> list[str]:
    """观察键 → websocket 证据形态（按 WEBSOCKET_EVIDENCE_KINDS 顺序，确定性）。"""
    return [kind for key, kind in WEBSOCKET_OBSERVATION_EVIDENCE_MAP.items() if evidence.get(key)]


def grade_websocket_observation(
    category: str, evidence_kinds: Iterable[str], status_hint: str | None = None
) -> str:
    """websocket 观察分级：升级证据满足 → candidate；否则 signal。status_hint 尊重人工判定。"""
    if status_hint in ic.CANDIDATE_STATUS_VALUES:
        return status_hint
    rule = WEBSOCKET_UPGRADE_RULES.get(category)
    if rule is None:
        return "signal"
    satisfied, _ = ic.rule_satisfied(
        rule, evidence_kinds, WEBSOCKET_EVIDENCE_KINDS, WEBSOCKET_INSUFFICIENT_EVIDENCE_KINDS
    )
    return "candidate" if satisfied else "signal"


def validate_websocket_candidate(
    candidate: Mapping[str, object], label: str = "websocket_candidate"
) -> list[str]:
    """websocket 候选行校验：8 状态 + 证据形态 + 升级规则（复用 injection_candidates 引擎）。"""
    violations: list[str] = []
    if not isinstance(candidate, Mapping):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "category", "status", "evidence_kinds", "source"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    category = str(candidate.get("category") or "")
    if category and category not in WEBSOCKET_CATEGORIES:
        violations.append(
            f"{label}.category 非法: {category!r}（允许值 {list(WEBSOCKET_CATEGORIES)}）"
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
            unknown = sorted({k for k in kind_list if k not in WEBSOCKET_EVIDENCE_KINDS})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if status in ("candidate", "confirmed"):
                satisfied, why = ic.rule_satisfied(
                    WEBSOCKET_UPGRADE_RULES.get(category) or {},
                    kind_list,
                    WEBSOCKET_EVIDENCE_KINDS,
                    WEBSOCKET_INSUFFICIENT_EVIDENCE_KINDS,
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
        str(observation.get("channel") or "").strip(),
        str(observation.get("input_location") or "").strip(),
        str(observation.get("parameter_name") or "").strip(),
    )
    return " ".join(p for p in parts if p)


def screen_websocket_observations(
    observations: Iterable[Mapping[str, object]],
    all_categories: bool = True,
    label: str = "websocket_review",
) -> tuple[list[dict], list[dict], list[str]]:
    """websocket 复核筛选 → (候选行, 类别汇总行, 违例)。

    观察必需键：category（本域三类之一）、applicability；可选：
    observation_schema_version（缺失按当前版本，显式不符记违例）、endpoint/channel/
    input_location/parameter_name/source/evidence/evidence_ref/reason/precondition/
    status_hint。注入类别观察记路由违例（归 injection_candidate_screening，不双计）。
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
                "（WebSocket 消息内注入归 injection_candidate_screening，不双计）"
            )
            continue
        if category not in WEBSOCKET_CATEGORIES:
            violations.append(
                f"{label}: 第 {index} 条观察 category 非法 {category!r}"
                f"（允许值 {list(WEBSOCKET_CATEGORIES)}）"
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
        kinds = derive_websocket_evidence_kinds(observation.get("evidence") or {})
        status = grade_websocket_observation(
            category, kinds, str(observation.get("status_hint") or "") or None
        )
        source = _observation_source(observation)
        if not source:
            violations.append(
                f"{label}: 第 {index} 条观察缺少来源（source 或 endpoint/parameter_name 均为空）"
            )
        row = {
            "candidate_id": f"ws-{index:04d}",
            "category": category,
            "status": status,
            "evidence_kinds": kinds,
            "source": source,
            "evidence_ref": str(observation.get("evidence_ref") or ""),
            "precondition": str(observation.get("precondition") or ""),
            "reason": reason,
        }
        rows.append(row)
        violations += validate_websocket_candidate(row, label=f"{label}[{row['candidate_id']}]")

    categories = (
        list(WEBSOCKET_CATEGORIES)
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
            summaries[-1], label=f"{label}.summary[{category}]", categories=WEBSOCKET_CATEGORIES
        )
    return rows, summaries, violations
