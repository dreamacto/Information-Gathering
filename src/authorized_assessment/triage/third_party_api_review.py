"""第三方 API 边界只读复核域（实施规格 5.3 第三方 API 小节 1297-1311 行 + 3.1
triage/third_party_api_review 模块清单）。

只读离线：沿用统一筛选模式（观察键→证据形态确定性映射→rule_satisfied 升级判定→
8 状态分级），不发任何请求、不发送 webhook、不重放任何回调。观察输入为复核会话
从既有证据（代码/配置/流量记录/文档）提炼的结构化记录。

四类别（规格四条检查方向）：
- third_party_response_trust：第三方响应是否未经验证直接进入权限/金额/状态决策；
- webhook_origin_validation：callback/webhook 是否校验来源、签名、时间戳和重放；
- asset_scope_hygiene：第三方资产是否被误计入自有目标（scope/资产清单纪律）；
- third_party_data_flow：第三方返回是否导致敏感字段、跳转或权限扩大。

升级边界（实现定义供操作者复核）：仅"确认越过"证据形态可升级 candidate——
unverified_decision_confirmed（未验证第三方值实际进入权限/金额/状态决策）、
webhook_unauthenticated_confirmed（webhook 实际接受无来源/签名/时间戳校验的伪造
回调）、foreign_asset_in_scope_confirmed（第三方资产确认误计自有目标）、
privilege_expansion_confirmed（第三方返回实际导致权限扩大/敏感字段/任意跳转）；
仅"存在第三方调用/webhook 端点存在/文档未见时间戳字段"等形态观察永不升级
（signal 不是漏洞）。confirmed 五门判定仍归 finding_quality_gate。

webhook 四子项（来源/签名/时间戳/重放）归并单类别：升级取"任一子项确认缺失且
伪造回调被实际接受"，四子项缺失的形态线索只作支持性观察（docstring 留痕）。

注入 15 类观察记路由违例（归 injection_candidate_screening，不双计）。
产物 CSV 表头契约：THIRD_PARTY_BOUNDARY_CSV_FIELDS 对应规格明示
artifacts/api/third-party-boundary.csv；落盘接线归后续批次。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.triage import injection_candidates as ic

# 第三方边界复核类别（规格四条检查方向，契约 review_categories 同源）。
THIRD_PARTY_CATEGORIES: tuple[str, ...] = (
    "third_party_response_trust",
    "webhook_origin_validation",
    "asset_scope_hygiene",
    "third_party_data_flow",
)

# 证据形态（14：10 形态/支持性永不升级 + 4 确认越过形态）。
THIRD_PARTY_EVIDENCE_KINDS: tuple[str, ...] = (
    "third_party_call_present",
    "webhook_endpoint_present",
    "timestamp_field_absent",
    "signature_field_absent",
    "allowlist_absent",
    "foreign_domain_reference",
    "redirect_to_third_party",
    "sensitive_field_in_response",
    "differential",
    "semantic_anomaly",
    "unverified_decision_confirmed",
    "webhook_unauthenticated_confirmed",
    "foreign_asset_in_scope_confirmed",
    "privilege_expansion_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察，未证明边界越过。
THIRD_PARTY_INSUFFICIENT_EVIDENCE_KINDS: tuple[str, ...] = (
    "third_party_call_present",
    "webhook_endpoint_present",
    "timestamp_field_absent",
    "signature_field_absent",
    "allowlist_absent",
    "foreign_domain_reference",
    "redirect_to_third_party",
    "sensitive_field_in_response",
    "differential",
    "semantic_anomaly",
)

# 升级规则（实现定义，固定语义；不在本表 = 该类别永不升级）。
THIRD_PARTY_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "third_party_response_trust": {
        "required_any_groups": (("unverified_decision_confirmed",),)
    },
    "webhook_origin_validation": {
        "required_any_groups": (("webhook_unauthenticated_confirmed",),)
    },
    "asset_scope_hygiene": {
        "required_any_groups": (("foreign_asset_in_scope_confirmed",),)
    },
    "third_party_data_flow": {
        "required_any_groups": (("privilege_expansion_confirmed",),)
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
THIRD_PARTY_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "third_party_call_present_observed": "third_party_call_present",
    "webhook_endpoint_present_observed": "webhook_endpoint_present",
    "timestamp_field_absent_observed": "timestamp_field_absent",
    "signature_field_absent_observed": "signature_field_absent",
    "allowlist_absent_observed": "allowlist_absent",
    "foreign_domain_reference_observed": "foreign_domain_reference",
    "redirect_to_third_party_observed": "redirect_to_third_party",
    "sensitive_field_in_response_observed": "sensitive_field_in_response",
    "differential_observed": "differential",
    "semantic_anomaly_observed": "semantic_anomaly",
    "unverified_decision_confirmed": "unverified_decision_confirmed",
    "webhook_unauthenticated_confirmed": "webhook_unauthenticated_confirmed",
    "foreign_asset_in_scope_confirmed": "foreign_asset_in_scope_confirmed",
    "privilege_expansion_confirmed": "privilege_expansion_confirmed",
}

THIRD_PARTY_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "third_party_call_present_observed": "观察到第三方服务调用面（支付/短信/OAuth/地图等——仅形态）",
    "webhook_endpoint_present_observed": "观察到 callback/webhook 端点存在（仅形态）",
    "timestamp_field_absent_observed": "回调处理代码/文档未见时间戳字段（缺失线索，不升级）",
    "signature_field_absent_observed": "回调处理代码/文档未见签名字段（缺失线索，不升级）",
    "allowlist_absent_observed": "回调来源未见白名单/allowlist（缺失线索，不升级）",
    "foreign_domain_reference_observed": "观察到第三方域名引用（形态，支持性）",
    "redirect_to_third_party_observed": "观察到跳转目标可为第三方域（形态，不升级）",
    "sensitive_field_in_response_observed": "第三方响应中出现敏感字段（形态，不升级）",
    "differential_observed": "观察到可控差分（仅支持性观察，单独不升级）",
    "semantic_anomaly_observed": "观察到语义异常（仅支持性观察，单独不升级）",
    "unverified_decision_confirmed": "已确认未验证的第三方值实际进入权限/金额/状态决策且可复现",
    "webhook_unauthenticated_confirmed": "已确认伪造回调（无来源/签名/时间戳校验）被实际接受并产生状态变更",
    "foreign_asset_in_scope_confirmed": "已确认第三方资产被误计入自有授权目标（scope/资产清单事实错误）",
    "privilege_expansion_confirmed": "已确认第三方返回实际导致权限扩大/敏感字段泄露/任意跳转",
}


def derive_third_party_evidence_kinds(evidence: Mapping[str, object]) -> list[str]:
    """观察键 → 第三方边界证据形态（按映射表顺序，确定性）。"""
    return [
        kind for key, kind in THIRD_PARTY_OBSERVATION_EVIDENCE_MAP.items() if evidence.get(key)
    ]


def grade_third_party_observation(
    category: str, evidence_kinds: Iterable[str], status_hint: str | None = None
) -> str:
    """第三方边界观察分级：确认形态满足 → candidate；否则 signal。status_hint 尊重人工判定。"""
    if status_hint in ic.CANDIDATE_STATUS_VALUES:
        return status_hint
    rule = THIRD_PARTY_UPGRADE_RULES.get(category)
    if rule is None:
        return "signal"
    satisfied, _ = ic.rule_satisfied(
        rule,
        evidence_kinds,
        THIRD_PARTY_EVIDENCE_KINDS,
        THIRD_PARTY_INSUFFICIENT_EVIDENCE_KINDS,
    )
    return "candidate" if satisfied else "signal"


def validate_third_party_candidate(
    candidate: Mapping[str, object], label: str = "third_party_candidate"
) -> list[str]:
    """第三方边界候选行校验：8 状态 + 证据形态 + 升级规则（复用 injection_candidates 引擎）。"""
    violations: list[str] = []
    if not isinstance(candidate, Mapping):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "category", "status", "evidence_kinds", "source"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    category = str(candidate.get("category") or "")
    if category and category not in THIRD_PARTY_CATEGORIES:
        violations.append(
            f"{label}.category 非法: {category!r}（允许值 {list(THIRD_PARTY_CATEGORIES)}）"
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
            unknown = sorted({k for k in kind_list if k not in THIRD_PARTY_EVIDENCE_KINDS})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if status in ("candidate", "confirmed"):
                rule = THIRD_PARTY_UPGRADE_RULES.get(category)
                if rule is None:
                    violations.append(
                        f"{label}: category={category} 永不升级（契约 never_upgrade_rule）"
                    )
                else:
                    satisfied, why = ic.rule_satisfied(
                        rule,
                        kind_list,
                        THIRD_PARTY_EVIDENCE_KINDS,
                        THIRD_PARTY_INSUFFICIENT_EVIDENCE_KINDS,
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
        str(observation.get("third_party") or "").strip(),
        str(observation.get("parameter_name") or "").strip(),
    )
    return " ".join(p for p in parts if p)


def screen_third_party_observations(
    observations: Iterable[Mapping[str, object]],
    all_categories: bool = True,
    label: str = "third_party_api_review",
) -> tuple[list[dict], list[dict], list[str]]:
    """第三方边界复核筛选 → (候选行, 类别汇总行, 违例)。

    观察必需键：category（本域四类之一）、applicability；可选：
    observation_schema_version（缺失按当前版本，显式不符记违例）、endpoint/
    third_party/parameter_name/source/evidence/evidence_ref/reason/precondition/
    status_hint。注入类别观察记路由违例（归 injection_candidate_screening，
    不双计）。
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
                "（归 injection_candidate_screening，不双计）"
            )
            continue
        if category not in THIRD_PARTY_CATEGORIES:
            violations.append(
                f"{label}: 第 {index} 条观察 category 非法 {category!r}"
                f"（允许值 {list(THIRD_PARTY_CATEGORIES)}）"
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
        kinds = derive_third_party_evidence_kinds(observation.get("evidence") or {})
        status = grade_third_party_observation(
            category, kinds, str(observation.get("status_hint") or "") or None
        )
        source = _observation_source(observation)
        if not source:
            violations.append(
                f"{label}: 第 {index} 条观察缺少来源（source 或 endpoint/third_party 均为空）"
            )
        row = {
            "candidate_id": f"tp-{index:04d}",
            "category": category,
            "status": status,
            "evidence_kinds": kinds,
            "source": source,
            "evidence_ref": str(observation.get("evidence_ref") or ""),
            "precondition": str(observation.get("precondition") or ""),
            "reason": reason,
        }
        rows.append(row)
        violations += validate_third_party_candidate(
            row, label=f"{label}[{row['candidate_id']}]"
        )

    categories = (
        list(THIRD_PARTY_CATEGORIES)
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
            summaries[-1],
            label=f"{label}.summary[{category}]",
            categories=THIRD_PARTY_CATEGORIES,
        )
    return rows, summaries, violations


# 产物 CSV 表头契约（规格明示 artifacts/api/third-party-boundary.csv；
# 落盘接线归后续批次；evidence_kinds 序列化约定：sorted 后 "|" 连接）。
THIRD_PARTY_BOUNDARY_CSV_FIELDS: tuple[str, ...] = (
    "candidate_id",
    "category",
    "status",
    "evidence_kinds",
    "source",
    "evidence_ref",
    "precondition",
    "reason",
)
