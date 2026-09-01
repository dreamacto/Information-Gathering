"""API 资源控制只读筛选域（实施规格 5.3 API 资源控制小节 1276-1295 行 + 3.1
triage/api_resource_controls 模块清单）。

只读离线：沿用统一筛选模式（观察键→证据形态确定性映射→rule_satisfied 升级判定→
8 状态分级），不发任何请求、不做高并发或造成实际资源压力的验证（规格红线）、
不构造放大请求。观察输入为复核会话从既有证据（响应元数据/文档/配置/流量记录）
提炼的结构化记录，非压测数据。

六类别（规格检查方向归并）：
- pagination_limits：page/pageSize 上限、深分页；
- batch_limits：批量查询数量上限；
- filter_complexity：复杂过滤器的资源成本约束；
- export_permission_cost：导出/报表接口的权限与资源成本；
- rate_quota：单用户/token/IP/租户的速率与配额；
- retry_timeout_cache_amp：重试、超时和缓存放大。

升级边界（实现定义供操作者复核）：仅"确认无上限/无配额/无权限校验/确认放大成功"
类确认证据可升级 candidate；仅参数存在/端点支持分页/缺失速率响应头等形态观察
永不升级（signal 不是漏洞）。confirmed 五门判定仍归 finding_quality_gate；本模块
只做候选层分级校验。注入 15 类观察记路由违例（归 injection_candidate_screening，
不双计）。

产物 CSV 表头契约：RESOURCE_CONTROL_REVIEW_CSV_FIELDS 对应规格明示
artifacts/api/resource-control-review.csv；落盘接线归后续批次（本批只锁表头，
evidence_kinds 序列化约定与 batch8_0 一致：sorted 后 "|" 连接）。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.triage import injection_candidates as ic

# 资源控制复核类别（规格 5.3 检查方向归并，契约 review_categories 同源）。
RESOURCE_CONTROL_CATEGORIES: tuple[str, ...] = (
    "pagination_limits",
    "batch_limits",
    "filter_complexity",
    "export_permission_cost",
    "rate_quota",
    "retry_timeout_cache_amp",
)

# 证据形态（15：13 形态/支持性永不升级 + 2 确认越过形态——与前批各域同构：
# "确认无防护/确认放大才升级，形态观察仅 signal"）。
RESOURCE_CONTROL_EVIDENCE_KINDS: tuple[str, ...] = (
    "pagination_params_present",
    "deep_pagination_supported",
    "batch_params_present",
    "filter_params_present",
    "export_endpoint_present",
    "no_rate_limit_headers",
    "no_quota_documented",
    "retry_after_header_present",
    "cache_headers_present",
    "timeout_error_observed",
    "differential",
    "semantic_anomaly",
    "cost_hint_observed",
    "unbounded_response_confirmed",
    "amplification_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察，未证明无防护或放大成功。
RESOURCE_CONTROL_INSUFFICIENT_EVIDENCE_KINDS: tuple[str, ...] = (
    "pagination_params_present",
    "deep_pagination_supported",
    "batch_params_present",
    "filter_params_present",
    "export_endpoint_present",
    "no_rate_limit_headers",
    "no_quota_documented",
    "retry_after_header_present",
    "cache_headers_present",
    "timeout_error_observed",
    "differential",
    "semantic_anomaly",
    "cost_hint_observed",
)

# 升级规则（实现定义，固定语义；不在本表 = 该类别永不升级）：
# - pagination_limits/batch_limits/filter_complexity：确认无上限的响应
#   （unbounded_response_confirmed——既有证据显示无上限或上限形同虚设）；
# - export_permission_cost：确认放大成功（未授权/低权导出实际成功或资源成本确认）；
# - rate_quota：确认放大成功（配额外请求实际成功且资源成本确认）；
# - retry_timeout_cache_amp：确认放大成功（重试/缓存键缺陷实际造成成倍资源消耗）。
# "确认"语义要求观察来自既有只读证据的复核判定；禁止为取得该确认而发起
# 高并发或资源压力验证（规格红线，precondition 必须留痕）。
RESOURCE_CONTROL_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "pagination_limits": {"required_any_groups": (("unbounded_response_confirmed",),)},
    "batch_limits": {"required_any_groups": (("unbounded_response_confirmed",),)},
    "filter_complexity": {"required_any_groups": (("unbounded_response_confirmed",),)},
    "export_permission_cost": {"required_any_groups": (("amplification_confirmed",),)},
    "rate_quota": {"required_any_groups": (("amplification_confirmed",),)},
    "retry_timeout_cache_amp": {"required_any_groups": (("amplification_confirmed",),)},
}

# 高并发红线（模块级常量供测试与审计引用；写入候选 precondition 语义）。
NO_LOAD_VALIDATION_RULE: str = (
    "不得用高并发或造成实际资源压力的方式验证资源控制假设；"
    "升级确认只能来自既有只读证据的复核判定"
)

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
RESOURCE_CONTROL_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "pagination_params_present_observed": "pagination_params_present",
    "deep_pagination_supported_observed": "deep_pagination_supported",
    "batch_params_present_observed": "batch_params_present",
    "filter_params_present_observed": "filter_params_present",
    "export_endpoint_present_observed": "export_endpoint_present",
    "no_rate_limit_headers_observed": "no_rate_limit_headers",
    "no_quota_documented_observed": "no_quota_documented",
    "retry_after_header_present_observed": "retry_after_header_present",
    "cache_headers_present_observed": "cache_headers_present",
    "timeout_error_observed": "timeout_error_observed",
    "differential_observed": "differential",
    "semantic_anomaly_observed": "semantic_anomaly",
    "cost_hint_observed": "cost_hint_observed",
    "unbounded_response_confirmed": "unbounded_response_confirmed",
    "amplification_confirmed": "amplification_confirmed",
}

RESOURCE_CONTROL_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "pagination_params_present_observed": "观察到分页参数面（page/size/offset/limit 等——仅形态）",
    "deep_pagination_supported_observed": "观察到深分页可达迹象（大 offset/页码接受——仅形态）",
    "batch_params_present_observed": "观察到批量参数面（ids/ids[]/batch 等——仅形态）",
    "filter_params_present_observed": "观察到过滤器参数面（filter/sort/q/group 等——仅形态）",
    "export_endpoint_present_observed": "观察到导出/报表端点存在（仅形态）",
    "no_rate_limit_headers_observed": "未观察到速率限制响应头（缺失≠不存在，仅形态）",
    "no_quota_documented_observed": "文档/配置未见配额定义（缺失≠不存在，仅形态）",
    "retry_after_header_present_observed": "观察到 Retry-After/429 语义存在（防护形态，支持性）",
    "cache_headers_present_observed": "观察到缓存头（形态，支持性）",
    "timeout_error_observed": "观察到超时/错误响应痕迹（形态，支持性）",
    "differential_observed": "观察到可控差分（仅支持性观察，单独不升级）",
    "semantic_anomaly_observed": "观察到语义异常（仅支持性观察，单独不升级）",
    "cost_hint_observed": "观察到资源成本线索（响应体量/字段数/耗时提示——仅形态）",
    "unbounded_response_confirmed": "已确认无上限/上限形同虚设：既有只读证据显示分页/批量/"
    "过滤器无有效上限且可复现（不发起高并发验证）",
    "amplification_confirmed": "已确认放大成功：既有只读证据显示导出/速率/重试/缓存缺陷实际造成"
    "成倍资源消耗或未授权成本（不发起高并发验证）",
}


def derive_resource_control_evidence_kinds(evidence: Mapping[str, object]) -> list[str]:
    """观察键 → 资源控制证据形态（按映射表顺序，确定性）。"""
    return [
        kind
        for key, kind in RESOURCE_CONTROL_OBSERVATION_EVIDENCE_MAP.items()
        if evidence.get(key)
    ]


def grade_resource_control_observation(
    category: str, evidence_kinds: Iterable[str], status_hint: str | None = None
) -> str:
    """资源控制观察分级：确认形态满足 → candidate；否则 signal。status_hint 尊重人工判定。"""
    if status_hint in ic.CANDIDATE_STATUS_VALUES:
        return status_hint
    rule = RESOURCE_CONTROL_UPGRADE_RULES.get(category)
    if rule is None:
        return "signal"
    satisfied, _ = ic.rule_satisfied(
        rule,
        evidence_kinds,
        RESOURCE_CONTROL_EVIDENCE_KINDS,
        RESOURCE_CONTROL_INSUFFICIENT_EVIDENCE_KINDS,
    )
    return "candidate" if satisfied else "signal"


def validate_resource_control_candidate(
    candidate: Mapping[str, object], label: str = "resource_control_candidate"
) -> list[str]:
    """资源控制候选行校验：8 状态 + 证据形态 + 升级规则（复用 injection_candidates 引擎）。"""
    violations: list[str] = []
    if not isinstance(candidate, Mapping):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "category", "status", "evidence_kinds", "source"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    category = str(candidate.get("category") or "")
    if category and category not in RESOURCE_CONTROL_CATEGORIES:
        violations.append(
            f"{label}.category 非法: {category!r}"
            f"（允许值 {list(RESOURCE_CONTROL_CATEGORIES)}）"
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
            unknown = sorted({k for k in kind_list if k not in RESOURCE_CONTROL_EVIDENCE_KINDS})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if status in ("candidate", "confirmed"):
                rule = RESOURCE_CONTROL_UPGRADE_RULES.get(category)
                if rule is None:
                    violations.append(
                        f"{label}: category={category} 永不升级（契约 never_upgrade_rule）"
                    )
                else:
                    satisfied, why = ic.rule_satisfied(
                        rule,
                        kind_list,
                        RESOURCE_CONTROL_EVIDENCE_KINDS,
                        RESOURCE_CONTROL_INSUFFICIENT_EVIDENCE_KINDS,
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
        str(observation.get("parameter_name") or "").strip(),
        str(observation.get("control_dimension") or "").strip(),
    )
    return " ".join(p for p in parts if p)


def screen_resource_control_observations(
    observations: Iterable[Mapping[str, object]],
    all_categories: bool = True,
    label: str = "api_resource_controls",
) -> tuple[list[dict], list[dict], list[str]]:
    """资源控制复核筛选 → (候选行, 类别汇总行, 违例)。

    观察必需键：category（本域六类之一）、applicability；可选：
    observation_schema_version（缺失按当前版本，显式不符记违例）、endpoint/
    parameter_name/control_dimension/source/evidence/evidence_ref/reason/
    precondition/status_hint。注入类别观察记路由违例（归
    injection_candidate_screening，不双计）。
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
        if category not in RESOURCE_CONTROL_CATEGORIES:
            violations.append(
                f"{label}: 第 {index} 条观察 category 非法 {category!r}"
                f"（允许值 {list(RESOURCE_CONTROL_CATEGORIES)}）"
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
        kinds = derive_resource_control_evidence_kinds(observation.get("evidence") or {})
        status = grade_resource_control_observation(
            category, kinds, str(observation.get("status_hint") or "") or None
        )
        source = _observation_source(observation)
        if not source:
            violations.append(
                f"{label}: 第 {index} 条观察缺少来源（source 或 endpoint/parameter_name 均为空）"
            )
        row = {
            "candidate_id": f"rc-{index:04d}",
            "category": category,
            "status": status,
            "evidence_kinds": kinds,
            "source": source,
            "evidence_ref": str(observation.get("evidence_ref") or ""),
            "precondition": str(observation.get("precondition") or ""),
            "reason": reason,
        }
        rows.append(row)
        violations += validate_resource_control_candidate(
            row, label=f"{label}[{row['candidate_id']}]"
        )

    categories = (
        list(RESOURCE_CONTROL_CATEGORIES)
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
            categories=RESOURCE_CONTROL_CATEGORIES,
        )
    return rows, summaries, violations


# 产物 CSV 表头契约（规格明示 artifacts/api/resource-control-review.csv；
# 落盘接线归后续批次；evidence_kinds 序列化约定：sorted 后 "|" 连接）。
RESOURCE_CONTROL_REVIEW_CSV_FIELDS: tuple[str, ...] = (
    "candidate_id",
    "category",
    "status",
    "evidence_kinds",
    "source",
    "evidence_ref",
    "precondition",
    "reason",
)
