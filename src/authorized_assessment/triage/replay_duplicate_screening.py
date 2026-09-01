"""重放/重复提交假设筛选域（实施规格 5.5 business_logic_testing 子分支 1453-1472
行，replay_duplicate 内部子分支）。

只读离线：沿用统一筛选模式（观察键→证据形态确定性映射→rule_satisfied 升级判定→
8 状态分级），不发任何请求、不发并发或重复轰炸请求（规格 1464/1472 红线）。观察
输入为复核会话从既有只读证据（请求记录/响应元数据/台账）提炼的结构化记录，非
压测数据。

四类别（与规格 1472 行四类服务端重复结果一一对应）：
- repeat_consumption：重复消费（库存/次数/配额/一次性标记被扣两次）；
- repeat_grant：重复发放（权益/奖励/积分/券发放两次）；
- repeat_deduction：重复扣款（金额/余额扣两次）；
- repeat_approval：重复审批（同一单据被审批两次/审批状态被二次推进）。

升级边界（实现定义供操作者复核）：仅对应类别的确认证据（duplicate_*_confirmed，
来自既有只读证据的复核判定：服务端状态确实发生不应有的重复变更且可复现）可升级
candidate；"重复请求被接受/幂等键缺失/无防重反馈/响应形态相似/请求间隔"等形态
观察与"差分/语义异常"支持性观察永不升级（signal 不是漏洞）。规格 1472 行红线：
重复点击一次（同一请求重复发送一次）不构成竞态漏洞认定——必须证明服务端状态
发生不应有的重复消费/发放/扣款/审批结果。confirmed 五门判定仍归
finding_quality_gate；本模块只做候选层分级校验。注入 15 类观察记路由违例
（归 injection_candidate_screening，不双计）。

产物 CSV 表头契约：REPLAY_DUPLICATE_REVIEW_CSV_FIELDS（规格未给本域产物路径——
表头契约按域常量先例锁定，落盘路径归后续批次/操作者决定；evidence_kinds 序列化
约定与 batch8_0 一致：sorted 后 "|" 连接）。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.triage import injection_candidates as ic

# 重放/重复提交复核类别（规格 1472 行四类服务端重复结果，契约 review_categories
# 同源）。
REPLAY_DUPLICATE_CATEGORIES: tuple[str, ...] = (
    "repeat_consumption",
    "repeat_grant",
    "repeat_deduction",
    "repeat_approval",
)

# 证据形态（11：7 形态/支持性永不升级 + 4 确认越过形态——确认与类别一一对应）。
REPLAY_DUPLICATE_EVIDENCE_KINDS: tuple[str, ...] = (
    "duplicate_request_accepted_observed",
    "idempotency_key_absent_observed",
    "no_dedup_feedback_observed",
    "response_similarity_observed",
    "timing_gap_observed",
    "differential",
    "semantic_anomaly",
    "duplicate_consumption_confirmed",
    "duplicate_grant_confirmed",
    "duplicate_deduction_confirmed",
    "duplicate_approval_confirmed",
)

# "不算漏洞"证据形态：仅形态/支持性观察，未证明服务端状态发生不应有的重复变更。
REPLAY_DUPLICATE_INSUFFICIENT_EVIDENCE_KINDS: tuple[str, ...] = (
    "duplicate_request_accepted_observed",
    "idempotency_key_absent_observed",
    "no_dedup_feedback_observed",
    "response_similarity_observed",
    "timing_gap_observed",
    "differential",
    "semantic_anomaly",
)

# 升级规则（实现定义，固定语义；确认形态与类别一一对应、不跨类升级）：
# "确认"语义要求观察来自既有只读证据的复核判定（服务端重复变更可复现）；禁止
# 为取得该确认而发起并发/重复轰炸验证（规格红线，precondition 必须留痕）。
REPLAY_DUPLICATE_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "repeat_consumption": {
        "required_any_groups": (("duplicate_consumption_confirmed",),)
    },
    "repeat_grant": {"required_any_groups": (("duplicate_grant_confirmed",),)},
    "repeat_deduction": {
        "required_any_groups": (("duplicate_deduction_confirmed",),)
    },
    "repeat_approval": {
        "required_any_groups": (("duplicate_approval_confirmed",),)
    },
}

# 规格 1472 行红线（模块级常量供测试与审计引用；写入候选 precondition 语义）。
SINGLE_REPEAT_NOT_RACE_RULE: str = (
    "重复点击一次（同一请求重复发送一次）不构成竞态漏洞认定；必须证明服务端状态"
    "发生不应有的重复消费/发放/扣款/审批结果，才升级为候选"
)

# 不发并发/重复轰炸验证红线（升级确认的 precondition 语义）。
NO_CONCURRENT_VALIDATION_RULE: str = (
    "不得用并发或重复轰炸方式验证重放/重复提交假设；升级确认只能来自既有只读"
    "证据的复核判定"
)

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
REPLAY_DUPLICATE_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "duplicate_request_accepted_observed": "duplicate_request_accepted_observed",
    "idempotency_key_absent_observed": "idempotency_key_absent_observed",
    "no_dedup_feedback_observed": "no_dedup_feedback_observed",
    "response_similarity_observed": "response_similarity_observed",
    "timing_gap_observed": "timing_gap_observed",
    "differential_observed": "differential",
    "semantic_anomaly_observed": "semantic_anomaly",
    "duplicate_consumption_confirmed": "duplicate_consumption_confirmed",
    "duplicate_grant_confirmed": "duplicate_grant_confirmed",
    "duplicate_deduction_confirmed": "duplicate_deduction_confirmed",
    "duplicate_approval_confirmed": "duplicate_approval_confirmed",
}

REPLAY_DUPLICATE_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "duplicate_request_accepted_observed": "观察到重复请求被服务端接受（非错误响应——仅形态，"
    "不代表服务端状态重复变更）",
    "idempotency_key_absent_observed": "请求未见幂等键/防重字段（缺失≠不存在，仅形态）",
    "no_dedup_feedback_observed": "未见防重复提交提示/去重痕迹（仅形态）",
    "response_similarity_observed": "两次响应形态相似（仅形态）",
    "timing_gap_observed": "观察到请求间隔时间线（形态，支持性）",
    "differential_observed": "观察到两次响应内容差分（仅支持性观察，单独不升级）",
    "semantic_anomaly_observed": "观察到语义异常（仅支持性观察，单独不升级）",
    "duplicate_consumption_confirmed": "已确认服务端重复消费：既有只读证据显示库存/次数/配额/"
    "一次性标记被扣两次且可复现（不发起并发/重复轰炸验证）",
    "duplicate_grant_confirmed": "已确认服务端重复发放：既有只读证据显示权益/奖励/积分/券"
    "发放两次且可复现（不发起并发/重复轰炸验证）",
    "duplicate_deduction_confirmed": "已确认服务端重复扣款：既有只读证据显示金额/余额扣两次"
    "且可复现（不发起并发/重复轰炸验证）",
    "duplicate_approval_confirmed": "已确认服务端重复审批：既有只读证据显示同一单据被审批两次/"
    "审批状态被二次推进且可复现（不发起并发/重复轰炸验证）",
}


def derive_replay_duplicate_evidence_kinds(evidence: Mapping[str, object]) -> list[str]:
    """观察键 → 重放/重复提交证据形态（按映射表顺序，确定性）。"""
    return [
        kind
        for key, kind in REPLAY_DUPLICATE_OBSERVATION_EVIDENCE_MAP.items()
        if evidence.get(key)
    ]


def grade_replay_duplicate_observation(
    category: str, evidence_kinds: Iterable[str], status_hint: str | None = None
) -> str:
    """重放/重复提交观察分级：确认形态满足 → candidate；否则 signal。status_hint
    尊重人工判定。"""
    if status_hint in ic.CANDIDATE_STATUS_VALUES:
        return status_hint
    rule = REPLAY_DUPLICATE_UPGRADE_RULES.get(category)
    if rule is None:
        return "signal"
    satisfied, _ = ic.rule_satisfied(
        rule,
        evidence_kinds,
        REPLAY_DUPLICATE_EVIDENCE_KINDS,
        REPLAY_DUPLICATE_INSUFFICIENT_EVIDENCE_KINDS,
    )
    return "candidate" if satisfied else "signal"


def validate_replay_duplicate_candidate(
    candidate: Mapping[str, object], label: str = "replay_duplicate_candidate"
) -> list[str]:
    """重放/重复提交候选行校验：8 状态 + 证据形态 + 升级规则（复用 ic 引擎）。"""
    violations: list[str] = []
    if not isinstance(candidate, Mapping):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "category", "status", "evidence_kinds", "source"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    category = str(candidate.get("category") or "")
    if category and category not in REPLAY_DUPLICATE_CATEGORIES:
        violations.append(
            f"{label}.category 非法: {category!r}"
            f"（允许值 {list(REPLAY_DUPLICATE_CATEGORIES)}）"
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
            unknown = sorted(
                {k for k in kind_list if k not in REPLAY_DUPLICATE_EVIDENCE_KINDS}
            )
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if status in ("candidate", "confirmed"):
                rule = REPLAY_DUPLICATE_UPGRADE_RULES.get(category)
                if rule is None:
                    violations.append(
                        f"{label}: category={category} 永不升级（契约 never_upgrade_rule）"
                    )
                else:
                    satisfied, why = ic.rule_satisfied(
                        rule,
                        kind_list,
                        REPLAY_DUPLICATE_EVIDENCE_KINDS,
                        REPLAY_DUPLICATE_INSUFFICIENT_EVIDENCE_KINDS,
                    )
                    if not satisfied:
                        violations.append(
                            f"{label}: status={status} 但升级证据不满足——{why}"
                        )
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
        str(observation.get("object_ref") or "").strip(),
        str(observation.get("parameter_name") or "").strip(),
    )
    return " ".join(p for p in parts if p)


def screen_replay_duplicate_observations(
    observations: Iterable[Mapping[str, object]],
    all_categories: bool = True,
    label: str = "replay_duplicate_screening",
) -> tuple[list[dict], list[dict], list[str]]:
    """重放/重复提交复核筛选 → (候选行, 类别汇总行, 违例)。

    观察必需键：category（本域四类之一）、applicability；可选：
    observation_schema_version（缺失按当前版本，显式不符记违例）、endpoint/
    object_ref/parameter_name/source/evidence/evidence_ref/reason/precondition/
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
        if category not in REPLAY_DUPLICATE_CATEGORIES:
            violations.append(
                f"{label}: 第 {index} 条观察 category 非法 {category!r}"
                f"（允许值 {list(REPLAY_DUPLICATE_CATEGORIES)}）"
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
        kinds = derive_replay_duplicate_evidence_kinds(observation.get("evidence") or {})
        status = grade_replay_duplicate_observation(
            category, kinds, str(observation.get("status_hint") or "") or None
        )
        source = _observation_source(observation)
        if not source:
            violations.append(
                f"{label}: 第 {index} 条观察缺少来源（source 或 endpoint/object_ref 均为空）"
            )
        row = {
            "candidate_id": f"rd-{index:04d}",
            "category": category,
            "status": status,
            "evidence_kinds": kinds,
            "source": source,
            "evidence_ref": str(observation.get("evidence_ref") or ""),
            "precondition": str(observation.get("precondition") or ""),
            "reason": reason,
        }
        rows.append(row)
        violations += validate_replay_duplicate_candidate(
            row, label=f"{label}[{row['candidate_id']}]"
        )

    categories = (
        list(REPLAY_DUPLICATE_CATEGORIES)
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
            categories=REPLAY_DUPLICATE_CATEGORIES,
        )
    return rows, summaries, violations


# 产物 CSV 表头契约（规格未给本域产物路径——表头契约按域常量先例锁定，落盘
# 路径归后续批次/操作者决定；evidence_kinds 序列化约定：sorted 后 "|" 连接）。
REPLAY_DUPLICATE_REVIEW_CSV_FIELDS: tuple[str, ...] = (
    "candidate_id",
    "category",
    "status",
    "evidence_kinds",
    "source",
    "evidence_ref",
    "precondition",
    "reason",
)
