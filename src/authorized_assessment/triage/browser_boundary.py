"""浏览器边界只读复核（实施规格 5.4 浏览器边界小节 + 3.1 模块清单）。

只读离线：沿用统一筛选模式（观察键→证据形态确定性映射→rule_satisfied 升级判定→
8 状态分级），不发任何请求、不渲染页面、不执行任何 JS。规格覆盖点归并为六复核类别：
cors_policy（CORS allow-origin/credentials + preflight）、csrf_protection（CSRF token/
SameSite/Origin/Referer）、cache_privacy（私有响应 Cache-Control + 缓存键认证维度）、
clickjacking_protection、open_redirect、postmessage_origin。

升级边界（规格 5.4"只有能导致跨站读取、跨用户操作、敏感数据缓存泄露或权限边界绕过
时才能升级为漏洞"的落地实现，实现定义供操作者复核）：每类别仅一个"确认越过"证据
形态可升级（跨站读取/跨用户操作/缓存泄露/框架内操作/外域跳转/跨源消息确认）；仅
配置与形态观察（反射 Origin、缺 CSRF token、SameSite=None、缺 Cache-Control、缺
frame 防护、重定向参数可控、postMessage 通配监听等）永不升级。postMessage 消息体中
的注入/XSS 归各自域（注入 15 类观察记路由违例，不双计）。

报告机读格式（实现定义，留痕）：build_browser_boundary_report 生成 markdown，内嵌
唯一 fenced JSON 块（schema_version/domain/category_summaries/violations）；
extract_report_summary 解析该块，供 input_testing.audit_input_testing 做
报告摘要↔候选行一致性审计。confirmed 五门判定仍归 finding_quality_gate。
"""
from __future__ import annotations

import json
from typing import Iterable, Mapping

from authorized_assessment.triage import injection_candidates as ic

# 浏览器边界复核类别（规格 5.4 八覆盖点归并）。
BROWSER_BOUNDARY_CATEGORIES: tuple[str, ...] = (
    "cors_policy",
    "csrf_protection",
    "cache_privacy",
    "clickjacking_protection",
    "open_redirect",
    "postmessage_origin",
)

# 浏览器边界证据形态（19：13 个形态/支持性观察 + 6 个确认越过形态）。
BROWSER_BOUNDARY_EVIDENCE_KINDS: tuple[str, ...] = (
    "wildcard_origin_reflected",
    "credentials_allowed",
    "preflight_broad_accept",
    "cors_cross_origin_read_confirmed",
    "csrf_token_missing",
    "samesite_none",
    "origin_referer_unchecked",
    "csrf_cross_user_action_confirmed",
    "private_response_no_cache_control",
    "cache_key_missing_auth_dimension",
    "cached_sensitive_data_confirmed",
    "framing_not_denied",
    "clickjacking_action_confirmed",
    "redirect_param_reflected",
    "external_redirect_confirmed",
    "postmessage_wildcard_listener",
    "postmessage_cross_origin_data_confirmed",
    "differential",
    "semantic_anomaly",
)

# "不算漏洞"证据形态：仅配置/形态观察或支持性观察，未证明边界越过。
BROWSER_BOUNDARY_INSUFFICIENT_EVIDENCE_KINDS: tuple[str, ...] = (
    "wildcard_origin_reflected",
    "credentials_allowed",
    "preflight_broad_accept",
    "csrf_token_missing",
    "samesite_none",
    "origin_referer_unchecked",
    "private_response_no_cache_control",
    "cache_key_missing_auth_dimension",
    "framing_not_denied",
    "redirect_param_reflected",
    "postmessage_wildcard_listener",
    "differential",
    "semantic_anomaly",
)

# 升级规则：每类别仅一个"确认越过"形态（组内 OR 单元素 == 要求该形态存在）。
BROWSER_BOUNDARY_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "cors_policy": {"required_any_groups": (("cors_cross_origin_read_confirmed",),)},
    "csrf_protection": {"required_any_groups": (("csrf_cross_user_action_confirmed",),)},
    "cache_privacy": {"required_any_groups": (("cached_sensitive_data_confirmed",),)},
    "clickjacking_protection": {"required_any_groups": (("clickjacking_action_confirmed",),)},
    "open_redirect": {"required_any_groups": (("external_redirect_confirmed",),)},
    "postmessage_origin": {
        "required_any_groups": (("postmessage_cross_origin_data_confirmed",),)
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
BROWSER_BOUNDARY_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "cors_origin_reflection_observed": "wildcard_origin_reflected",
    "cors_credentials_allowed_observed": "credentials_allowed",
    "preflight_broad_accept_observed": "preflight_broad_accept",
    "cors_cross_origin_read_confirmed": "cors_cross_origin_read_confirmed",
    "csrf_token_missing_observed": "csrf_token_missing",
    "samesite_none_observed": "samesite_none",
    "origin_referer_unchecked_observed": "origin_referer_unchecked",
    "csrf_cross_user_action_confirmed": "csrf_cross_user_action_confirmed",
    "private_response_no_cache_control_observed": "private_response_no_cache_control",
    "cache_key_missing_auth_dimension_observed": "cache_key_missing_auth_dimension",
    "cached_sensitive_data_confirmed": "cached_sensitive_data_confirmed",
    "framing_not_denied_observed": "framing_not_denied",
    "clickjacking_action_confirmed": "clickjacking_action_confirmed",
    "redirect_param_reflected_observed": "redirect_param_reflected",
    "external_redirect_confirmed": "external_redirect_confirmed",
    "postmessage_wildcard_listener_observed": "postmessage_wildcard_listener",
    "postmessage_cross_origin_data_confirmed": "postmessage_cross_origin_data_confirmed",
    "differential_observed": "differential",
    "semantic_anomaly_observed": "semantic_anomaly",
}

BROWSER_BOUNDARY_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "cors_origin_reflection_observed": "观察到 ACAO 反射任意 Origin（仅形态观察，永不升级）",
    "cors_credentials_allowed_observed": "观察到 Access-Control-Allow-Credentials: true（仅形态观察）",
    "preflight_broad_accept_observed": "观察到 preflight 接受任意方法/头（仅形态观察）",
    "cors_cross_origin_read_confirmed": "已确认以跨站上下文实际读取到带凭证的私有响应",
    "csrf_token_missing_observed": "观察到写端点缺 CSRF token（仅形态观察）",
    "samesite_none_observed": "观察到会话 cookie SameSite=None 无 Lax 兜底（仅形态观察）",
    "origin_referer_unchecked_observed": "观察到服务端不校验 Origin/Referer（仅形态观察）",
    "csrf_cross_user_action_confirmed": "已确认跨站上下文实际触发跨用户/状态变更操作",
    "private_response_no_cache_control_observed": "观察到私有响应缺 Cache-Control 防护（仅形态观察）",
    "cache_key_missing_auth_dimension_observed": "观察到缓存键不含认证维度（仅形态观察）",
    "cached_sensitive_data_confirmed": "已确认缓存实际向其他用户/共享层泄露敏感数据",
    "framing_not_denied_observed": "观察到缺 X-Frame-Options/frame-ancestors 防护（仅形态观察）",
    "clickjacking_action_confirmed": "已确认敏感操作可在无防护框架内被覆盖实际触发",
    "redirect_param_reflected_observed": "观察到重定向参数可控且回显在 Location（仅形态观察）",
    "external_redirect_confirmed": "已确认实际跳转到外部域（边界越过）",
    "postmessage_wildcard_listener_observed": "观察到 message 监听不校验 origin（仅形态观察）",
    "postmessage_cross_origin_data_confirmed": "已确认跨源页面实际收到敏感消息/触发操作",
    "differential_observed": "观察到可控差分（仅支持性观察，单独不升级）",
    "semantic_anomaly_observed": "观察到语义异常（仅支持性观察，单独不升级）",
}

REPORT_SCHEMA_VERSION = "1.0"
_REPORT_FENCE_OPEN = "```json"
_REPORT_FENCE_CLOSE = "```"

REPORT_CATEGORY_DOCS: dict[str, str] = {
    "cors_policy": "CORS allow-origin/credentials 与 preflight 边界",
    "csrf_protection": "CSRF token、SameSite、Origin/Referer 校验",
    "cache_privacy": "私有响应 Cache-Control 与缓存键认证维度",
    "clickjacking_protection": "帧嵌套防护（点击劫持）",
    "open_redirect": "开放重定向",
    "postmessage_origin": "postMessage 来源校验",
}


def derive_browser_boundary_evidence_kinds(evidence: Mapping[str, object]) -> list[str]:
    """观察键 → 浏览器边界证据形态（按映射表顺序，确定性）。"""
    return [
        kind
        for key, kind in BROWSER_BOUNDARY_OBSERVATION_EVIDENCE_MAP.items()
        if evidence.get(key)
    ]


def grade_browser_boundary_observation(
    category: str, evidence_kinds: Iterable[str], status_hint: str | None = None
) -> str:
    """浏览器边界观察分级：确认越过形态满足 → candidate；否则 signal。
    status_hint 尊重人工判定（8 状态直通）。
    """
    if status_hint in ic.CANDIDATE_STATUS_VALUES:
        return status_hint
    rule = BROWSER_BOUNDARY_UPGRADE_RULES.get(category)
    if rule is None:
        return "signal"
    satisfied, _ = ic.rule_satisfied(
        rule,
        evidence_kinds,
        BROWSER_BOUNDARY_EVIDENCE_KINDS,
        BROWSER_BOUNDARY_INSUFFICIENT_EVIDENCE_KINDS,
    )
    return "candidate" if satisfied else "signal"


def validate_browser_boundary_candidate(
    candidate: Mapping[str, object], label: str = "browser_boundary_candidate"
) -> list[str]:
    """浏览器边界候选行校验：8 状态 + 证据形态 + 升级规则（复用 injection_candidates 引擎）。"""
    violations: list[str] = []
    if not isinstance(candidate, Mapping):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "category", "status", "evidence_kinds", "source"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    category = str(candidate.get("category") or "")
    if category and category not in BROWSER_BOUNDARY_CATEGORIES:
        violations.append(
            f"{label}.category 非法: {category!r}（允许值 {list(BROWSER_BOUNDARY_CATEGORIES)}）"
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
            unknown = sorted({k for k in kind_list if k not in BROWSER_BOUNDARY_EVIDENCE_KINDS})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if status in ("candidate", "confirmed"):
                satisfied, why = ic.rule_satisfied(
                    BROWSER_BOUNDARY_UPGRADE_RULES.get(category) or {},
                    kind_list,
                    BROWSER_BOUNDARY_EVIDENCE_KINDS,
                    BROWSER_BOUNDARY_INSUFFICIENT_EVIDENCE_KINDS,
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
        str(observation.get("input_location") or "").strip(),
        str(observation.get("page") or "").strip(),
    )
    return " ".join(p for p in parts if p)


def screen_browser_boundary_observations(
    observations: Iterable[Mapping[str, object]],
    all_categories: bool = True,
    label: str = "browser_boundary_review",
) -> tuple[list[dict], list[dict], list[str]]:
    """浏览器边界复核筛选 → (候选行, 类别汇总行, 违例)。

    观察必需键：category（本域六类之一）、applicability；可选：
    observation_schema_version（缺失按当前版本，显式不符记违例）、endpoint/
    parameter_name/input_location/page/source/evidence/evidence_ref/reason/
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
                "（消息体注入归 injection_candidate_screening，不双计）"
            )
            continue
        if category not in BROWSER_BOUNDARY_CATEGORIES:
            violations.append(
                f"{label}: 第 {index} 条观察 category 非法 {category!r}"
                f"（允许值 {list(BROWSER_BOUNDARY_CATEGORIES)}；XSS 归 XSS 复核域）"
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
        kinds = derive_browser_boundary_evidence_kinds(observation.get("evidence") or {})
        status = grade_browser_boundary_observation(
            category, kinds, str(observation.get("status_hint") or "") or None
        )
        source = _observation_source(observation)
        if not source:
            violations.append(
                f"{label}: 第 {index} 条观察缺少来源（source 或 endpoint/parameter_name 均为空）"
            )
        row = {
            "candidate_id": f"bb-{index:04d}",
            "category": category,
            "status": status,
            "evidence_kinds": kinds,
            "source": source,
            "evidence_ref": str(observation.get("evidence_ref") or ""),
            "precondition": str(observation.get("precondition") or ""),
            "reason": reason,
        }
        rows.append(row)
        violations += validate_browser_boundary_candidate(
            row, label=f"{label}[{row['candidate_id']}]"
        )

    categories = (
        list(BROWSER_BOUNDARY_CATEGORIES)
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
            categories=BROWSER_BOUNDARY_CATEGORIES,
        )
    return rows, summaries, violations


def build_browser_boundary_report(summaries: list[dict], violations: list[str]) -> str:
    """六类别汇总行 → markdown 报告（内嵌唯一 fenced JSON 机读块，确定性输出）。"""
    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "domain": "browser_boundary",
        "category_summaries": list(summaries),
        "violations": list(violations),
    }
    lines = [
        "# 浏览器边界复核报告（browser_boundary_review）",
        "",
        "> 候选分级不是漏洞证明：signal/观察不是漏洞；confirmed 判定归 finding_quality_gate 五门。",
        "> 升级边界见 src/authorized_assessment/triage/browser_boundary.py 模块 docstring。",
        "",
        _REPORT_FENCE_OPEN,
        json.dumps(payload, ensure_ascii=False, indent=2),
        _REPORT_FENCE_CLOSE,
        "",
        "## 类别说明",
    ]
    lines += [f"- {cat}: {doc}" for cat, doc in REPORT_CATEGORY_DOCS.items()]
    return "\n".join(lines) + "\n"


def extract_report_summary(md_text: str) -> tuple[dict | None, str | None]:
    """从报告 markdown 提取 fenced JSON 机读块 → (payload, 错误)。"""
    start = md_text.find(_REPORT_FENCE_OPEN)
    if start < 0:
        return None, "报告中缺少 ```json 机读块"
    start += len(_REPORT_FENCE_OPEN)
    end = md_text.find(_REPORT_FENCE_CLOSE, start)
    if end < 0:
        return None, "报告 json 块未闭合"
    try:
        payload = json.loads(md_text[start:end])
    except json.JSONDecodeError as exc:
        return None, f"报告 json 块不可解析: {exc}"
    if not isinstance(payload, dict):
        return None, "报告 json 块必须是键值对象"
    return payload, None
