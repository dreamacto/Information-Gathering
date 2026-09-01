"""finding_quality_gate.py —— 漏洞成立五门判定器与 8 状态分类（实施规格 2.1-2.2）。

离线纯函数：输入 finding 分类输入 dict，输出符合 contracts/finding_quality_schema.json 的
finding quality report。零网络请求，不耦合具体 run 文件布局，不读取真实 runs/。

五门（缺任何一门都不得 confirmed）：
  authorization / reachability / reproducibility / security_impact / evidence

状态判定优先序（固化于契约 status_decision_order，实现与校验器共用 _decide_status）：
  duplicate > rejected > blocked > inconclusive > confirmed
  > needs_manual_validation > signal(可达未证) > signal(复现未证)
  > candidate(有影响假设) > signal(纯现象)
未经人工验证的 AI 候选不得为 confirmed（manual_validation_status != verified →
needs_manual_validation）。

分类输入契约（全部可选，缺省按最严格语义处理）：
  finding_id: str
  duplicate_of: str                       # 非空 → duplicate（合并键本身属 Batch 3）
  rejection_reason: str                   # 非空 → rejected
  manual_validation_status: not_started|in_progress|verified|rejected（默认 not_started）
  validation_result: verified|failed|inconclusive|None
  authorization: {in_scope, scope_confirmed, credentials_authorized,
                  approval_required, approval_records}
  reachability: {evidence_type: live_response|authenticated_response|static_only|none}
  reproducibility: {baseline_recorded, anomalous_response_recorded, repeatable,
                    one_time_anomaly, minimal_steps_recorded}
  impact: {category: 规格 2.2 影响清单枚举或 None, hypothesis: 影响假设文本}
  probe_quality: {waf_blocked, rate_limited, no_valid_response}
  + 规格 2.2 证据门十四字段直接位于顶层（finding_id / source_run / engagement_id /
    target / asset_identity / vulnerability_family / precondition /
    minimal_reproduction / observed_result / impact_statement / evidence_ref /
    validation_result / reviewer / reviewed_at）
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from authorized_assessment.quality.run_quality_gate import (
    _FORBIDDEN_KEY_FRAGMENTS as _BASE_FORBIDDEN_KEY_FRAGMENTS,
)

FINDING_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "contracts" / "finding_quality_schema.json"
)

# B1 决议：8 状态超集（signal/candidate/needs_manual_validation/confirmed/
# inconclusive/blocked/rejected/duplicate）。
FINDING_STATUS_STATES = (
    "signal",
    "candidate",
    "needs_manual_validation",
    "confirmed",
    "inconclusive",
    "blocked",
    "rejected",
    "duplicate",
)

FIVE_GATES = (
    "authorization",
    "reachability",
    "reproducibility",
    "security_impact",
    "evidence",
)

MANUAL_VALIDATION_STATES = ("not_started", "in_progress", "verified", "rejected")

VALIDATION_RESULT_STATES = ("verified", "failed", "inconclusive")

REACHABILITY_EVIDENCE_TYPES = (
    "live_response",
    "authenticated_response",
    "static_only",
    "none",
)

# 规格 2.2 安全影响门影响清单（9 项）。
IMPACT_CATEGORIES = (
    "unauthorized_object_access",
    "privilege_escalation",
    "boundary_crossing",
    "sensitive_data_exposure",
    "code_or_command_execution",
    "network_zone_access",
    "business_state_change",
    "resource_consumption_or_availability",
    "auditable_attack_chain",
)

GATE_REASON_ENUMS: dict[str, tuple[str, ...]] = {
    "authorization": (
        "authorization_proven",
        "out_of_scope",
        "scope_unconfirmed",
        "credentials_not_authorized",
        "approval_record_missing",
    ),
    "reachability": (
        "live_reachability_proven",
        "static_evidence_only",
        "reachability_unproven",
    ),
    "reproducibility": (
        "reproduction_proven",
        "baseline_missing",
        "anomalous_response_missing",
        "not_repeatable",
        "one_time_anomaly",
        "reproduction_steps_missing",
    ),
    "security_impact": (
        "impact_proven",
        "impact_category_missing",
        "impact_below_threshold",
    ),
    "evidence": (
        "evidence_complete",
        "evidence_field_missing",
        "validation_result_missing_or_unverified",
    ),
}

# 规格 2.2 证据门：confirmed 至少需要的十四个字段。
EVIDENCE_REQUIRED_FIELDS = (
    "finding_id",
    "source_run",
    "engagement_id",
    "target",
    "asset_identity",
    "vulnerability_family",
    "precondition",
    "minimal_reproduction",
    "observed_result",
    "impact_statement",
    "evidence_ref",
    "validation_result",
    "reviewer",
    "reviewed_at",
)

INCONCLUSIVE_INDICATORS = ("waf_blocked", "rate_limited", "no_valid_response")

# 规格 4.4 在基础凭证片段上显式点名 session_key/AppSecret；AppSecret 已被
# "secret" 覆盖，session_key 需补充。
_FORBIDDEN_KEY_FRAGMENTS = tuple(_BASE_FORBIDDEN_KEY_FRAGMENTS) + ("session_key",)

# 精确豁免：作为 key 名出现时它只会是五门之一的门名（授权门），
# 与 policy_snapshot 校验器精确豁免 authorization_status 枚举字段同一先例。
_EXEMPT_EXACT_KEYS = frozenset({"authorization"})

STATUS_RULE_IDS = (
    "duplicate_merge_reference",
    "explicit_rejection",
    "authorization_gate_failed",
    "inconclusive_indicators",
    "five_gates_confirmed",
    "validation_evidence_incomplete",
    "reachability_unproven",
    "reproduction_unproven",
    "impact_unproven_with_hypothesis",
    "impact_unproven_no_hypothesis",
)


def _gate_result(passed: bool, reasons: list[str]) -> dict[str, Any]:
    return {"passed": passed, "reasons": list(reasons)}


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _field_present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value)
    return value is not None


def _evaluate_authorization(finding: Mapping[str, Any]) -> dict[str, Any]:
    auth = finding.get("authorization") or {}
    reasons: list[str] = []
    if auth.get("in_scope") is not True:
        reasons.append("out_of_scope")
    if auth.get("scope_confirmed") is not True:
        reasons.append("scope_unconfirmed")
    if auth.get("credentials_authorized") is not True:
        reasons.append("credentials_not_authorized")
    if auth.get("approval_required") is True and not _field_present(
        auth.get("approval_records")
    ):
        reasons.append("approval_record_missing")
    return _gate_result(not reasons, reasons or ["authorization_proven"])


def _evaluate_reachability(finding: Mapping[str, Any]) -> dict[str, Any]:
    reach = finding.get("reachability") or {}
    evidence_type = reach.get("evidence_type")
    if evidence_type in ("live_response", "authenticated_response"):
        return _gate_result(True, ["live_reachability_proven"])
    if evidence_type == "static_only":
        # 规格 2.2 门 2：只有静态代码证据而没有可触达链路，最多 whitebox_candidate，
        # 按 B1 八状态模型映射为 signal 上限。
        return _gate_result(False, ["static_evidence_only"])
    return _gate_result(False, ["reachability_unproven"])


def _evaluate_reproducibility(finding: Mapping[str, Any]) -> dict[str, Any]:
    rep = finding.get("reproducibility") or {}
    reasons: list[str] = []
    if rep.get("baseline_recorded") is not True:
        reasons.append("baseline_missing")
    if rep.get("anomalous_response_recorded") is not True:
        reasons.append("anomalous_response_missing")
    if rep.get("repeatable") is not True:
        reasons.append("not_repeatable")
    if rep.get("one_time_anomaly") is True:
        reasons.append("one_time_anomaly")
    if rep.get("minimal_steps_recorded") is not True:
        reasons.append("reproduction_steps_missing")
    return _gate_result(not reasons, reasons or ["reproduction_proven"])


def _evaluate_impact(
    finding: Mapping[str, Any],
) -> tuple[dict[str, Any], str | None, bool]:
    impact = finding.get("impact") or {}
    category = impact.get("category") or None
    hypothesis = _text(impact.get("hypothesis"))
    if category in IMPACT_CATEGORIES:
        gate = _gate_result(True, ["impact_proven"])
    elif category:
        gate = _gate_result(False, ["impact_below_threshold"])
    else:
        gate = _gate_result(False, ["impact_category_missing"])
    return gate, category, bool(hypothesis)


def _evaluate_evidence(
    finding: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    missing = [
        field
        for field in EVIDENCE_REQUIRED_FIELDS
        if not _field_present(finding.get(field))
    ]
    reasons: list[str] = []
    if missing:
        reasons.append("evidence_field_missing")
    if finding.get("validation_result") != "verified":
        reasons.append("validation_result_missing_or_unverified")
    return _gate_result(not reasons, reasons or ["evidence_complete"]), missing


def _decide_status(
    duplicate_of: str,
    rejection_reason: str,
    manual_validation_status: str,
    validation_result: str | None,
    inconclusive_indicators: list[str],
    passed: Mapping[str, bool],
    impact_hypothesis_recorded: bool,
) -> tuple[str, str]:
    """状态判定唯一实现：evaluate 与校验器共用，保证报告自洽可复核。"""
    if duplicate_of:
        return "duplicate", "duplicate_merge_reference"
    if rejection_reason or manual_validation_status == "rejected":
        return "rejected", "explicit_rejection"
    if not passed["authorization"]:
        return "blocked", "authorization_gate_failed"
    if validation_result == "inconclusive" or inconclusive_indicators:
        return "inconclusive", "inconclusive_indicators"
    if all(passed[gate] for gate in FIVE_GATES) and manual_validation_status == "verified":
        return "confirmed", "five_gates_confirmed"
    core_four = ("authorization", "reachability", "reproducibility", "security_impact")
    if all(passed[gate] for gate in core_four) and (
        not passed["evidence"] or manual_validation_status != "verified"
    ):
        return "needs_manual_validation", "validation_evidence_incomplete"
    if not passed["reachability"]:
        return "signal", "reachability_unproven"
    if not passed["reproducibility"]:
        return "signal", "reproduction_unproven"
    if not passed["security_impact"]:
        if impact_hypothesis_recorded:
            return "candidate", "impact_unproven_with_hypothesis"
        return "signal", "impact_unproven_no_hypothesis"
    # 五门全过但 manual_validation_status 已是 verified 时不会到达这里；
    # 防御性兜底与 validation_evidence_incomplete 同语义（fail-closed）。
    return "needs_manual_validation", "validation_evidence_incomplete"


def evaluate_finding_quality(finding: Mapping[str, Any] | None) -> dict[str, Any]:
    """从 finding 分类输入推导五门判定与 8 状态分类；纯函数、同输入同输出。

    非法枚举输入按最保守语义归一（manual_validation_status→not_started、
    validation_result→None、未知 evidence_type→不可达），保证输出恒可通过
    validate_finding_quality_report。
    """
    f = dict(finding or {})

    manual = f.get("manual_validation_status")
    if manual not in MANUAL_VALIDATION_STATES:
        manual = "not_started"
    validation_result = f.get("validation_result")
    if validation_result not in VALIDATION_RESULT_STATES:
        validation_result = None

    duplicate_of = _text(f.get("duplicate_of"))
    rejection_reason = _text(f.get("rejection_reason"))

    probe_quality = f.get("probe_quality") or {}
    indicators = [
        name for name in INCONCLUSIVE_INDICATORS if probe_quality.get(name) is True
    ]

    authorization_gate = _evaluate_authorization(f)
    reachability_gate = _evaluate_reachability(f)
    reproducibility_gate = _evaluate_reproducibility(f)
    impact_gate, impact_category, impact_hypothesis = _evaluate_impact(f)
    evidence_gate, missing_evidence = _evaluate_evidence(f)

    gate_results = {
        "authorization": authorization_gate,
        "reachability": reachability_gate,
        "reproducibility": reproducibility_gate,
        "security_impact": impact_gate,
        "evidence": evidence_gate,
    }
    gates_failed = [gate for gate in FIVE_GATES if not gate_results[gate]["passed"]]
    gates_passed = len(FIVE_GATES) - len(gates_failed)
    confirmed_allowed = not gates_failed

    passed = {gate: gate_results[gate]["passed"] for gate in FIVE_GATES}
    status, rule = _decide_status(
        duplicate_of,
        rejection_reason,
        manual,
        validation_result,
        indicators,
        passed,
        impact_hypothesis,
    )

    blockers = [f"gate_{gate}_failed" for gate in gates_failed]
    if manual != "verified":
        blockers.append("manual_validation_not_verified")
    if duplicate_of:
        blockers.append("duplicate_of_set")
    if rejection_reason or manual == "rejected":
        blockers.append("explicit_rejection")
    if validation_result == "inconclusive":
        blockers.append("validation_result_inconclusive")
    blockers.extend(f"inconclusive_indicator:{name}" for name in indicators)
    blockers.extend(f"evidence_field_missing:{field}" for field in missing_evidence)

    return {
        "finding_id": _text(f.get("finding_id")),
        "finding_status": status,
        "status_rule_applied": rule,
        "manual_validation_status": manual,
        "validation_result": validation_result,
        "duplicate_of": duplicate_of,
        "rejection_reason": rejection_reason,
        "inconclusive_indicators": indicators,
        "gate_results": gate_results,
        "gates_passed": gates_passed,
        "gates_failed": gates_failed,
        "confirmed_allowed": confirmed_allowed,
        "blockers": blockers,
        "missing_evidence_fields": missing_evidence,
        "impact_category": impact_category,
        "impact_hypothesis_recorded": impact_hypothesis,
    }


def load_finding_schema() -> dict[str, Any]:
    if not FINDING_SCHEMA_PATH.is_file():
        return {}
    try:
        return json.loads(FINDING_SCHEMA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _credential_scan(node: Any, prefix: str) -> list[str]:
    errors: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key).lower()
            path = f"{prefix}.{key}" if prefix else str(key)
            if (
                key_text not in _EXEMPT_EXACT_KEYS
                and any(fragment in key_text for fragment in _FORBIDDEN_KEY_FRAGMENTS)
            ):
                errors.append(
                    f"credential-like key is forbidden in finding quality report: {path}"
                )
            errors.extend(_credential_scan(value, path))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            errors.extend(_credential_scan(value, f"{prefix}[{index}]"))
    return errors


def _is_plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _decide_status_from_report(report: Mapping[str, Any]) -> tuple[str, str]:
    gate_results = report["gate_results"]
    passed = {
        gate: bool(
            isinstance(gate_results.get(gate), dict)
            and gate_results[gate].get("passed") is True
        )
        for gate in FIVE_GATES
    }
    return _decide_status(
        report.get("duplicate_of") or "",
        report.get("rejection_reason") or "",
        report.get("manual_validation_status") or "not_started",
        report.get("validation_result"),
        report.get("inconclusive_indicators") or [],
        passed,
        report.get("impact_hypothesis_recorded") is True,
    )


def validate_finding_quality_report(report: Any) -> list[str]:
    """依赖-free 契约校验；返回错误列表（空 = 通过）。

    拒绝：缺必需字段、状态/原因不在枚举、gate 计数与 gate_results 不一致、
    confirmed_allowed 与五门结果不一致、evidence/impact 门与回显输入不一致、
    finding_status 与 status_decision_order 推导不一致、confirmed 带 blockers、
    凭证类键（含规格 4.4 点名的 session_key）。
    """
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["finding quality report must be a dict"]

    schema = load_finding_schema()
    required = schema.get("required") or [
        "finding_id",
        "finding_status",
        "status_rule_applied",
        "manual_validation_status",
        "validation_result",
        "duplicate_of",
        "rejection_reason",
        "inconclusive_indicators",
        "gate_results",
        "gates_passed",
        "gates_failed",
        "confirmed_allowed",
        "blockers",
        "missing_evidence_fields",
        "impact_category",
        "impact_hypothesis_recorded",
    ]
    for field in required:
        if field not in report:
            errors.append(f"missing required field: {field}")
    if errors:
        return errors

    status = report["finding_status"]
    states = schema.get("finding_status_states") or list(FINDING_STATUS_STATES)
    if not isinstance(status, str) or status not in states:
        errors.append(f"finding_status not in schema enum: {status!r}")

    rule = report["status_rule_applied"]
    rule_ids = [item.get("rule") for item in (schema.get("status_decision_order") or [])]
    if not rule_ids:
        rule_ids = list(STATUS_RULE_IDS)
    if not isinstance(rule, str) or rule not in rule_ids:
        errors.append(f"status_rule_applied not in schema enum: {rule!r}")

    manual = report["manual_validation_status"]
    manual_states = schema.get("manual_validation_states") or list(
        MANUAL_VALIDATION_STATES
    )
    if not isinstance(manual, str) or manual not in manual_states:
        errors.append(f"manual_validation_status not in schema enum: {manual!r}")

    validation_result = report["validation_result"]
    vr_states = schema.get("validation_result_states") or list(VALIDATION_RESULT_STATES)
    if validation_result is not None and (
        not isinstance(validation_result, str) or validation_result not in vr_states
    ):
        errors.append(f"validation_result not in schema enum: {validation_result!r}")

    for field in ("finding_id", "duplicate_of", "rejection_reason"):
        if not isinstance(report[field], str):
            errors.append(f"{field} must be a string")

    if not isinstance(report["impact_hypothesis_recorded"], bool):
        errors.append("impact_hypothesis_recorded must be a boolean")

    gates = schema.get("gates") or list(FIVE_GATES)
    gate_results = report["gate_results"]
    gates_usable = isinstance(gate_results, dict) and set(gate_results) == set(gates)
    if not gates_usable:
        errors.append("gate_results must contain exactly the five gates")
    else:
        reason_enums = schema.get("gate_reason_enums") or GATE_REASON_ENUMS
        for gate in gates:
            result = gate_results[gate]
            if (
                not isinstance(result, dict)
                or set(result) != {"passed", "reasons"}
                or not isinstance(result.get("passed"), bool)
            ):
                errors.append(
                    f"gate_results.{gate} must be an object with boolean passed and reasons"
                )
                continue
            reasons = result["reasons"]
            enum = reason_enums.get(gate, [])
            if (
                not isinstance(reasons, list)
                or not reasons
                or not all(isinstance(r, str) for r in reasons)
            ):
                errors.append(
                    f"gate_results.{gate}.reasons must be a non-empty list of strings"
                )
            else:
                for reason in reasons:
                    if reason not in enum:
                        errors.append(
                            f"gate_results.{gate} reason not in schema enum: {reason!r}"
                        )

    gates_passed = report["gates_passed"]
    if not _is_plain_int(gates_passed) or not 0 <= gates_passed <= 5:
        errors.append("gates_passed must be an integer in [0,5]")
    gates_failed = report["gates_failed"]
    if not isinstance(gates_failed, list) or not all(g in gates for g in gates_failed):
        errors.append("gates_failed must be a list of gate names")
    confirmed_allowed = report["confirmed_allowed"]
    if not isinstance(confirmed_allowed, bool):
        errors.append("confirmed_allowed must be a boolean")

    if gates_usable:
        failed = [
            gate
            for gate in gates
            if gate_results[gate].get("passed") is not True
        ]
        if gates_passed != len(gates) - len(failed):
            errors.append("gates_passed does not match gate_results")
        if list(gates_failed) != failed:
            errors.append("gates_failed does not match gate_results")
        if confirmed_allowed != (not failed):
            errors.append("confirmed_allowed must equal all-five-gates-passed")

    missing_evidence = report["missing_evidence_fields"]
    evidence_fields = schema.get("evidence_required_fields") or list(
        EVIDENCE_REQUIRED_FIELDS
    )
    if not isinstance(missing_evidence, list) or not all(
        field in evidence_fields for field in missing_evidence
    ):
        errors.append("missing_evidence_fields must be a list of evidence field names")
    else:
        if len(set(missing_evidence)) != len(missing_evidence):
            errors.append("missing_evidence_fields contains duplicates")
        if gates_usable:
            expected_pass = (not missing_evidence) and validation_result == "verified"
            if gate_results["evidence"].get("passed") is not expected_pass:
                errors.append(
                    "evidence gate result inconsistent with missing_evidence_fields/validation_result"
                )

    impact_category = report["impact_category"]
    impact_categories = schema.get("impact_categories") or list(IMPACT_CATEGORIES)
    if impact_category is not None and (
        not isinstance(impact_category, str) or impact_category not in impact_categories
    ):
        errors.append(f"impact_category not in schema enum: {impact_category!r}")
    if gates_usable:
        expected_impact = impact_category in impact_categories
        if gate_results["security_impact"].get("passed") is not expected_impact:
            errors.append(
                "security_impact gate result inconsistent with impact_category"
            )

    indicators = report["inconclusive_indicators"]
    indicator_enum = schema.get("inconclusive_indicators") or list(
        INCONCLUSIVE_INDICATORS
    )
    if not isinstance(indicators, list) or not all(
        item in indicator_enum for item in indicators
    ):
        errors.append("inconclusive_indicators must be a list of known indicator names")

    blockers = report["blockers"]
    if not isinstance(blockers, list) or not all(
        isinstance(item, str) for item in blockers
    ):
        errors.append("blockers must be a list of strings")

    if gates_usable and all(
        isinstance(gate_results[gate], dict)
        and isinstance(gate_results[gate].get("passed"), bool)
        for gate in gates
    ):
        expected_status, expected_rule = _decide_status_from_report(report)
        if isinstance(status, str) and status != expected_status:
            errors.append(
                f"finding_status inconsistent with classification inputs: "
                f"expected {expected_status!r}, got {status!r}"
            )
        elif status == expected_status and isinstance(rule, str) and rule != expected_rule:
            errors.append(
                f"status_rule_applied does not match status decision order: "
                f"expected {expected_rule!r}"
            )
        if expected_status == "confirmed" and isinstance(blockers, list) and blockers:
            errors.append("confirmed status must carry an empty blockers list")

    errors.extend(_credential_scan(report, ""))
    return errors


# ---------------------------------------------------------------------------
# 补天口径映射与降级抑制（实施规格 2.5-2.9）
# ---------------------------------------------------------------------------

# 规格 2.8 的双字段：exercise_result_class（演练导向）与 platform_submission_class
# （补天收录导向）；2.9 权威字段清单将后者实现为 submission_eligibility，二者不得合并。
FINDING_CLASSES = ("generic_vulnerability", "event_vulnerability")

PLATFORM_SEVERITIES = ("high", "medium", "low", "not_collectible")

EXERCISE_RESULT_CLASSES = ("access", "boundary", "data", "business_impact", "signal_only")

SUBMISSION_ELIGIBILITIES = (
    "eligible",
    "manual_review_required",
    "deprioritized",
    "ignored",
    "duplicate",
)

IMPACT_SCOPES = (
    "single_object",
    "single_user",
    "tenant",
    "organization",
    "multiple_organizations",
    "critical_network",
)

# 规格 2.6：项目内部保留 P0/P1/P2/P3，映射补天口径。
INTERNAL_PRIORITY_TO_PLATFORM_SEVERITY = {
    "P0": "high",
    "P1": "high",
    "P2": "medium",
    "P3": "low",
}

# 影响类别 → 补天三档保守默认表（仅 finding_status == confirmed 且未给
# internal_priority 时使用；2.6 高危七条件需证据级区分，调用方应显式传级）。
PLATFORM_SEVERITY_DEFAULT_BY_IMPACT_CATEGORY = {
    "unauthorized_object_access": "medium",
    "privilege_escalation": "high",
    "boundary_crossing": "medium",
    "sensitive_data_exposure": "medium",
    "code_or_command_execution": "high",
    "network_zone_access": "high",
    "business_state_change": "medium",
    "resource_consumption_or_availability": "low",
    "auditable_attack_chain": "high",
}

# 影响类别 → 演练结果类别（规格 2.4/2.8：权限/边界/数据/业务影响）。
EXERCISE_RESULT_CLASS_BY_IMPACT_CATEGORY = {
    "unauthorized_object_access": "data",
    "privilege_escalation": "access",
    "boundary_crossing": "boundary",
    "sensitive_data_exposure": "data",
    "code_or_command_execution": "access",
    "network_zone_access": "boundary",
    "business_state_change": "business_impact",
    "resource_consumption_or_availability": "business_impact",
    "auditable_attack_chain": "access",
}

# 规格 2.5：通用漏洞必须同时记录的八字段。
GENERIC_VULNERABILITY_FIELDS = (
    "product_or_component",
    "product_version_or_build",
    "vulnerability_family",
    "affected_condition",
    "vendor_or_upstream_reference",
    "affected_instance_count",
    "reproduction_stability",
    "whether_public_or_0day",
)

# 规格 2.7 十条降级/忽略规则（RULE_9 通常由 manual_validation_status 派生，
# 仍保留为显式 flag 以便人工强制）。检测器属后续批次，这里只做确定性判定。
SUPPRESSION_RULES: dict[str, dict[str, str]] = {
    "RULE_1_LOW_VALUE_PATTERNS": {
        "outcome": "deprioritized",
        "description": "Open redirect, front-desk personal weak passwords, open registration, Self-XSS, mail bombing (spec 2.7 rule 1) unless higher impact is proven.",
    },
    "RULE_2_CONFIG_HARDENING_ONLY": {
        "outcome": "deprioritized",
        "description": "CORS misconfiguration or generic hardening gap without cross-site read, privilege bypass, or sensitive impact (spec 2.7 rule 2).",
    },
    "RULE_3_UNEXPLOITABLE_INFO": {
        "outcome": "ignored",
        "description": "Internal hostnames, IPs, paths, banners, expired keys, or invalid tokens that cannot be exploited directly (spec 2.7 rule 3).",
    },
    "RULE_4_NO_SENSITIVE_DATA": {
        "outcome": "ignored",
        "description": "Desensitized info, public files, or API disclosures without usable content (spec 2.7 rule 4).",
    },
    "RULE_5_FORBIDDEN_PROOF_REQUIRED": {
        "outcome": "ignored",
        "description": "Results provable only by damaging the business, denial of service, or data tampering (spec 2.7 rule 5; those actions are forbidden anyway).",
    },
    "RULE_6_SAME_TYPE_OVER_LIMIT": {
        "outcome": "duplicate",
        "description": "More than three results of the same vulnerability type on the same system (spec 2.7 rule 6).",
    },
    "RULE_7_SQLI_PER_ENDPOINT_MERGE": {
        "outcome": "duplicate",
        "description": "SQL injection merges per endpoint; multiple parameters on one endpoint count once (spec 2.7 rule 7).",
    },
    "RULE_8_GENERIC_ROOT_CAUSE_DUPLICATE": {
        "outcome": "duplicate",
        "description": "The same generic-product root cause across enterprises must merge into one generic finding (spec 2.7 rule 8).",
    },
    "RULE_9_UNVERIFIED_AI_CANDIDATE": {
        "outcome": "manual_review_required",
        "description": "Unverified AI-generated candidates must not enter formal vulnerability submission (spec 2.7 rule 9); auto-derived from manual_validation_status != verified.",
    },
    "RULE_10_LOW_VALUE_SITE": {
        "outcome": "deprioritized",
        "description": "Unmaintained sites, personal small sites, low-impact templates marked low_value_or_deprioritized; no splitting for volume (spec 2.7 rule 10).",
    },
}

_DUPLICATE_OUTCOME_RULES = frozenset(
    rule for rule, spec in SUPPRESSION_RULES.items() if spec["outcome"] == "duplicate"
)
_IGNORED_OUTCOME_RULES = frozenset(
    rule for rule, spec in SUPPRESSION_RULES.items() if spec["outcome"] == "ignored"
)
_DEPRIORITIZED_OUTCOME_RULES = frozenset(
    rule for rule, spec in SUPPRESSION_RULES.items() if spec["outcome"] == "deprioritized"
)


def map_platform_severity(internal_priority: str | None) -> str | None:
    """规格 2.6 三档映射：P0/P1→high、P2→medium、P3→low；未知输入返回 None。"""
    if internal_priority is None:
        return None
    return INTERNAL_PRIORITY_TO_PLATFORM_SEVERITY.get(str(internal_priority).strip())


def classify_finding_class(finding: Mapping[str, Any]) -> tuple[str, list[str]]:
    """规格 2.5：给出 product_or_component 即按通用漏洞归类并核对八字段，否则事件漏洞。"""
    product = _text(finding.get("product_or_component"))
    if not product:
        return "event_vulnerability", []
    missing = [
        field
        for field in GENERIC_VULNERABILITY_FIELDS
        if not _field_present(finding.get(field))
    ]
    return "generic_vulnerability", missing


def _resolve_platform_severity(
    finding_status: str,
    impact_category: str | None,
    internal_priority: str | None,
) -> tuple[str, str]:
    mapped = map_platform_severity(internal_priority)
    if finding_status == "confirmed":
        if mapped is not None:
            return mapped, "internal_priority"
        if impact_category in PLATFORM_SEVERITY_DEFAULT_BY_IMPACT_CATEGORY:
            return (
                PLATFORM_SEVERITY_DEFAULT_BY_IMPACT_CATEGORY[impact_category],
                "impact_category_default",
            )
        return "low", "status_ceiling"
    if finding_status in ("needs_manual_validation", "candidate"):
        # 规格 2.6：五门未齐不得建议高危/中危；低危候选/线索允许。
        return "low", "status_ceiling"
    return "not_collectible", "status_ceiling"


def _resolve_exercise_result_class(
    finding_status: str, impact_category: str | None
) -> str:
    if finding_status == "confirmed" or finding_status in (
        "needs_manual_validation",
        "candidate",
    ):
        if impact_category in EXERCISE_RESULT_CLASS_BY_IMPACT_CATEGORY:
            return EXERCISE_RESULT_CLASS_BY_IMPACT_CATEGORY[impact_category]
    return "signal_only"


def _resolve_submission_eligibility(
    finding_status: str,
    manual_validation_status: str,
    suppression_flags: list[str],
) -> tuple[str, list[str]]:
    """规格 2.7 优先序：duplicate > ignored > manual_review_required > deprioritized > eligible。"""
    applied = [flag for flag in suppression_flags if flag in SUPPRESSION_RULES]
    if finding_status == "duplicate" or any(
        flag in _DUPLICATE_OUTCOME_RULES for flag in applied
    ):
        return "duplicate", applied
    if finding_status in ("signal", "rejected", "inconclusive", "blocked") or any(
        flag in _IGNORED_OUTCOME_RULES for flag in applied
    ):
        return "ignored", applied
    if finding_status == "needs_manual_validation" or any(
        flag == "RULE_9_UNVERIFIED_AI_CANDIDATE" for flag in applied
    ):
        # 规格 2.7 规则 9：未经人工验证的 AI 候选不得进入正式漏洞提交。
        return "manual_review_required", applied
    if any(flag in _DEPRIORITIZED_OUTCOME_RULES for flag in applied):
        return "deprioritized", applied
    if finding_status == "candidate":
        return "deprioritized", applied
    return "eligible", applied


def build_finding_classification(finding: Mapping[str, Any] | None) -> dict[str, Any]:
    """汇总规格 2.9 九字段 + 抑制分析；内部先跑 evaluate_finding_quality 保证一致。"""
    f = dict(finding or {})
    quality = evaluate_finding_quality(f)
    status = quality["finding_status"]
    manual = quality["manual_validation_status"]

    raw_flags = f.get("suppression_flags") or []
    suppression_flags = [str(flag).strip() for flag in raw_flags if str(flag).strip()]
    unknown_flags = [flag for flag in suppression_flags if flag not in SUPPRESSION_RULES]

    eligibility, applied_rules = _resolve_submission_eligibility(
        status, manual, suppression_flags
    )
    finding_class, generic_missing = classify_finding_class(f)

    impact_category = quality["impact_category"]
    severity, severity_basis = _resolve_platform_severity(
        status, impact_category, f.get("internal_priority")
    )
    exercise_class = _resolve_exercise_result_class(status, impact_category)

    impact_scope = f.get("impact_scope")
    if impact_scope not in IMPACT_SCOPES:
        impact_scope = "single_object"

    reason_parts: list[str] = []
    if eligibility != "eligible":
        if quality["rejection_reason"]:
            reason_parts.append(f"rejection_reason: {quality['rejection_reason']}")
        elif quality["duplicate_of"]:
            reason_parts.append(f"duplicate_of: {quality['duplicate_of']}")
        elif quality["blockers"]:
            reason_parts.append(f"blockers: {', '.join(quality['blockers'])}")
        if applied_rules:
            reason_parts.append(f"suppression: {', '.join(applied_rules)}")
        if not reason_parts:
            reason_parts.append(f"finding_status={status}")

    return {
        "finding_status": status,
        "finding_class": finding_class,
        "platform_severity": severity,
        "platform_severity_basis": severity_basis,
        "exercise_result_class": exercise_class,
        "submission_eligibility": eligibility,
        "manual_validation_status": manual,
        "impact_scope": impact_scope,
        "root_cause_signature": _text(f.get("root_cause_signature")),
        "merge_group_id": _text(f.get("merge_group_id")),
        "reason_not_a_vulnerability": "; ".join(reason_parts),
        "suppression_rules_applied": applied_rules,
        "suppression_rules_unknown": unknown_flags,
        "generic_fields_missing": generic_missing,
        "quality_report": quality,
    }


def validate_finding_classification(classification: Any) -> list[str]:
    """依赖-free classification 校验；返回错误列表（空 = 通过）。

    除枚举检查外强制与 finding_status 的交叉一致性：eligible ⟺ confirmed 且
    manual verified 且无抑制规则；high/medium 仅 confirmed；duplicate 需
    duplicate 状态或合并类抑制规则；manual_review_required 需未人工验证状态或
    RULE_9；quality_report 子报告本身必须通过 validate_finding_quality_report。
    """
    errors: list[str] = []
    if not isinstance(classification, dict):
        return ["finding classification must be a dict"]

    required = (
        "finding_status",
        "finding_class",
        "platform_severity",
        "exercise_result_class",
        "submission_eligibility",
        "manual_validation_status",
        "impact_scope",
        "root_cause_signature",
        "merge_group_id",
        "reason_not_a_vulnerability",
        "suppression_rules_applied",
        "quality_report",
    )
    for field in required:
        if field not in classification:
            errors.append(f"missing required field: {field}")
    if errors:
        return errors

    schema = load_finding_schema()
    enums = schema.get("classification_enums") or {}
    enum_checks = (
        ("finding_class", FINDING_CLASSES),
        ("platform_severity", PLATFORM_SEVERITIES),
        ("exercise_result_class", EXERCISE_RESULT_CLASSES),
        ("submission_eligibility", SUBMISSION_ELIGIBILITIES),
        ("impact_scope", IMPACT_SCOPES),
    )
    for field, fallback in enum_checks:
        value = classification[field]
        allowed = enums.get(field) or list(fallback)
        if not isinstance(value, str) or value not in allowed:
            errors.append(f"{field} not in schema enum: {value!r}")

    status = classification["finding_status"]
    for field in ("root_cause_signature", "merge_group_id", "reason_not_a_vulnerability"):
        if not isinstance(classification[field], str):
            errors.append(f"{field} must be a string")

    applied = classification["suppression_rules_applied"]
    catalog = schema.get("suppression_rules") or SUPPRESSION_RULES
    if not isinstance(applied, list) or not all(isinstance(rule, str) for rule in applied):
        errors.append("suppression_rules_applied must be a list of rule ids")
    else:
        for rule in applied:
            if rule not in catalog:
                errors.append(f"suppression rule id not in catalog: {rule!r}")
        if len(set(applied)) != len(applied):
            errors.append("suppression_rules_applied contains duplicates")

    quality_report = classification["quality_report"]
    quality_errors = validate_finding_quality_report(quality_report)
    if quality_errors:
        errors.extend(f"quality_report: {e}" for e in quality_errors)
        return errors

    # 与 quality_report 的交叉一致性
    if isinstance(status, str) and quality_report["finding_status"] != status:
        errors.append("finding_status does not match quality_report.finding_status")

    manual = quality_report.get("manual_validation_status")
    eligibility = classification["submission_eligibility"]
    severity = classification["platform_severity"]
    duplicate_flags = any(rule in _DUPLICATE_OUTCOME_RULES for rule in applied or []) if isinstance(applied, list) else False
    ignored_flags = any(rule in _IGNORED_OUTCOME_RULES for rule in applied or []) if isinstance(applied, list) else False
    rule9 = isinstance(applied, list) and "RULE_9_UNVERIFIED_AI_CANDIDATE" in applied

    if eligibility == "eligible":
        if status != "confirmed" or manual != "verified":
            errors.append("eligible requires finding_status confirmed and manual_validation_status verified")
        if isinstance(applied, list) and applied:
            errors.append("eligible must not carry applied suppression rules")
    if eligibility == "duplicate" and status != "duplicate" and not duplicate_flags:
        errors.append("duplicate eligibility requires duplicate status or a duplicate-outcome suppression rule")
    if eligibility == "manual_review_required" and status != "needs_manual_validation" and not rule9:
        errors.append("manual_review_required requires needs_manual_validation status or RULE_9")
    if severity in ("high", "medium") and status != "confirmed":
        errors.append(f"platform_severity {severity!r} may only be suggested for confirmed findings (spec 2.6)")
    if severity == "not_collectible" and status in (
        "confirmed",
        "needs_manual_validation",
        "candidate",
    ):
        errors.append(f"platform_severity not_collectible conflicts with finding_status {status!r}")
    if severity in ("low",) and status in ("signal", "rejected", "inconclusive", "blocked", "duplicate"):
        errors.append(f"platform_severity low conflicts with finding_status {status!r}")
    if (
        classification["exercise_result_class"] == "signal_only"
        and status == "confirmed"
        and quality_report.get("impact_category")
    ):
        errors.append("exercise_result_class signal_only conflicts with a proven impact category")
    if (
        classification["exercise_result_class"] != "signal_only"
        and status in ("signal", "rejected", "inconclusive", "blocked", "duplicate")
    ):
        errors.append(
            f"exercise_result_class {classification['exercise_result_class']!r} requires a proven impact-bearing status"
        )
    if ignored_flags and eligibility not in ("ignored", "duplicate"):
        errors.append("an ignored-outcome suppression rule must force ignored (or duplicate) eligibility")

    return errors
