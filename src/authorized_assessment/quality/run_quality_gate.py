"""run_quality_gate.py —— run 质量状态判定器（实施规格 3.2）。

离线纯函数：输入唯一 in-scope target 集合与 probe 行列表，输出符合
contracts/run_quality_schema.json 的质量报告。零网络请求，不耦合具体 run 文件布局。

强制门控（任一触发 → 状态不得为 VALID，且禁止"未发现漏洞"结论）：
  probe_coverage < 0.90 / probe_ok_ratio < 0.50
  rate_limit_skips / unique_in_scope_targets > 0.20
  transport_error_ratio > 0.30 / 所有目标都没有成功响应 / WAF 比例超过配置阈值

状态优先序：BLOCKED > FAILED > INCONCLUSIVE > PARTIAL > VALID；
negative_conclusion_allowed 当且仅当 VALID。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping

QUALITY_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "contracts" / "run_quality_schema.json"
)

QUALITY_STATUS_STATES = ("VALID", "PARTIAL", "INCONCLUSIVE", "FAILED", "BLOCKED")

GATE_REASONS = (
    "probe_coverage_below_threshold",
    "probe_ok_ratio_below_threshold",
    "rate_limit_skip_ratio_high",
    "transport_error_ratio_high",
    "no_successful_probe",
    "waf_block_ratio_exceeded",
    "no_in_scope_targets",
    "run_blocked",
)

TRANSPORT_ERROR_CLASSES = frozenset({"dns", "timeout", "connection"})

_FORBIDDEN_KEY_FRAGMENTS = (
    "cookie",
    "token",
    "password",
    "passwd",
    "secret",
    "authorization",
    "session_id",
    "credential",
)


@dataclass(frozen=True)
class GateThresholds:
    """强制门控阈值（默认值固化在 contracts/run_quality_schema.json）。"""

    probe_coverage_min: float = 0.90
    probe_ok_ratio_min: float = 0.50
    rate_limit_skip_ratio_max: float = 0.20
    transport_error_ratio_max: float = 0.30
    waf_block_ratio_max: float = 0.10

    def as_dict(self) -> dict[str, float]:
        return {
            "probe_coverage_min": self.probe_coverage_min,
            "probe_ok_ratio_min": self.probe_ok_ratio_min,
            "rate_limit_skip_ratio_max": self.rate_limit_skip_ratio_max,
            "transport_error_ratio_max": self.transport_error_ratio_max,
            "waf_block_ratio_max": self.waf_block_ratio_max,
        }


def _ratio(part: int, total: int) -> float:
    return part / total if total else 0.0


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return round(value, 4)


def evaluate_run_quality(
    in_scope_targets: Iterable[str],
    probe_rows: Iterable[Mapping[str, Any]],
    *,
    blocked: bool = False,
    thresholds: GateThresholds | None = None,
) -> dict[str, Any]:
    """从 in-scope 目标与 probe 行推导质量报告；纯函数、可重复调用结果一致。

    probe 行契约：{"target": str, "ok": bool, "error_class": str|None}，
    error_class 认可 dns / timeout / connection / waf / rate_limit / 其他。
    """
    th = thresholds or GateThresholds()
    targets = {str(t) for t in in_scope_targets if str(t).strip()}
    rows = [dict(r) for r in probe_rows]

    ok_rows = sum(1 for r in rows if r.get("ok") is True)
    dns_errors = sum(1 for r in rows if r.get("error_class") == "dns")
    timeouts = sum(1 for r in rows if r.get("error_class") == "timeout")
    waf_blocks = sum(1 for r in rows if r.get("error_class") == "waf")
    rate_limit_skips = sum(1 for r in rows if r.get("error_class") == "rate_limit")
    transport_errors = sum(1 for r in rows if r.get("error_class") in TRANSPORT_ERROR_CLASSES)

    ok_in_scope_targets = {
        str(r.get("target"))
        for r in rows
        if r.get("ok") is True and str(r.get("target")) in targets
    }
    unique_in_scope_targets = len(targets)
    unique_targets_with_successful_probe = len(ok_in_scope_targets)

    probe_coverage = _clamp01(_ratio(unique_targets_with_successful_probe, unique_in_scope_targets))
    probe_ok_ratio = _clamp01(_ratio(ok_rows, len(rows)))
    rate_limit_skip_ratio = _ratio(rate_limit_skips, unique_in_scope_targets)
    transport_error_ratio = _ratio(transport_errors, len(rows))
    waf_block_ratio = _ratio(waf_blocks, len(rows))

    reasons: list[str] = []
    if unique_in_scope_targets == 0:
        reasons.append("no_in_scope_targets")
    else:
        if probe_coverage < th.probe_coverage_min:
            reasons.append("probe_coverage_below_threshold")
        if rate_limit_skip_ratio > th.rate_limit_skip_ratio_max:
            reasons.append("rate_limit_skip_ratio_high")
        if unique_targets_with_successful_probe == 0:
            reasons.append("no_successful_probe")
    if rows:
        if probe_ok_ratio < th.probe_ok_ratio_min:
            reasons.append("probe_ok_ratio_below_threshold")
        if transport_error_ratio > th.transport_error_ratio_max:
            reasons.append("transport_error_ratio_high")
        if waf_block_ratio > th.waf_block_ratio_max:
            reasons.append("waf_block_ratio_exceeded")
    if blocked:
        reasons.append("run_blocked")

    if blocked:
        status = "BLOCKED"
    elif unique_in_scope_targets and unique_targets_with_successful_probe == 0:
        status = "FAILED"
    elif reasons:
        status = "INCONCLUSIVE"
    elif transport_errors or waf_blocks or rate_limit_skips:
        status = "PARTIAL"
    else:
        status = "VALID"

    return {
        "quality_status": status,
        "negative_conclusion_allowed": status == "VALID",
        "unique_in_scope_targets": unique_in_scope_targets,
        "unique_targets_with_successful_probe": unique_targets_with_successful_probe,
        "probe_coverage": probe_coverage,
        "probe_ok_ratio": probe_ok_ratio,
        "transport_errors": transport_errors,
        "dns_errors": dns_errors,
        "timeouts": timeouts,
        "waf_blocks": waf_blocks,
        "rate_limit_skips": rate_limit_skips,
        "quality_gate_reasons": reasons,
    }


def load_schema() -> dict[str, Any]:
    if not QUALITY_SCHEMA_PATH.is_file():
        return {}
    try:
        return json.loads(QUALITY_SCHEMA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _credential_scan(node: Any, prefix: str) -> list[str]:
    errors: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key).lower()
            path = f"{prefix}.{key}" if prefix else str(key)
            if any(fragment in key_text for fragment in _FORBIDDEN_KEY_FRAGMENTS):
                errors.append(f"credential-like key is forbidden in quality report: {path}")
            errors.extend(_credential_scan(value, path))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            errors.extend(_credential_scan(value, f"{prefix}[{index}]"))
    return errors


def _is_plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_quality_report(report: Any) -> list[str]:
    """依赖-free 契约校验；返回错误列表（空 = 通过）。

    拒绝（规格 13.2 负例）：coverage > 1、缺必需字段、状态/原因不在枚举、
    negative_conclusion_allowed 与状态不一致、无门控原因却非 VALID、凭证类键。
    """
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["quality report must be a dict"]

    schema = load_schema()
    required = schema.get("required") or list(report.keys())
    for field in required:
        if field not in report:
            errors.append(f"missing required field: {field}")
    if errors:
        return errors

    schema_states = schema.get("quality_status_states") or list(QUALITY_STATUS_STATES)
    status = report["quality_status"]
    if not isinstance(status, str) or status not in schema_states:
        errors.append(f"quality_status not in schema enum: {status!r}")

    if not isinstance(report["negative_conclusion_allowed"], bool):
        errors.append("negative_conclusion_allowed must be a boolean")

    for field in (
        "unique_in_scope_targets",
        "unique_targets_with_successful_probe",
        "transport_errors",
        "dns_errors",
        "timeouts",
        "waf_blocks",
        "rate_limit_skips",
    ):
        value = report[field]
        if not _is_plain_int(value) or value < 0:
            errors.append(f"{field} must be a non-negative integer")

    if (
        _is_plain_int(report["unique_targets_with_successful_probe"])
        and _is_plain_int(report["unique_in_scope_targets"])
        and report["unique_targets_with_successful_probe"] > report["unique_in_scope_targets"]
    ):
        errors.append("unique_targets_with_successful_probe exceeds unique_in_scope_targets")

    for field in ("probe_coverage", "probe_ok_ratio"):
        value = report[field]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            errors.append(f"{field} must be a number")
        elif not 0.0 <= float(value) <= 1.0:
            errors.append(f"{field} must be clamped to [0,1], got {value}")

    reasons = report["quality_gate_reasons"]
    schema_reasons = None
    schema_reason_items = (schema.get("properties") or {}).get("quality_gate_reasons", {}).get("items", {})
    if schema_reason_items.get("enum"):
        schema_reasons = schema_reason_items["enum"]
    if not isinstance(reasons, list) or not all(isinstance(r, str) for r in reasons):
        errors.append("quality_gate_reasons must be a list of strings")
    else:
        if len(set(reasons)) != len(reasons):
            errors.append("quality_gate_reasons contains duplicates")
        if schema_reasons:
            for reason in reasons:
                if reason not in schema_reasons:
                    errors.append(f"quality_gate_reason not in schema enum: {reason!r}")
        if status == "VALID" and reasons:
            errors.append("VALID status must not carry gate reasons")
        if status != "VALID" and not reasons:
            errors.append(f"non-VALID status {status!r} must carry at least one gate reason")

    if isinstance(report["negative_conclusion_allowed"], bool) and isinstance(status, str):
        expected = status == "VALID"
        if report["negative_conclusion_allowed"] != expected:
            errors.append(
                "negative_conclusion_allowed must be true if and only if quality_status is VALID"
            )

    errors.extend(_credential_scan(report, ""))
    return errors


def load_thresholds_overrides(schema: Mapping[str, Any] | None = None) -> GateThresholds:
    """从契约文件读取门控阈值，保证实现与 schema 不漂移；文件缺失时用内置默认。"""
    data = dict(schema) if schema else load_schema()
    gate = data.get("gate_thresholds") or {}
    defaults = GateThresholds()
    fields = {f: gate[f] for f in defaults.as_dict() if f in gate}
    return replace(defaults, **fields) if fields else defaults
