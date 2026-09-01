"""evidence_gate.py —— 报告发布前证据门（实施规格 4.4，1169-1186 行）。

离线纯函数：输入待发布的 finding 行列表与必传的文件系统 root（evidence_ref 相对解析），
输出符合 contracts/finding_evidence_schema.json 的门报告。零网络请求。

发布前必须拒绝（规格 4.4 六类 + 13.2 空 ledger 负例）：
  缺 finding_id / evidence_ref 为空或路径不存在 / 没有 validation result /
  confirmed(或 accepted_risk) 缺 reviewer、reviewed_at / 报告把 candidate 当 confirmed /
  报告含凭证、token、session_key、AppSecret 或敏感数据原文 / 空 source ledger

凭证内容扫描按设计过 inclusion（fail-closed）：报告中出现凭证样赋值文本即违例——
报告只应引用证据文件，不应携带敏感赋值。违例明细只记 JSON 位置，绝不回显凭证值。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from authorized_assessment.quality.finding_quality_gate import FINDING_STATUS_STATES

EVIDENCE_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "contracts" / "finding_evidence_schema.json"
)

GATE_STATUS_STATES = ("PASS", "REJECTED")

PRESENTED_AS_FORMS = ("confirmed", "candidate", "signal", "informational")

VIOLATION_CODES = (
    "missing_finding_id",
    "finding_status_missing",
    "evidence_ref_missing",
    "evidence_path_not_found",
    "validation_result_missing",
    "validation_result_unverified_for_confirmed",
    "reviewer_missing_for_confirmed",
    "reviewed_at_missing_for_confirmed",
    "candidate_presented_as_confirmed",
    "credential_key_detected",
    "credential_content_detected",
    "empty_source_ledger",
)

# 与 finding_quality_gate 相同的键纪律，另含规格 4.4 点名的 session_key
# （AppSecret 已被 "secret" 覆盖）。
_FORBIDDEN_KEY_FRAGMENTS = (
    "cookie",
    "token",
    "password",
    "passwd",
    "secret",
    "authorization",
    "session_id",
    "credential",
    "session_key",
)

# 值内容扫描：凭证样赋值文本（Cookie: xxx / Authorization: Bearer xxx /
# token=xxx / session_key: xxx / AppSecret=xxx / password: xxx 等）。
_CREDENTIAL_CONTENT_PATTERN = re.compile(
    r"(?i)\b(cookie|authorization|appsecret|session_key|access_token|refresh_token"
    r"|api_key|apikey|token|password|passwd)\b\s*[:=]\s*\S"
)

# 精确豁免：与 finding_quality_gate 同一先例（扫描到结构键时不会误伤，
# 这里主要是防御未来把扫描器复用到含 gate 名的载荷上）。
_EXEMPT_EXACT_KEYS = frozenset({"authorization"})


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _field_present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value)
    return value is not None


def _iter_strings(node: Any, prefix: str):
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _iter_strings(value, path)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _iter_strings(value, f"{prefix}[{index}]")
    elif isinstance(node, str):
        yield prefix, node


def _credential_key_paths(node: Any, prefix: str) -> list[str]:
    """键扫描：返回含凭证片段的键的 JSON 路径（不返回值）。"""
    hits: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key).lower()
            path = f"{prefix}.{key}" if prefix else str(key)
            if (
                key_text not in _EXEMPT_EXACT_KEYS
                and any(fragment in key_text for fragment in _FORBIDDEN_KEY_FRAGMENTS)
            ):
                hits.append(path)
            hits.extend(_credential_key_paths(value, path))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            hits.extend(_credential_key_paths(value, f"{prefix}[{index}]"))
    return hits


def _credential_value_paths(node: Any, prefix: str) -> list[str]:
    """值内容扫描：返回命中凭证样赋值文本的 JSON 路径（不返回命中内容）。"""
    hits: list[str] = []
    for path, text in _iter_strings(node, prefix):
        if _CREDENTIAL_CONTENT_PATTERN.search(text):
            hits.append(path)
    return hits


def _evidence_ref_paths(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        refs: list[str] = []
        for item in value:
            if isinstance(item, str) and item.strip():
                refs.append(item.strip())
        return refs
    return []


def evaluate_evidence_gate(
    rows: Iterable[Mapping[str, Any]],
    root: str | Path,
    *,
    source_ledger: str | Path | None = None,
) -> dict[str, Any]:
    """对报告待发布 finding 行执行证据门；纯函数、零网络。

    rows 中每行契约：finding_id / finding_status / evidence_ref / validation_result
    （published_finding_required_fields），可选 presented_as / disposition / reviewer /
    reviewed_at。evidence_ref 相对 root 解析（绝对路径按原样）。
    """
    base_root = Path(root)
    violations: list[dict[str, Any]] = []
    row_list = [dict(row) for row in rows]

    def _violation(code: str, detail: str, finding_id: str = "") -> None:
        violations.append(
            {"code": code, "finding_id": finding_id, "detail": detail}
        )

    for index, row in enumerate(row_list):
        prefix = f"rows[{index}]"
        finding_id = _text(row.get("finding_id"))

        if not finding_id:
            _violation("missing_finding_id", f"{prefix}: finding_id is missing or empty")

        finding_status = row.get("finding_status")
        if (
            not _field_present(finding_status)
            or finding_status not in FINDING_STATUS_STATES
        ):
            # 状态缺失或不在 8 状态枚举内都无法核验主张，fail-closed。
            _violation(
                "finding_status_missing",
                f"{prefix}: finding_status missing or not in the 8-state enum: {finding_status!r}",
                finding_id,
            )
            finding_status = None

        presented_as = row.get("presented_as")
        if _field_present(presented_as) and presented_as not in PRESENTED_AS_FORMS:
            # 非法呈现形式按最保守处理：视为 confirmed 主张，交给状态一致性检查。
            presented_as = "confirmed"

        # 规格 4.4 第 5 类：报告把 candidate 当 confirmed。
        if presented_as == "confirmed" and finding_status != "confirmed":
            _violation(
                "candidate_presented_as_confirmed",
                f"{prefix}: presented_as=confirmed but finding_status={finding_status!r}",
                finding_id,
            )

        # 规格 4.4 第 2 类：evidence_ref 为空或路径不存在。
        refs = _evidence_ref_paths(row.get("evidence_ref"))
        if not refs:
            _violation("evidence_ref_missing", f"{prefix}: evidence_ref is empty", finding_id)
        else:
            for ref in refs:
                ref_path = Path(ref)
                resolved = ref_path if ref_path.is_absolute() else base_root / ref_path
                if not resolved.exists():
                    _violation(
                        "evidence_path_not_found",
                        f"{prefix}: evidence path does not exist: {ref}",
                        finding_id,
                    )

        # 规格 4.4 第 3 类：没有 validation result。
        validation_result = row.get("validation_result")
        if not _field_present(validation_result):
            _violation(
                "validation_result_missing",
                f"{prefix}: validation_result is missing",
                finding_id,
            )

        # 规格 4.4 第 4 类：confirmed / accepted_risk 需要 reviewer 与 reviewed_at。
        confirmed_claim = finding_status == "confirmed" or presented_as == "confirmed"
        accepted_risk = _text(row.get("disposition")) == "accepted_risk"
        if confirmed_claim and _field_present(validation_result) and validation_result != "verified":
            _violation(
                "validation_result_unverified_for_confirmed",
                f"{prefix}: confirmed rows require validation_result=verified, got {validation_result!r}",
                finding_id,
            )
        if confirmed_claim or accepted_risk:
            if not _field_present(row.get("reviewer")):
                _violation(
                    "reviewer_missing_for_confirmed",
                    f"{prefix}: reviewer is required for confirmed/accepted_risk rows",
                    finding_id,
                )
            if not _field_present(row.get("reviewed_at")):
                _violation(
                    "reviewed_at_missing_for_confirmed",
                    f"{prefix}: reviewed_at is required for confirmed/accepted_risk rows",
                    finding_id,
                )

        # 规格 4.4 第 6 类：报告含凭证（键 + 值内容）。
        for path in _credential_key_paths(row, prefix):
            _violation("credential_key_detected", f"{prefix}: credential-like key at {path}", finding_id)
        for path in _credential_value_paths(row, prefix):
            _violation(
                "credential_content_detected",
                f"{prefix}: credential-like assignment text at {path} (content withheld)",
                finding_id,
            )

    # 13.2 负例：空 ledger。
    if source_ledger is not None:
        ledger_path = Path(source_ledger)
        if not ledger_path.is_file():
            _violation("empty_source_ledger", f"source ledger is missing: {ledger_path}")
        elif not ledger_path.read_text(encoding="utf-8", errors="replace").strip():
            _violation("empty_source_ledger", f"source ledger has zero rows: {ledger_path}")

    gate_status = "PASS" if not violations else "REJECTED"
    return {
        "gate_status": gate_status,
        "rows_checked": len(row_list),
        "violations": violations,
    }


def load_evidence_schema() -> dict[str, Any]:
    if not EVIDENCE_SCHEMA_PATH.is_file():
        return {}
    try:
        return json.loads(EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _is_plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_evidence_gate_report(report: Any) -> list[str]:
    """依赖-free 门报告校验；返回错误列表（空 = 通过）。

    拒绝：缺字段、gate_status 不在枚举、违例码不在枚举、PASS 却带违例或
    REJECTED 却零违例、违例缺 detail、凭证类键、违例明细中夹带凭证样赋值文本
    （门报告自身也必须无凭证内容）。
    """
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["evidence gate report must be a dict"]

    schema = load_evidence_schema()
    required = schema.get("required") or ["gate_status", "rows_checked", "violations"]
    for field in required:
        if field not in report:
            errors.append(f"missing required field: {field}")
    if errors:
        return errors

    gate_status = report["gate_status"]
    status_states = schema.get("gate_status_states") or list(GATE_STATUS_STATES)
    if not isinstance(gate_status, str) or gate_status not in status_states:
        errors.append(f"gate_status not in schema enum: {gate_status!r}")

    rows_checked = report["rows_checked"]
    if not _is_plain_int(rows_checked) or rows_checked < 0:
        errors.append("rows_checked must be a non-negative integer")

    violations = report["violations"]
    violation_codes = (
        (schema.get("violation_codes") or None) or list(VIOLATION_CODES)
    )
    if not isinstance(violations, list):
        errors.append("violations must be a list")
    else:
        for index, violation in enumerate(violations):
            prefix = f"violations[{index}]"
            if not isinstance(violation, dict):
                errors.append(f"{prefix} must be an object")
                continue
            code = violation.get("code")
            if not isinstance(code, str) or code not in violation_codes:
                errors.append(f"{prefix}.code not in schema enum: {code!r}")
            if not isinstance(violation.get("detail"), str) or not violation["detail"]:
                errors.append(f"{prefix}.detail must be a non-empty string")
            finding_id = violation.get("finding_id", "")
            if not isinstance(finding_id, str):
                errors.append(f"{prefix}.finding_id must be a string")

    if isinstance(gate_status, str) and isinstance(violations, list):
        if gate_status == "PASS" and violations:
            errors.append("PASS gate report must not carry violations")
        if gate_status == "REJECTED" and not violations:
            errors.append("REJECTED gate report must carry at least one violation")

    # 门报告自身凭证纪律：键 + 值内容（违例明细不得夹带凭证样文本）。
    for path in _credential_key_paths(report, ""):
        errors.append(
            f"credential-like key is forbidden in evidence gate report: {path}"
        )
    for path, text in _iter_strings(report, ""):
        if _CREDENTIAL_CONTENT_PATTERN.search(text):
            errors.append(
                f"credential-like assignment text is forbidden in evidence gate report: {path}"
            )
    return errors
