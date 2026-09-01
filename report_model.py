"""Canonical report finding normalization and deterministic aggregation."""
from __future__ import annotations

import re
from collections import OrderedDict
from copy import deepcopy
from urllib.parse import urlsplit

_MISSING = {"", "-", "--", "n/a", "na", "none", "null", "todo", "待补充", "待定"}
_BOUNDARY_MARKERS = (
    "复核边界", "勿外推", "未实测", "未测试", "仅静态", "不构成", "不可伪造", "限制条件", "边界说明",
)


def text(value: object, default: str = "") -> str:
    if value is None:
        return default
    value = str(value).strip()
    return default if not value or value.lower() in _MISSING else value


def _first(row: dict, *keys: str, default: str = "") -> str:
    for key in keys:
        value = text(row.get(key))
        if value:
            return value
    return default


def _as_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [item for item in value if text(item)]
    return [value] if text(value) else []


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        value = text(value)
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _merge_values(values: list, *, dict_key: str | None = None) -> list:
    result: list = []
    seen: set[str] = set()
    for value in values:
        if isinstance(value, dict):
            marker = text(value.get(dict_key or "cmd")) or repr(sorted(value.items()))
            item = deepcopy(value)
        else:
            marker = text(value)
            item = value
        if marker and marker not in seen:
            seen.add(marker)
            result.append(item)
    return result


def asset_identity(row: dict) -> str:
    explicit = _first(row, "asset_identity", "asset")
    source = _first(row, "base_url", "url", "target_url", "endpoint")
    fallback_name = _first(row, "target_name", "system", "app_name", "miniapp_name")
    candidate = explicit or source or fallback_name or "待补充资产"
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        host = (urlsplit(candidate).hostname or "").lower().rstrip(".")
        if host:
            return host
    except ValueError:
        pass
    candidate = re.sub(r"^https?://", "", candidate, flags=re.I)
    return candidate.split("/", 1)[0].split("?", 1)[0].lower().rstrip("/") or "待补充资产"


def canonical_url(row: dict) -> str:
    url = _first(row, "url", "target_url", "endpoint")
    if not url:
        base = _first(row, "base_url")
        path = _first(row, "path")
        if base:
            url = base.rstrip("/") + (path if path.startswith("/") else ("/" + path if path else ""))
    return url


def vulnerability_family(row: dict) -> str:
    return _first(row, "vulnerability_family", "vuln_type", "type", "kind", "threat", "category", "finding", "risk_type", default="待补充漏洞类型")


def _data_volume(row: dict) -> str:
    value = _first(row, "data_volume", "involved_data_count", "record_count", "affected_count", "quantity", "count")
    if value:
        return value
    for key in ("total", "total_count", "records_total", "data_count"):
        value = text(row.get(key))
        if value:
            return value + "条" if value.isdigit() else value
    return ""


def _impact_scope(row: dict) -> str:
    return _first(row, "impact_scope", "scope", "affected_scope", "data_scope", "affected_function", "function_scope")


def _text_values(row: dict, keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        values.extend(text(item) for item in _as_list(row.get(key)))
    return _unique(values)


def _evidence(row: dict) -> list[str]:
    return _text_values(row, ("evidence", "evidence_ref", "evidence_refs", "evidence_files", "proof", "screenshot_desc"))


def _problems(row: dict) -> list[str]:
    return _text_values(row, ("problems", "problem", "issue", "issues", "root_cause"))


def _remediations(row: dict) -> list[str]:
    return _text_values(row, ("remediations", "remediation", "fix", "suggestion", "recommendation", "fixes"))


def _steps(row: dict) -> list[str]:
    return _text_values(row, ("steps", "verification_steps", "操作步骤", "验证步骤"))


def _pagination(row: dict) -> list[str]:
    return _text_values(row, ("pagination", "page_verification", "翻页验证"))


def _command_parts(row: dict) -> tuple[list[dict | str], list[str]]:
    raw = row.get("commands")
    if raw is None:
        raw = row.get("reproduction_commands")
    commands: list[dict | str] = []
    notes: list[str] = []
    for item in _as_list(raw):
        if isinstance(item, dict):
            command = text(item.get("cmd") or item.get("command") or item.get("request"))
            note = text(item.get("note") or item.get("notes"))
            if command:
                if command.startswith(_BOUNDARY_MARKERS):
                    notes.append(command)
                else:
                    commands.append(deepcopy(item))
            if note:
                notes.append(note)
        else:
            value = text(item)
            if value.startswith(_BOUNDARY_MARKERS):
                notes.append(value)
            elif value:
                commands.append(value)
    explicit_notes = _text_values(row, ("note", "notes", "command_note", "limitations", "limit_conditions", "constraints"))
    notes.extend(explicit_notes)
    return _merge_values(commands), _unique(notes)


def normalize_report_finding(row: dict, index: int = 1) -> dict:
    row = row if isinstance(row, dict) else {}
    url = canonical_url(row)
    family = vulnerability_family(row)
    system = _first(row, "system", "target_name", "app_name", "asset", default=asset_identity(row))
    title = _first(row, "title", "summary", "finding_id", default=family)
    description = _first(row, "description", "desc", "summary", "title", default=f"{family}：{url or system}")
    commands, command_notes = _command_parts(row)
    process = _first(row, "process", "attack_process", "commands_summary", default="")
    notes = _unique(command_notes + _text_values(row, ("note", "notes")))
    steps = _steps(row)
    if not steps and process and not commands:
        steps = [process]
    interpretation = _first(row, "interpretation", "impact_statement", "impact", "impact_summary", "exploitability", default="")
    expected = _first(row, "expected_result", "expected", "判定依据", default="")
    actual = _first(row, "actual_result", "result", "return_result", "response_result", default="")
    cleanup = _text_values(row, ("cleanup", "restore", "rollback", "还原步骤"))
    permission = _first(row, "permission", "permission_level", "perm_check", "role", "account", default="")
    score = _first(row, "score", "verification_score", "expected_score", "level", default="")
    level = _first(row, "level", default=score)
    status = _first(row, "status", "disposition", "review_status", default="")
    return {
        "finding_id": _first(row, "finding_id", "id", default=f"finding-{index}"),
        "title": title,
        "asset_identity": asset_identity(row),
        "system": system,
        "url": url,
        "vulnerability_family": family,
        "description": description,
        "process": process,
        "impact": interpretation,
        "interpretation": interpretation,
        "expected_result": expected,
        "actual_result": actual,
        "permission": permission,
        "score": score,
        "level": level,
        "status": status,
        "data_volume": _data_volume(row),
        "impact_scope": _impact_scope(row),
        "evidence": _evidence(row),
        "problems": _problems(row),
        "remediations": _remediations(row),
        "commands": commands,
        "reproduction_commands": commands,
        "steps": steps,
        "notes": notes,
        "note": "；".join(notes),
        "cleanup": cleanup,
        "pagination": _pagination(row),
        "raw": deepcopy(row),
    }


def _merge_text(values: list[str], limit: int = 2) -> list[str]:
    return _unique(values)[:limit]


def aggregate_report_findings(rows: list[dict]) -> list[dict]:
    normalized = [normalize_report_finding(row, i + 1) for i, row in enumerate(rows or [])]
    groups: OrderedDict[tuple[str, str], dict] = OrderedDict()
    for item in normalized:
        key = (item["asset_identity"], item["vulnerability_family"].casefold())
        group = groups.setdefault(key, {
            "finding_id": item["finding_id"], "title": item["title"], "asset_identity": item["asset_identity"],
            "system": item["system"], "vulnerability_family": item["vulnerability_family"], "description": item["description"],
            "process": item["process"], "impact": item["impact"], "interpretation": item["interpretation"], "expected_result": item["expected_result"],
            "actual_result": item["actual_result"], "permission": item["permission"], "score": item["score"],
            "level": item["level"], "status": item["status"], "data_volume": item["data_volume"], "impact_scope": item["impact_scope"],
            "urls": [], "members": [], "evidence": [], "problems": [], "remediations": [], "commands": [],
            "reproduction_commands": [], "steps": [], "notes": [], "cleanup": [], "pagination": [],
        })
        group["members"].append(item["finding_id"])
        if item["url"]: group["urls"].append(item["url"])
        for field in ("evidence", "problems", "remediations", "steps", "notes", "cleanup", "pagination"):
            group[field].extend(item[field])
        group["commands"].extend(item["commands"])
        group["reproduction_commands"].extend(item["reproduction_commands"])
        for field in ("data_volume", "impact_scope", "permission", "expected_result", "actual_result", "interpretation"):
            if not group[field] and item[field]: group[field] = item[field]
        if item["status"] and not group["status"]: group["status"] = item["status"]
    result: list[dict] = []
    for group in groups.values():
        group["urls"] = sorted(_unique(group["urls"]))
        group["members"] = _unique(group["members"])
        group["evidence"] = sorted(_unique(group["evidence"]))
        group["problems"] = _merge_text(group["problems"])
        group["remediations"] = _merge_text(group["remediations"])
        group["steps"] = _unique(group["steps"])
        group["notes"] = _unique(group["notes"])
        group["cleanup"] = _unique(group["cleanup"])
        group["pagination"] = _unique(group["pagination"])
        group["commands"] = _merge_values(group["commands"])
        group["reproduction_commands"] = _merge_values(group["reproduction_commands"])
        group["note"] = "；".join(group["notes"])
        group["member_count"] = len(group["members"])
        group["url_count"] = len(group["urls"])
        group["url"] = group["urls"][0] if group["urls"] else ""
        result.append(group)
    result.sort(key=lambda item: (item["asset_identity"].casefold(), item["vulnerability_family"].casefold(), item["url"].casefold()))
    return result


def optional_scope_rows(finding: dict) -> list[tuple[str, str]]:
    if text(finding.get("data_volume")):
        return [("涉及数据量", text(finding["data_volume"]))]
    if text(finding.get("impact_scope")):
        return [("影响范围", text(finding["impact_scope"]))]
    return []
