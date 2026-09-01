"""candidate_dedup.py —— 候选去重与合并引擎（实施规格 4.2 跨 run + 2.7 合并规则 + 13.2 负例）。

纯离线模块：输入候选/finding 行列表，输出去重报告与跨 run 折叠记录；零网络、零文件系统。

B1 决议承接：本引擎只产出 duplicate_of 字段（重复引用），不自行做 duplicate 状态判定——
duplicate 状态由 finding_quality_gate._decide_status 按 duplicate_of 派生（8 状态超集）。
代表行 finding_status 不被改写；所有行保留（审计不丢行）。

确定性：代表选择 = seen_at 最早优先（缺 seen_at 视为最旧、排在有时间戳的行之后），
平局取 finding_id 字典序最小；同输入（任意行序）同输出。

2.7 合并规则（apply_merge_rules，一次确定性合批，duplicate_of 只指向无 duplicate_of 的行）：
  规则A 合并键分组   merge_key 相同 → 最早行为代表，其余 duplicate_of=代表；
                     代表汇总成员参数名为 merged_parameters（sqli 同接口多参数只计一处的落地）。
  规则B 通用产品合并 同 product_or_component+root_cause_signature 且跨多个 canonical_target 的
                     代表 → 最早代表为 generic finding（generic_cluster=true），挂接
                     instance_targets 实例清单；实例代表保持独立（不串联）。
  规则C 同系统同族限量 (canonical_target, vulnerability_family) 超过 QUOTA_MAX_PER_SYSTEM_AND_FAMILY
                     条 → 首条代表保留，其后行 duplicate_of 指向组内代表的最终代表（一跳解析，
                     不形成链）。

跨 run（merge_cross_run）：按 identity_hash 折叠后每键只保留规格 4.2 五字段：
first_seen/last_seen/seen_count/latest_status/latest_evidence_ref。
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from authorized_assessment.quality.finding_quality_gate import FINDING_STATUS_STATES
from authorized_assessment.triage.canonical_keys import (
    CROSS_RUN_RETENTION_FIELDS,
    IDENTITY_KINDS,
    QUOTA_MAX_PER_SYSTEM_AND_FAMILY,
    compute_candidate_identity,
    identity_hash,
    merge_key,
)

DUPLICATE_REFERENCE_FIELD = "duplicate_of"

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

_NO_SEEN_SORT_KEY = "9999-12-31T23:59:59+00:00"


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _seen_sort_key(row: Mapping[str, Any]) -> tuple[str, str]:
    seen_at = _text(row.get("seen_at") or row.get("first_seen"))
    # 缺 seen_at 的行排在有时间戳的行之后（视为最旧不可得）；平局用 finding_id 保证确定性
    return (seen_at or _NO_SEEN_SORT_KEY, _text(row.get("finding_id")))


def _row_identity(row: Mapping[str, Any], default_kind: str | None) -> dict[str, Any]:
    kind = _text(row.get("identity_kind") or row.get("kind") or default_kind).lower()
    if not kind:
        raise ValueError(f"candidate row missing identity_kind: {_text(row.get('finding_id'))!r}")
    return compute_candidate_identity({**row, "identity_kind": kind})


def _parameter_names_of(row: Mapping[str, Any]) -> set[str]:
    names = set()
    if _text(row.get("parameter_name")):
        names.add(_text(row.get("parameter_name")).lower())
    for name in row.get("parameter_names") or []:
        if _text(name):
            names.add(_text(name).lower())
    return names


def dedupe_candidates(
    rows: Iterable[Mapping[str, Any]], *, default_identity_kind: str | None = None
) -> dict[str, Any]:
    """按身份键去重（规格 4.2 + 13.2 "重复 API 候选"负例的实现）。

    行契约：finding_id 必填非空；identity_kind（或行内 kind，或 default_identity_kind）必填；
    seen_at/finding_status/evidence_ref 可选。返回：
      rows                原行副本（附 identity_hash；非代表行附 duplicate_of，finding_status 不改写）
      groups              [{"identity_kind","identity_hash","representative_id","duplicate_ids"}]
      summary             {input_rows, representative_count, duplicate_count, group_count}
    """
    input_rows = [dict(row) for row in rows]
    seen_ids: set[str] = set()
    for row in input_rows:
        finding_id = _text(row.get("finding_id"))
        if not finding_id:
            raise ValueError("dedupe row missing finding_id")
        if finding_id in seen_ids:
            raise ValueError(f"duplicate finding_id in input: {finding_id!r}")
        seen_ids.add(finding_id)

    identities = {row["finding_id"]: _row_identity(row, default_identity_kind) for row in input_rows}

    groups_by_hash: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in input_rows:
        identity = identities[row["finding_id"]]
        groups_by_hash.setdefault(
            (identity["identity_kind"], identity["identity_hash"]), []
        ).append(row)

    out_rows: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    duplicate_count = 0
    for (kind, key_hash), members in sorted(groups_by_hash.items(), key=lambda item: item[0]):
        ordered = sorted(members, key=_seen_sort_key)
        representative = dict(ordered[0])
        representative["identity_hash"] = key_hash
        duplicates = [dict(member) for member in ordered[1:]]
        for duplicate in duplicates:
            duplicate["identity_hash"] = key_hash
            duplicate[DUPLICATE_REFERENCE_FIELD] = representative["finding_id"]
            duplicate_count += 1
        out_rows.append(representative)
        out_rows.extend(duplicates)
        groups.append(
            {
                "identity_kind": kind,
                "identity_hash": key_hash,
                "representative_id": representative["finding_id"],
                "duplicate_ids": [member["finding_id"] for member in duplicates],
            }
        )

    return {
        "rows": out_rows,
        "groups": groups,
        "summary": {
            "input_rows": len(input_rows),
            "representative_count": len(out_rows) - duplicate_count,
            "duplicate_count": duplicate_count,
            "group_count": len(groups),
        },
    }


def merge_cross_run(
    rows: Iterable[Mapping[str, Any]], *, default_identity_kind: str | None = None
) -> list[dict[str, Any]]:
    """跨 run 折叠（规格 4.2"跨 run 只保留"五字段）。

    行契约同 dedupe_candidates，另要求每行带 finding_status（8 状态枚举，缺失即报错）
    与 seen_at（缺失按 first_seen 回退）。输出每键一条：
      identity_kind/identity_hash + first_seen/last_seen/seen_count/latest_status/latest_evidence_ref
    """
    input_rows = [dict(row) for row in rows]
    for row in input_rows:
        if not _text(row.get("finding_id")):
            raise ValueError("cross-run row missing finding_id")
        if _text(row.get("finding_status")) not in FINDING_STATUS_STATES:
            raise ValueError(
                f"cross-run row missing/invalid finding_status: {_text(row.get('finding_id'))!r}"
            )

    identities = {row["finding_id"]: _row_identity(row, default_identity_kind) for row in input_rows}
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in input_rows:
        identity = identities[row["finding_id"]]
        grouped.setdefault((identity["identity_kind"], identity["identity_hash"]), []).append(row)

    records: list[dict[str, Any]] = []
    for (kind, key_hash), members in sorted(grouped.items(), key=lambda item: item[0]):
        ordered = sorted(members, key=_seen_sort_key)
        seen_values = sorted(
            _text(member.get("seen_at") or member.get("first_seen")) for member in members
        )
        seen_values = [value for value in seen_values if value]
        latest = max(members, key=_seen_sort_key)
        record = {
            "identity_kind": kind,
            "identity_hash": key_hash,
            "first_seen": seen_values[0] if seen_values else "",
            "last_seen": seen_values[-1] if seen_values else "",
            "seen_count": len(members),
            "latest_status": _text(latest.get("finding_status")),
            "latest_evidence_ref": _text(latest.get("evidence_ref")),
        }
        records.append(record)
    return records


def apply_merge_rules(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """2.7 合并规则一次合批（规则A/B/C，见模块 docstring）。

    行契约：finding_id、canonical_target、product_or_component、normalized_endpoint、
    http_method、vulnerability_family、root_cause_signature 必填；其余可选。
    """
    input_rows = [dict(row) for row in rows]
    seen_ids: set[str] = set()
    for row in input_rows:
        finding_id = _text(row.get("finding_id"))
        if not finding_id:
            raise ValueError("merge rule row missing finding_id")
        if finding_id in seen_ids:
            raise ValueError(f"duplicate finding_id in input: {finding_id!r}")
        seen_ids.add(finding_id)
        missing = [
            field
            for field in ("canonical_target", "product_or_component", "normalized_endpoint",
                          "http_method", "vulnerability_family", "root_cause_signature")
            if not _text(row.get(field))
        ]
        if missing:
            raise ValueError(f"merge rule row {finding_id!r} missing fields: {missing}")

    # 规则A：合并键分组
    key_of = {row["finding_id"]: merge_key(row) for row in input_rows}
    hash_of = {row_id: identity_hash(key) for row_id, key in key_of.items()}
    groups_by_hash: dict[str, list[dict[str, Any]]] = {}
    for row in input_rows:
        groups_by_hash.setdefault(hash_of[row["finding_id"]], []).append(row)

    duplicate_of: dict[str, str] = {}
    merged_parameters: dict[str, set[str]] = {}
    merge_groups: list[dict[str, Any]] = []
    for key_hash, members in sorted(groups_by_hash.items()):
        ordered = sorted(members, key=_seen_sort_key)
        representative = ordered[0]
        params: set[str] = set()
        for member in ordered:
            params |= _parameter_names_of(member)
        if params:
            merged_parameters[representative["finding_id"]] = params
        duplicate_ids = [member["finding_id"] for member in ordered[1:]]
        for member_id in duplicate_ids:
            duplicate_of[member_id] = representative["finding_id"]
        merge_groups.append(
            {
                "merge_hash": key_hash,
                "merge_key": key_of[representative["finding_id"]],
                "representative_id": representative["finding_id"],
                "member_ids": [member["finding_id"] for member in ordered],
                "duplicate_ids": duplicate_ids,
                "merged_parameters": sorted(params),
            }
        )

    # 规则B：通用产品合并（同 product+root_cause 跨多个 target 的代表挂实例清单；不串联）
    cluster_groups: dict[tuple[str, str], list[str]] = {}
    for group in merge_groups:
        rep_id = group["representative_id"]
        row = next(r for r in input_rows if r["finding_id"] == rep_id)
        cluster_groups.setdefault(
            (_text(row.get("product_or_component")).lower(),
             _text(row.get("root_cause_signature")).lower()),
            [],
        ).append(rep_id)

    generic_clusters: list[dict[str, Any]] = []
    for (product, root_cause), rep_ids in sorted(cluster_groups.items()):
        if len(rep_ids) < 2:
            continue
        rows_by_id = {row["finding_id"]: row for row in input_rows}
        ordered_ids = sorted(rep_ids, key=lambda rid: _seen_sort_key(rows_by_id[rid]))
        lead_id = ordered_ids[0]
        lead_row = next(r for r in input_rows if r["finding_id"] == lead_id)
        targets = sorted({_text(rows_by_id[rid].get("canonical_target")) for rid in rep_ids})
        if len(targets) < 2:
            continue
        generic_clusters.append(
            {
                "product_or_component": product,
                "root_cause_signature": root_cause,
                "lead_id": lead_id,
                "instance_ids": ordered_ids,
                "instance_targets": targets,
            }
        )

    # 规则C：同系统同族限量（>3 条时后续行 duplicate_of 指向组内最终代表，一跳解析）
    quota_groups: list[dict[str, Any]] = []
    quota_buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in input_rows:
        quota_buckets.setdefault(
            (_text(row.get("canonical_target")).lower(), _text(row.get("vulnerability_family")).lower()),
            [],
        ).append(row)
    for (system, family), members in sorted(quota_buckets.items()):
        if len(members) <= QUOTA_MAX_PER_SYSTEM_AND_FAMILY:
            continue
        ordered = sorted(members, key=_seen_sort_key)
        kept = [member["finding_id"] for member in ordered[:QUOTA_MAX_PER_SYSTEM_AND_FAMILY]]
        lead = ordered[0]
        lead_target = lead["finding_id"]
        resolved_target = duplicate_of.get(lead_target, lead_target)  # 一跳解析，避免链
        merged_ids: list[str] = []
        for member in ordered[QUOTA_MAX_PER_SYSTEM_AND_FAMILY:]:
            member_id = member["finding_id"]
            if member_id in duplicate_of:
                continue  # 规则A已标记的行保持原引用（指向其合并键代表）
            duplicate_of[member_id] = resolved_target
            merged_ids.append(member_id)
        quota_groups.append(
            {"system": system, "vulnerability_family": family,
             "kept_ids": kept, "merged_ids": merged_ids}
        )

    out_rows: list[dict[str, Any]] = []
    for row in input_rows:
        out = dict(row)
        if row["finding_id"] in duplicate_of:
            out[DUPLICATE_REFERENCE_FIELD] = duplicate_of[row["finding_id"]]
        if row["finding_id"] in merged_parameters:
            out["merged_parameters"] = sorted(merged_parameters[row["finding_id"]])
        out_rows.append(out)
    for cluster in generic_clusters:
        lead = next(r for r in out_rows if r["finding_id"] == cluster["lead_id"])
        lead["generic_cluster"] = True
        lead["instance_targets"] = cluster["instance_targets"]

    duplicate_count = len(duplicate_of)
    return {
        "rows": out_rows,
        "merge_groups": merge_groups,
        "generic_clusters": generic_clusters,
        "quota_groups": quota_groups,
        "summary": {
            "input_rows": len(input_rows),
            "representative_count": len(input_rows) - duplicate_count,
            "duplicate_count": duplicate_count,
            "merge_group_count": len(merge_groups),
            "generic_cluster_count": len(generic_clusters),
            "quota_group_count": len(quota_groups),
        },
    }


def _credential_scan(node: Any, prefix: str) -> list[str]:
    errors: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key).lower()
            path = f"{prefix}.{key}" if prefix else str(key)
            if any(fragment in key_text for fragment in _FORBIDDEN_KEY_FRAGMENTS):
                errors.append(f"credential-like key is forbidden in dedup report: {path}")
            errors.extend(_credential_scan(value, path))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            errors.extend(_credential_scan(value, f"{prefix}[{index}]"))
    return errors


def _is_plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_dedup_report(report: Any) -> list[str]:
    """依赖-free 校验去重报告；返回错误列表（空 = 通过）。

    拒绝：缺节、行缺 finding_id、duplicate_of 悬空引用/自引用/链式引用、
    duplicate 行与代表 identity_hash 不一致、summary 计数不一致、凭证类键。
    """
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["dedup report must be a dict"]
    for section in ("rows", "summary"):
        if section not in report:
            errors.append(f"missing required section: {section}")
    if errors:
        return errors

    rows = report["rows"]
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        return ["rows must be a list of dicts"]

    rows_by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        finding_id = _text(row.get("finding_id"))
        if not finding_id:
            errors.append("row missing finding_id")
            continue
        if finding_id in rows_by_id:
            errors.append(f"duplicate finding_id in report rows: {finding_id!r}")
        rows_by_id[finding_id] = row

    duplicate_rows = [row for row in rows if _text(row.get(DUPLICATE_REFERENCE_FIELD))]
    for row in duplicate_rows:
        target_id = _text(row.get(DUPLICATE_REFERENCE_FIELD))
        if target_id == _text(row.get("finding_id")):
            errors.append(f"duplicate_of must not self-reference: {target_id!r}")
            continue
        target = rows_by_id.get(target_id)
        if target is None:
            errors.append(f"duplicate_of references unknown finding_id: {target_id!r}")
            continue
        if _text(target.get(DUPLICATE_REFERENCE_FIELD)):
            errors.append(
                f"chained duplicate_of is forbidden: {row.get('finding_id')!r} -> {target_id!r}"
            )
        if (
            _text(row.get("identity_hash"))
            and _text(target.get("identity_hash"))
            and row["identity_hash"] != target["identity_hash"]
        ):
            errors.append(
                f"duplicate {row.get('finding_id')!r} identity_hash differs from representative {target_id!r}"
            )

    summary = report["summary"]
    if not isinstance(summary, dict):
        errors.append("summary must be a dict")
    else:
        expected = {
            "input_rows": len(rows),
            "duplicate_count": len(duplicate_rows),
            "representative_count": len(rows) - len(duplicate_rows),
        }
        for field, value in expected.items():
            if summary.get(field) != value:
                errors.append(f"summary.{field} inconsistent: {summary.get(field)!r} != {value}")

    errors.extend(_credential_scan(report, ""))
    return errors


def validate_merge_rules_report(report: Any) -> list[str]:
    """依赖-free 校验 2.7 合并规则报告；拒绝悬空/链式/自引用 duplicate_of 与计数不一致。"""
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["merge rules report must be a dict"]
    for section in ("rows", "merge_groups", "summary"):
        if section not in report:
            errors.append(f"missing required section: {section}")
    if errors:
        return errors

    rows = report["rows"]
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        return ["rows must be a list of dicts"]

    rows_by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        finding_id = _text(row.get("finding_id"))
        if not finding_id:
            errors.append("row missing finding_id")
            continue
        rows_by_id[finding_id] = row

    duplicate_rows = [row for row in rows if _text(row.get(DUPLICATE_REFERENCE_FIELD))]
    for row in duplicate_rows:
        target_id = _text(row.get(DUPLICATE_REFERENCE_FIELD))
        if target_id == _text(row.get("finding_id")):
            errors.append(f"duplicate_of must not self-reference: {target_id!r}")
            continue
        target = rows_by_id.get(target_id)
        if target is None:
            errors.append(f"duplicate_of references unknown finding_id: {target_id!r}")
            continue
        if _text(target.get(DUPLICATE_REFERENCE_FIELD)):
            errors.append(
                f"chained duplicate_of is forbidden: {row.get('finding_id')!r} -> {target_id!r}"
            )

    summary = report["summary"]
    if not isinstance(summary, dict):
        errors.append("summary must be a dict")
    else:
        expected = {
            "input_rows": len(rows),
            "duplicate_count": len(duplicate_rows),
            "representative_count": len(rows) - len(duplicate_rows),
        }
        for field, value in expected.items():
            if summary.get(field) != value:
                errors.append(f"summary.{field} inconsistent: {summary.get(field)!r} != {value}")

    errors.extend(_credential_scan(report, ""))
    return errors


def validate_cross_run_records(records: Any) -> list[str]:
    """依赖-free 校验跨 run 折叠记录（规格 4.2 五字段 + 8 状态枚举交叉）。"""
    errors: list[str] = []
    if not isinstance(records, list):
        return ["cross-run records must be a list"]
    for index, record in enumerate(records):
        prefix = f"records[{index}]"
        local_errors: list[str] = []
        if not isinstance(record, dict):
            errors.append(f"{prefix} must be a dict")
            continue
        if record.get("identity_kind") not in IDENTITY_KINDS:
            local_errors.append(f"{prefix}.identity_kind not in enum: {record.get('identity_kind')!r}")
        hash_value = _text(record.get("identity_hash"))
        if len(hash_value) != 64 or any(c not in "0123456789abcdef" for c in hash_value):
            local_errors.append(f"{prefix}.identity_hash must be 64-hex")
        for field in CROSS_RUN_RETENTION_FIELDS:
            if field not in record:
                local_errors.append(f"{prefix} missing cross-run field: {field}")
        if local_errors:
            errors.extend(local_errors)
            continue
        if not _text(record.get("first_seen")) or not _text(record.get("last_seen")):
            local_errors.append(f"{prefix} first_seen/last_seen must be non-empty")
        elif _text(record["first_seen"]) > _text(record["last_seen"]):
            local_errors.append(f"{prefix} first_seen must not be after last_seen")
        seen_count = record.get("seen_count")
        if not _is_plain_int(seen_count) or seen_count < 1:
            local_errors.append(f"{prefix}.seen_count must be an integer >= 1")
        if _text(record.get("latest_status")) not in FINDING_STATUS_STATES:
            local_errors.append(f"{prefix}.latest_status not in finding status enum: "
                                f"{record.get('latest_status')!r}")
        errors.extend(local_errors)
    errors.extend(_credential_scan(records, ""))
    return errors
