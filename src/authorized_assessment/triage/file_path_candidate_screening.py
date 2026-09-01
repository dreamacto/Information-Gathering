"""file_path_candidate_screening——路径穿越/LFI 文件面独立只读筛选域
（实施规格 5.4 子阶段清单 file_path_candidate_screening + 操作员 batch6_4 决定⑤）。

只读离线：沿用统一筛选模式（观察键→证据形态确定性映射→rule_satisfied 升级判定→
8 状态分级），不发任何请求、不读任何本地文件、不构造穿越 payload。独立子域依据
（操作员决定⑤）：不因注入 15 类已有 path_traversal/lfi 视为完成——本域为文件面
维度，两类别与注入类别显式区隔：

- path_traversal_boundary：路径穿越越界边界（越出预期目录且取回可区分内容的确认）；
- lfi_read_boundary：本地文件读取边界（已知低敏感文件内容回显的确认）。

双计防护（路由纪律，docstring 留痕）：观察声明注入类别（含 path_traversal/lfi）记
路由违例归 injection_candidate_screening，不双计；注入域不感知本域（其 15 类契约与
升级规则不动）。注入域 path_traversal/lfi 是 payload/注入维度（error_based/
differential/semantic_anomaly/server_side_evaluation 升级）；本域是文件面维度
（越界确认/已知文件内容确认升级），两域观察不得互相投递。

升级边界（规格 4.1 固定路径 signal + 11.3 细微发现处置 + 13.2 的落地，实现定义
供操作者复核）：仅参数名/固定路径/白名单/静态拼接/穿越处理迹象/差分/语义异常
永不升级；确认越界或确认已知文件内容回显才升级。confirmed 五门判定仍归
finding_quality_gate。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.triage import injection_candidates as ic

# 文件面复核类别（与注入 15 类显式区隔）。
FILE_PATH_CATEGORIES: tuple[str, ...] = (
    "path_traversal_boundary",
    "lfi_read_boundary",
)

# 文件面证据形态（8：6 形态/支持性 + 2 确认越过形态）。
FILE_PATH_EVIDENCE_KINDS: tuple[str, ...] = (
    "file_path_parameter",
    "traversal_filter_response",
    "extension_whitelist_only",
    "static_path_concatenation",
    "differential",
    "semantic_anomaly",
    "traversal_boundary_crossed_confirmed",
    "known_file_content_confirmed",
)

# "不算漏洞"证据形态：仅形态/静态/支持性观察，未证明边界越过。
FILE_PATH_INSUFFICIENT_EVIDENCE_KINDS: tuple[str, ...] = (
    "file_path_parameter",
    "traversal_filter_response",
    "extension_whitelist_only",
    "static_path_concatenation",
    "differential",
    "semantic_anomaly",
)

# 升级规则：path_traversal_boundary 需越界确认；lfi_read_boundary 需已知文件内容
# 回显确认或越界确认（穿越读文件即 LFI，两形态 OR）。
FILE_PATH_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "path_traversal_boundary": {
        "required_any_groups": (("traversal_boundary_crossed_confirmed",),)
    },
    "lfi_read_boundary": {
        "required_any_groups": (
            ("known_file_content_confirmed", "traversal_boundary_crossed_confirmed"),
        )
    },
}

# v1 观察键 → 证据形态（确定性映射；版本化演进同 OBSERVATION_SCHEMA_VERSION）。
FILE_PATH_OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "file_path_parameter_observed": "file_path_parameter",
    "traversal_filter_response_observed": "traversal_filter_response",
    "extension_whitelist_only_observed": "extension_whitelist_only",
    "static_path_concatenation_observed": "static_path_concatenation",
    "differential_observed": "differential",
    "semantic_anomaly_observed": "semantic_anomaly",
    "traversal_boundary_crossed_confirmed": "traversal_boundary_crossed_confirmed",
    "known_file_content_confirmed": "known_file_content_confirmed",
}

FILE_PATH_OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "file_path_parameter_observed": "观察到文件路径参数面（path/file/download/export/"
    "import/attachment/template 等承载路径值——仅形态观察，永不升级）",
    "traversal_filter_response_observed": "观察到穿越序列处理迹象（过滤/规范化/错误痕迹"
    "——仅形态观察，永不升级）",
    "extension_whitelist_only_observed": "观察到仅扩展名/前缀白名单防护（仅形态观察）",
    "static_path_concatenation_observed": "观察到静态代码/JS 中路径拼接（静态形态，不升级）",
    "differential_observed": "观察到可控差分（仅支持性观察，单独不升级）",
    "semantic_anomaly_observed": "观察到语义异常（仅支持性观察，单独不升级）",
    "traversal_boundary_crossed_confirmed": "已确认可控路径越出预期目录且取回可区分内容"
    "（授权环境低敏感文件，不读本地敏感文件）",
    "known_file_content_confirmed": "已确认回显已知低敏感文件内容，可复现且上下文相关",
}


def derive_file_path_evidence_kinds(evidence: Mapping[str, object]) -> list[str]:
    """观察键 → 文件面证据形态（按映射表顺序，确定性）。"""
    return [
        kind for key, kind in FILE_PATH_OBSERVATION_EVIDENCE_MAP.items() if evidence.get(key)
    ]


def grade_file_path_observation(
    category: str, evidence_kinds: Iterable[str], status_hint: str | None = None
) -> str:
    """文件面观察分级：确认越过形态满足 → candidate；否则 signal。status_hint 尊重人工判定。"""
    if status_hint in ic.CANDIDATE_STATUS_VALUES:
        return status_hint
    rule = FILE_PATH_UPGRADE_RULES.get(category)
    if rule is None:
        return "signal"
    satisfied, _ = ic.rule_satisfied(
        rule,
        evidence_kinds,
        FILE_PATH_EVIDENCE_KINDS,
        FILE_PATH_INSUFFICIENT_EVIDENCE_KINDS,
    )
    return "candidate" if satisfied else "signal"


def validate_file_path_candidate(
    candidate: Mapping[str, object], label: str = "file_path_candidate"
) -> list[str]:
    """文件面候选行校验：8 状态 + 证据形态 + 升级规则（复用 injection_candidates 引擎）。"""
    violations: list[str] = []
    if not isinstance(candidate, Mapping):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "category", "status", "evidence_kinds", "source"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    category = str(candidate.get("category") or "")
    if category and category not in FILE_PATH_CATEGORIES:
        violations.append(
            f"{label}.category 非法: {category!r}（允许值 {list(FILE_PATH_CATEGORIES)}；"
            "path_traversal/lfi 注入类别归 injection_candidate_screening）"
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
            unknown = sorted({k for k in kind_list if k not in FILE_PATH_EVIDENCE_KINDS})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if status in ("candidate", "confirmed"):
                satisfied, why = ic.rule_satisfied(
                    FILE_PATH_UPGRADE_RULES.get(category) or {},
                    kind_list,
                    FILE_PATH_EVIDENCE_KINDS,
                    FILE_PATH_INSUFFICIENT_EVIDENCE_KINDS,
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
    )
    return " ".join(p for p in parts if p)


def screen_file_path_observations(
    observations: Iterable[Mapping[str, object]],
    all_categories: bool = True,
    label: str = "file_path_candidate_screening",
) -> tuple[list[dict], list[dict], list[str]]:
    """文件面复核筛选 → (候选行, 类别汇总行, 违例)。

    观察必需键：category（本域两类之一）、applicability；可选：
    observation_schema_version（缺失按当前版本，显式不符记违例）、endpoint/
    parameter_name/input_location/source/evidence/evidence_ref/reason/precondition/
    status_hint。注入类别观察（含 path_traversal/lfi）记路由违例（归
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
                "（payload 维度归 injection_candidate_screening，不双计）"
            )
            continue
        if category not in FILE_PATH_CATEGORIES:
            violations.append(
                f"{label}: 第 {index} 条观察 category 非法 {category!r}"
                f"（允许值 {list(FILE_PATH_CATEGORIES)}）"
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
        kinds = derive_file_path_evidence_kinds(observation.get("evidence") or {})
        status = grade_file_path_observation(
            category, kinds, str(observation.get("status_hint") or "") or None
        )
        source = _observation_source(observation)
        if not source:
            violations.append(
                f"{label}: 第 {index} 条观察缺少来源（source 或 endpoint/parameter_name 均为空）"
            )
        row = {
            "candidate_id": f"fp-{index:04d}",
            "category": category,
            "status": status,
            "evidence_kinds": kinds,
            "source": source,
            "evidence_ref": str(observation.get("evidence_ref") or ""),
            "precondition": str(observation.get("precondition") or ""),
            "reason": reason,
        }
        rows.append(row)
        violations += validate_file_path_candidate(row, label=f"{label}[{row['candidate_id']}]")

    categories = (
        list(FILE_PATH_CATEGORIES)
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
            summaries[-1], label=f"{label}.summary[{category}]", categories=FILE_PATH_CATEGORIES
        )
    return rows, summaries, violations
