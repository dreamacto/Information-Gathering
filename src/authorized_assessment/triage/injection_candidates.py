"""统一注入候选契约（实施规格 5.4：injection_candidate_screening + parser_deserialization_screening）。

契约层数据形状与校验的唯一实现。纯 stdlib、零网络、只读幂等；候选筛选不发送任何
payload，SQLMap 与一切高风险验证均为审批门动作（由现有流程策略控制，本模块不重复登记）。

  - INJECTION_CATEGORIES：规格 5.4 十五类注入/解析类别；
  - CATEGORY_SCREENING：两子阶段归属映射（XXE/XML/YAML/反序列化归 parser_deserialization_screening）；
  - CATEGORY_SUMMARY_FIELDS：汇总行字段——三统计概念分离（操作员决定①③）：
    category_status（类别整体状态，复用 COVERAGE_SUBSTATUSES 六状态）、
    applicability_counts（适用性判定分布三键计数）、status_counts（finding 8 状态八键
    计数）、tested_count（实际执行并产生确定结果的观察项数 = DEFINITIVE 各键之和）；
  - CANDIDATE_STATUS_VALUES：候选分级 8 状态（与 finding_quality_gate.FINDING_STATUS_STATES 同源）；
  - OBSERVATION_SCHEMA_VERSION / OBSERVATION_FIELD_DOCS：观察记录 schema 版本与字段说明
    （键名可版本化演进，操作员决定②）；
  - rule_satisfied：通用升级规则判定引擎（required_any_groups / required_any_branches /
    required_all），注入域与 SSRF 域共用；
  - aggregate_category_status：类别整体状态确定性聚合；
  - validate_category_summary / validate_injection_candidate：行级校验，返回违例列表。

观察与候选不是漏洞证明（契约 observation_schema.not_proof_semantics）；confirmed 的
完整五门判定仍由 finding_quality_gate 承担，本模块只做候选层分级校验。
"""
from __future__ import annotations

from typing import Iterable, Mapping

from authorized_assessment.analysis.coverage_matrix import COVERAGE_SUBSTATUSES

INJECTION_CATEGORIES = (
    "sql",
    "nosql",
    "ldap",
    "xpath",
    "ssti",
    "expression_language",
    "os_command",
    "header_injection",
    "template_injection",
    "path_traversal",
    "lfi",
    "xxe",
    "xml_parser",
    "yaml_parser",
    "unsafe_deserialization",
)

# 规格 5.4：XXE 放在 parser_deserialization_screening，不与 SQLi 混记；两集合完备且互斥。
CATEGORY_SCREENING: dict[str, tuple[str, ...]] = {
    "injection_candidate_screening": (
        "sql",
        "nosql",
        "ldap",
        "xpath",
        "ssti",
        "expression_language",
        "os_command",
        "header_injection",
        "template_injection",
        "path_traversal",
        "lfi",
    ),
    "parser_deserialization_screening": (
        "xxe",
        "xml_parser",
        "yaml_parser",
        "unsafe_deserialization",
    ),
}

# 每类别汇总行：三个统计概念分离（操作员决定①③）+ category + 三个说明字段。
CATEGORY_SUMMARY_FIELDS = (
    "category",
    "category_status",
    "applicability_counts",
    "status_counts",
    "tested_count",
    "reason",
    "source",
    "precondition",
)

# category_status 取值复用覆盖子状态六状态（单一事实源，契约 invariants 同源声明）。
CATEGORY_STATUS_VALUES = COVERAGE_SUBSTATUSES

APPLICABILITY_COUNT_KEYS = ("applicable", "not_applicable", "unknown")

# "实际执行并产生确定结果"的状态集合（操作员决定①：tested_count 的定义基础）。
# 排除 signal（未执行测试的初分类）、needs_manual_validation（待人工，无确定结果）、
# inconclusive（无结论）。
DEFINITIVE_RESULT_STATUSES = ("candidate", "confirmed", "blocked", "rejected", "duplicate")

# 观察记录 schema 版本（操作员决定②）：键名集合可版本化演进，改名/增删键必须 bump
# 本常量并同步契约 observation_schema.version 与 fields。不声明永久不可修改。
OBSERVATION_SCHEMA_VERSION = "1.0"

# 观察键字段说明（与契约 observation_schema.fields 同文，测试锁定一致）。
OBSERVATION_FIELD_DOCS: dict[str, str] = {
    "query_input_point_confirmed": "已确认该参数进入真实查询（SQL/NoSQL 升级第一要素）",
    "error_message_observed": "观察到数据库/解释器错误响应",
    "differential_observed": "观察到可控差分（不同输入产生可复现的不同响应）",
    "semantic_anomaly_observed": "观察到语义异常（响应内容/结构随输入发生不合理解释的变化）",
    "server_side_evaluation_confirmed": "已确认最小无破坏表达式在服务端求值且结果可重复、上下文相关",
    "parser_confirmed": "已确认后端解析器处理该输入（XML/YAML/反序列化面）",
    "external_input_into_parser_observed": "观察到外部可控输入进入解析器",
    "unsafe_type_recovery_observed": "观察到不安全类型/对象恢复或表达式处理",
    "reproducible_impact_confirmed": "已确认可复现的安全影响",
    "reflected_observed": "观察到反射（不足以证明可执行）",
    "template_syntax_observed": "观察到模板语法形态 {{ }}/${ }（不算漏洞证据）",
    "client_template_or_echo_observed": "观察到客户端模板/普通字符串回显/错误页",
    "fingerprint_or_name_only_observed": "仅依赖名/类名/版本指纹/序列化格式",
    "xml_content_observed": "观察到 XML 内容但未证明解析器行为",
    "static_sink_observed": "仅静态 sink，无可达链路",
}

APPLICABLE_VALUES = ("applicable", "not_applicable", "unknown")

CANDIDATE_STATUS_VALUES = (
    "signal",
    "candidate",
    "needs_manual_validation",
    "confirmed",
    "inconclusive",
    "blocked",
    "rejected",
    "duplicate",
)

# 需要升级证据支撑的状态：signal 是初分类、blocked/rejected/duplicate/inconclusive 不升级。
_UPGRADE_REQUIRED_STATUSES = ("candidate", "confirmed")

EVIDENCE_KINDS = (
    "query_input_point",
    "error_based",
    "differential",
    "semantic_anomaly",
    "server_side_evaluation",
    "parser_confirmed",
    "external_input_into_parser",
    "unsafe_type_recovery",
    "reproducible_impact",
    "reflected_only",
    "template_syntax_seen",
    "client_template_or_echo",
    "fingerprint_or_name_only",
    "xml_content_seen",
    "static_sink_only",
)

# 13.2 负例语义：这些证据形态永不满足任何升级规则（仅反射/仅语法/仅指纹/仅静态 sink 等）。
INSUFFICIENT_EVIDENCE_KINDS = (
    "reflected_only",
    "template_syntax_seen",
    "client_template_or_echo",
    "fingerprint_or_name_only",
    "xml_content_seen",
    "static_sink_only",
)

# 组间 AND、组内 OR；required_any_branches：branch 间 OR、branch 内 AND；
# required_all 与上述键可并存（当前规则只用其一）。
_UPGRADE_RULES: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {
    "sql": {"required_any_groups": (("query_input_point",), ("error_based", "differential", "semantic_anomaly"))},
    "nosql": {"required_any_groups": (("query_input_point",), ("error_based", "differential", "semantic_anomaly"))},
    "ldap": {"required_any_groups": (("error_based", "differential", "semantic_anomaly", "server_side_evaluation"),)},
    "xpath": {"required_any_groups": (("error_based", "differential", "semantic_anomaly", "server_side_evaluation"),)},
    "ssti": {"required_any_groups": (("server_side_evaluation",),)},
    "expression_language": {"required_any_groups": (("server_side_evaluation",),)},
    "template_injection": {"required_any_groups": (("server_side_evaluation",),)},
    "os_command": {"required_any_groups": (("error_based", "differential", "semantic_anomaly", "server_side_evaluation"),)},
    "header_injection": {"required_any_groups": (("error_based", "differential", "semantic_anomaly", "server_side_evaluation"),)},
    "path_traversal": {"required_any_groups": (("error_based", "differential", "semantic_anomaly", "server_side_evaluation"),)},
    "lfi": {"required_any_groups": (("error_based", "differential", "semantic_anomaly", "server_side_evaluation"),)},
    "xxe": {"required_any_branches": (("parser_confirmed",), ("external_input_into_parser", "unsafe_type_recovery"))},
    "xml_parser": {"required_any_branches": (("parser_confirmed",), ("external_input_into_parser", "unsafe_type_recovery"))},
    "yaml_parser": {"required_any_branches": (("parser_confirmed",), ("external_input_into_parser", "unsafe_type_recovery"))},
    "unsafe_deserialization": {
        "required_all": ("external_input_into_parser", "unsafe_type_recovery", "reproducible_impact")
    },
}

_UPGRADE_NOT_REQUIRED = ("inconclusive", "blocked", "rejected", "duplicate")


def rule_satisfied(
    rule: Mapping[str, object],
    evidence_kinds: Iterable[str],
    evidence_enum: Iterable[str],
    insufficient_kinds: Iterable[str] = (),
) -> tuple[bool, str]:
    """通用升级规则判定引擎（组间 AND、组内 OR；branch 间 OR、branch 内 AND；required_all 全存在）。

    batch6_2 从 upgrade_satisfied 提取为单一实现，供注入域与 SSRF 域共用：
    证据全部属于 insufficient_kinds 时永不满足；未知证据形态（不在 evidence_enum）不满足。
    """
    kinds = [str(k) for k in evidence_kinds]
    if not kinds:
        return False, "证据形态为空"
    enum = set(evidence_enum)
    unknown = [k for k in kinds if k not in enum]
    if unknown:
        return False, f"未知证据形态: {unknown}"
    kind_set = set(kinds)
    insufficient = set(insufficient_kinds)
    if insufficient and kind_set <= insufficient:
        return False, "仅有'不算漏洞'的证据形态（反射/语法形态/指纹/静态 sink 等），禁止升级"
    required_all = tuple(rule.get("required_all") or ())
    missing_all = [k for k in required_all if k not in kind_set]
    if missing_all:
        return False, f"缺少必需证据（required_all）: {missing_all}"
    for group in rule.get("required_any_groups") or ():
        if not kind_set & set(group):
            return False, f"每组至少一个证据未满足: 组 {list(group)}"
    branches = tuple(rule.get("required_any_branches") or ())
    if branches and not any(set(branch) <= kind_set for branch in branches):
        best = max(branches, key=lambda b: len(set(b) & kind_set))
        return False, f"任一分支的全部证据必须同时满足，最接近的分支缺: {sorted(set(best) - kind_set)}"
    return True, "升级证据满足"


def upgrade_satisfied(category: str, evidence_kinds: Iterable[str]) -> tuple[bool, str]:
    """判定某 category 在给定证据形态下是否满足升级规则。

    返回 (satisfied, explanation)。未知 category 或空证据直接不满足；
    证据全部属于 INSUFFICIENT_EVIDENCE_KINDS 时永不满足（规格 13.2）。
    """
    rule = _UPGRADE_RULES.get(category)
    if rule is None:
        return False, f"未知 category: {category!r}（无升级规则）"
    return rule_satisfied(rule, evidence_kinds, EVIDENCE_KINDS, INSUFFICIENT_EVIDENCE_KINDS)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def aggregate_category_status(
    statuses: Iterable[str], has_not_applicable_records: bool
) -> str:
    """类别整体状态确定性聚合（契约 category_status_aggregation 优先级）。

    statuses = 该类别下非 not_applicable 观察产生的候选状态列表（可为空）。
    返回六状态之一；approval_required 不由聚合产生（六状态合法值，供复核显式设置）。
    """
    statuses = list(statuses)
    if not statuses and not has_not_applicable_records:
        return "inconclusive"
    if not statuses:
        return "not_applicable"
    if any(s in DEFINITIVE_RESULT_STATUSES for s in statuses):
        return "tested"
    if any(s == "needs_manual_validation" for s in statuses):
        return "needs_manual_validation"
    return "inconclusive"


def _validate_count_map(
    counts: object, keys: tuple[str, ...], label: str, field: str, violations: list[str]
) -> dict[str, int]:
    if not isinstance(counts, Mapping):
        violations.append(f"{label}.{field} 必须为键值对象")
        return {}
    missing = [k for k in keys if k not in counts]
    unknown = sorted(set(counts) - set(keys))
    if missing:
        violations.append(f"{label}.{field} 缺少键 {missing}")
    if unknown:
        violations.append(f"{label}.{field} 未知键 {unknown}")
    result: dict[str, int] = {}
    for key in keys:
        value = counts.get(key)
        if key in counts and not _is_count(value):
            violations.append(f"{label}.{field}.{key} 必须为非负整数（bool 不算），实际: {value!r}")
        elif _is_count(value):
            result[key] = int(value)  # type: ignore[arg-type]
    return result


def validate_category_summary(
    row: Mapping[str, object],
    label: str = "injection_summary",
    categories: Iterable[str] = INJECTION_CATEGORIES,
) -> list[str]:
    """每类别汇总行校验（三统计概念分离：category_status / applicability_counts /
    status_counts / tested_count——操作员决定①③；13.2 负例）。

    categories 默认注入域 15 类；其它域（如 SSRF 的 ("ssrf",)）传入自己的类别集合复用
    同一校验逻辑。
    """
    violations: list[str] = []
    if not isinstance(row, Mapping):
        return [f"{label}: 行必须是键值映射"]
    allowed = tuple(categories)
    for field in CATEGORY_SUMMARY_FIELDS:
        if field not in row:
            violations.append(f"{label}: 缺少必需字段 {field}")
    category = str(row.get("category") or "")
    if category and category not in allowed:
        violations.append(f"{label}.category 非法: {category!r}（允许值 {list(allowed)}）")
    category_status = str(row.get("category_status") or "")
    if category_status and category_status not in CATEGORY_STATUS_VALUES:
        violations.append(
            f"{label}.category_status 非法: {category_status!r}（允许值 {list(CATEGORY_STATUS_VALUES)}）"
        )
    applicability = _validate_count_map(
        row.get("applicability_counts"), APPLICABILITY_COUNT_KEYS, label, "applicability_counts", violations
    )
    status_counts = _validate_count_map(
        row.get("status_counts"), CANDIDATE_STATUS_VALUES, label, "status_counts", violations
    )
    tested_count = row.get("tested_count")
    if "tested_count" in row and not _is_count(tested_count):
        violations.append(f"{label}.tested_count 必须为非负整数（bool 不算），实际: {tested_count!r}")
        tested_count = None
    if isinstance(tested_count, int) and not isinstance(tested_count, bool):
        definitive_sum = sum(status_counts.get(s, 0) for s in DEFINITIVE_RESULT_STATUSES)
        if tested_count != definitive_sum:
            violations.append(
                f"{label}.tested_count={tested_count} 与 status_counts definitive 键之和"
                f" {definitive_sum} 不一致（行数矛盾拒绝）"
            )
    if category_status == "not_applicable":
        if not str(row.get("reason") or "").strip():
            violations.append(
                f"{label}: category_status=not_applicable 但 reason 为空（未做适用性判定不得宣称不适用）"
            )
        nonzero = [k for k, v in status_counts.items() if v != 0]
        if nonzero:
            violations.append(
                f"{label}: category_status=not_applicable 但 status_counts 非零 {sorted(nonzero)}"
                "（不适用类别不得有候选计数）"
            )
        if applicability.get("applicable", 0) != 0 or applicability.get("unknown", 0) != 0:
            violations.append(
                f"{label}: category_status=not_applicable 但 applicability_counts 存在"
                " applicable/unknown 计数（未做适用性判定不得宣称不适用）"
            )
    if category_status == "tested" and isinstance(tested_count, int) and tested_count == 0:
        violations.append(f"{label}: category_status=tested 但 tested_count=0（完成必须可证明）")
    if (
        category_status == "needs_manual_validation"
        and status_counts.get("needs_manual_validation", 0) == 0
    ):
        violations.append(
            f"{label}: category_status=needs_manual_validation 但 status_counts 无该状态计数"
        )
    if category_status == "approval_required" and status_counts.get("candidate", 0) == 0:
        violations.append(
            f"{label}: category_status=approval_required 但 status_counts.candidate=0"
            "（审批等待状态必须有候选）"
        )
    if (status_counts.get("candidate", 0) > 0 or (isinstance(tested_count, int) and tested_count > 0)) and not str(
        row.get("source") or ""
    ).strip():
        violations.append(f"{label}: candidate 计数或 tested_count 大于 0 但 source 为空（候选必须可追溯）")
    if status_counts.get("candidate", 0) > 0 and not str(row.get("precondition") or "").strip():
        violations.append(f"{label}: status_counts.candidate>0 但 precondition 为空（升级/验证前置条件必须落盘）")
    return violations


def validate_injection_candidate(candidate: Mapping[str, object], label: str = "injection_candidate") -> list[str]:
    """候选条目校验（8 状态分级 + 升级证据规则 + 13.2 负例）。"""
    violations: list[str] = []
    if not isinstance(candidate, Mapping):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "category", "status", "evidence_kinds", "source"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    if not isinstance(candidate, Mapping):
        return violations
    category = str(candidate.get("category") or "")
    if category and category not in INJECTION_CATEGORIES:
        violations.append(f"{label}.category 非法: {category!r}（允许值 {list(INJECTION_CATEGORIES)}）")
    status = str(candidate.get("status") or "")
    if status and status not in CANDIDATE_STATUS_VALUES:
        violations.append(f"{label}.status 非法: {status!r}（允许值 {list(CANDIDATE_STATUS_VALUES)}）")
    kinds = candidate.get("evidence_kinds")
    if kinds is not None:
        if not isinstance(kinds, (list, tuple)):
            violations.append(f"{label}.evidence_kinds 必须为列表")
        else:
            kind_list = [str(k) for k in kinds]
            if not kind_list:
                violations.append(f"{label}.evidence_kinds 不能为空（signal 也需记录观察形态）")
            unknown = sorted({k for k in kind_list if k not in EVIDENCE_KINDS})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if len(set(kind_list)) != len(kind_list):
                violations.append(f"{label}.evidence_kinds 存在重复项")
            if status in _UPGRADE_REQUIRED_STATUSES and category in _UPGRADE_RULES:
                satisfied, why = upgrade_satisfied(category, kind_list)
                if not satisfied:
                    violations.append(f"{label}: status={status} 但升级证据不满足——{why}")
    if status in ("candidate", "confirmed", "needs_manual_validation") and not str(
        candidate.get("evidence_ref") or ""
    ).strip():
        violations.append(f"{label}: status={status} 但 evidence_ref 为空（候选必须可证明）")
    if candidate.get("approval_required") and not str(candidate.get("reason") or "").strip():
        violations.append(f"{label}: approval_required=true 但 reason 为空（必须说明审批原因，如 SQLMap 单候选）")
    return violations


# ---------------------------------------------------------------------------
# batch6_1：筛选行为（只读离线；不发 payload、不做参数名启发式猜测）
# ---------------------------------------------------------------------------

# 结构化观察键 → 证据形态（v1 观察键，规格 5.4 各小节的可证明事实）。
# 确定性映射：观察记录由复核会话从 run 产物/代理记录提炼，模块不做启发式推断。
OBSERVATION_EVIDENCE_MAP: dict[str, str] = {
    "query_input_point_confirmed": "query_input_point",
    "error_message_observed": "error_based",
    "differential_observed": "differential",
    "semantic_anomaly_observed": "semantic_anomaly",
    "server_side_evaluation_confirmed": "server_side_evaluation",
    "parser_confirmed": "parser_confirmed",
    "external_input_into_parser_observed": "external_input_into_parser",
    "unsafe_type_recovery_observed": "unsafe_type_recovery",
    "reproducible_impact_confirmed": "reproducible_impact",
    "reflected_observed": "reflected_only",
    "template_syntax_observed": "template_syntax_seen",
    "client_template_or_echo_observed": "client_template_or_echo",
    "fingerprint_or_name_only_observed": "fingerprint_or_name_only",
    "xml_content_observed": "xml_content_seen",
    "static_sink_observed": "static_sink_only",
}



def derive_evidence_kinds(evidence: Mapping[str, object]) -> list[str]:
    """从结构化观察键确定性映射到证据形态（按 EVIDENCE_KINDS 顺序输出，无重复）。"""
    return [kind for key, kind in OBSERVATION_EVIDENCE_MAP.items() if evidence.get(key)]


def grade_observation(
    category: str, evidence_kinds: Iterable[str], status_hint: str | None = None
) -> str:
    """观察分级：升级证据满足 → candidate；否则 signal（signal 不是漏洞，只是初分类）。

    status_hint 允许复核会话显式给出 8 状态之一（如 blocked/rejected/inconclusive），
    模块不覆盖人工判定；hint 非法时回退到证据分级。
    """
    if status_hint in CANDIDATE_STATUS_VALUES:
        return status_hint
    satisfied, _ = upgrade_satisfied(category, evidence_kinds)
    return "candidate" if satisfied else "signal"


def _observation_source(observation: Mapping[str, object]) -> str:
    explicit = str(observation.get("source") or "").strip()
    if explicit:
        return explicit
    parts = (
        str(observation.get("endpoint") or "").strip(),
        str(observation.get("http_method") or "").strip(),
        str(observation.get("input_location") or "").strip(),
        str(observation.get("parameter_name") or "").strip(),
    )
    return " ".join(p for p in parts if p)


def screen_observations(
    observations: Iterable[Mapping[str, object]],
    all_categories: bool = True,
    label: str = "injection_screening",
) -> tuple[list[dict], list[dict], list[str]]:
    """筛选观察列表 → (候选行, 类别汇总行, 违例)。

    只读数据变换：不产生任何请求；类别由观察显式声明（模块校验合法性），证据形态由
    OBSERVATION_EVIDENCE_MAP 确定性映射，没有升级证据的观察只能得 signal。
    观察是筛选输入不是漏洞证明（契约 observation_schema.not_proof_semantics）。
    适用性优先：applicability=not_applicable 的观察不产候选行，只计入汇总
    applicability_counts.not_applicable 并保留 reason。

    观察必需键：category、applicability（applicable/not_applicable/unknown）；
    可选：observation_schema_version（缺失按当前版本，显式不符记违例）、
    endpoint/http_method/input_location/parameter_name/source/evidence/
    evidence_ref/reason/precondition/status_hint/approval_required。
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
        if obs_version is not None and str(obs_version) != OBSERVATION_SCHEMA_VERSION:
            violations.append(
                f"{label}: 第 {index} 条观察 observation_schema_version={obs_version!r} "
                f"与当前版本 {OBSERVATION_SCHEMA_VERSION!r} 不符（键名集合已版本化演进，需同步契约）"
            )
        category = str(observation.get("category") or "")
        if category not in INJECTION_CATEGORIES:
            violations.append(f"{label}: 第 {index} 条观察 category 非法 {category!r}")
            continue
        applicability = str(observation.get("applicability") or "unknown")
        if applicability not in APPLICABLE_VALUES:
            violations.append(
                f"{label}: 第 {index} 条观察 applicability 非法 {applicability!r}"
                f"（允许值 {list(APPLICABLE_VALUES)}）"
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
        kinds = derive_evidence_kinds(observation.get("evidence") or {})
        status = grade_observation(
            category, kinds, str(observation.get("status_hint") or "") or None
        )
        source = _observation_source(observation)
        if not source:
            violations.append(
                f"{label}: 第 {index} 条观察缺少来源（source 或 endpoint/parameter_name 均为空，"
                "契约 observation_schema.source_required）"
            )
        row = {
            "candidate_id": f"inj-{index:04d}",
            "category": category,
            "status": status,
            "evidence_kinds": kinds,
            "source": source,
            "evidence_ref": str(observation.get("evidence_ref") or ""),
            "precondition": str(observation.get("precondition") or ""),
            "reason": reason,
        }
        if observation.get("approval_required"):
            row["approval_required"] = True
        rows.append(row)
        violations += validate_injection_candidate(row, label=f"{label}[{row['candidate_id']}]")

    categories = list(INJECTION_CATEGORIES) if all_categories else sorted(
        {str(r["category"]) for r in rows}
        | set(na_counts)
        | set(applicable_counts_acc)
        | set(unknown_counts_acc)
    )
    summaries: list[dict] = []
    for category in categories:
        cat_rows = [r for r in rows if r["category"] == category]
        status_counts = {s: 0 for s in CANDIDATE_STATUS_VALUES}
        for r in cat_rows:
            status_counts[r["status"]] += 1
        applicability_counts = {
            "applicable": applicable_counts_acc.get(category, 0),
            "not_applicable": na_counts.get(category, 0),
            "unknown": unknown_counts_acc.get(category, 0),
        }
        tested_count = sum(status_counts[s] for s in DEFINITIVE_RESULT_STATUSES)
        category_status = aggregate_category_status(
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
        violations += validate_category_summary(summaries[-1], label=f"{label}.summary[{category}]")
    return rows, summaries, violations
