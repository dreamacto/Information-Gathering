"""单候选 XSS 验证（实施规格 7.2 Dalfox/XSStrike 二选一：XSStrike；Batch 16）。

二选一决策（batch16_0 记录）：引入 XSStrike，不引入 Dalfox——XSStrike 为 Python
运行时（匹配项目规范运行时纪律）、默认即单 URL 单参数模式、无需 Go 二进制。

两个纯离线模式，模块自身永不执行工具、永不发网络请求：

  plan   构建单候选受控验证计划：只接受已筛选的反射/DOM 候选（必须携带
         xss_candidate_triage 筛选产物标记 source_key_sha256 / candidate_priority /
         score 之一），单目标单参数；命令只含 -u 与 --skip，显式排除 --crawl
         （不做全量爬站）、--blind（不用 OOB）、--update（禁自更新联网）。
         工具状态来自 tools/tool_registry.json：未登记/非 active/路径不可解析 →
         executable=false fail-closed。executable 只表示"计划可交操作者执行"。

  ingest 解析操作者手工回填的单候选验证结果 JSON（本模块定义的契约——XSStrike
         无官方结构化输出，ingest 只吃该契约，不吃自由文本）：
           url / param / status / reflected / executable_context / dom_sink_hit /
           waf_block / error / context / evidence_ref [/ console_excerpt]
         升级规则复用 injection_candidates.rule_satisfied：可执行上下文反射或
         DOM sink 到达（branch OR）；reflected_not_executable / waf_block /
         error_or_timeout 为负例永不升级（13.2"反射但不可执行"）。结果行强制
         回指请求（url+param）、响应（status）、浏览器上下文（context）与证据
         索引（evidence_ref，candidate 必填）。凭证类键（复用
         response_baseline._credential_scan）与疑似敏感值摘录拒绝入行。

与 xss_candidate_triage（反射候选筛选主链）的关系：本模块是其下游的单候选验证
筛选层，candidate 必须来自上游筛选产物；tool_strategy 接线由 batch16_6 统一处理。
"""
from __future__ import annotations

import re
from pathlib import Path

from authorized_assessment.tools import registry as tool_registry
from authorized_assessment.triage import injection_candidates as ic
from authorized_assessment.triage import response_baseline as rb

XSSTRIKE_TOOL_ID = "xsstrike"

# 已筛选候选标记（xss_candidate_triage.candidate_record 产物字段，三有一即可）。
SCREENED_CANDIDATE_MARKERS: tuple[str, ...] = ("source_key_sha256", "candidate_priority", "score")

# 浏览器上下文枚举（结果行回指浏览器上下文的合法值）。
BROWSER_CONTEXTS: tuple[str, ...] = (
    "html_body",
    "html_attribute",
    "js_string",
    "dom_sink",
    "url_reflected_only",
    "unknown",
)

# 证据形态：前两个为升级要件，其余为负例（永不升级；13.2"反射但不可执行"）。
XSS_VALIDATION_EVIDENCE_KINDS: tuple[str, ...] = (
    "payload_reflected_in_executable_context",
    "dom_sink_reached",
    "reflected_not_executable",
    "waf_block",
    "error_or_timeout",
)
XSS_VALIDATION_INSUFFICIENT_KINDS: tuple[str, ...] = (
    "reflected_not_executable",
    "waf_block",
    "error_or_timeout",
)

# branch 间 OR：可执行上下文反射 或 DOM sink 到达。
XSS_VALIDATION_UPGRADE_RULE: dict[str, tuple[tuple[str, ...], ...]] = {
    "required_any_branches": (
        ("payload_reflected_in_executable_context",),
        ("dom_sink_reached",),
    ),
}

XSS_VALIDATION_CATEGORY = "single_candidate_xss"

# plan 命令只允许这两个工具旗标（crawl/blind/update 全部排除）。
PLAN_ALLOWED_FLAGS: tuple[str, ...] = ("-u", "--skip")

# 疑似敏感值形态（console_excerpt 值级扫描；命中即拒绝入行）。
SENSITIVE_VALUE_RE = re.compile(
    r"(cookie\s*[:=]|authorization\s*[:=]|bearer\s+[A-Za-z0-9._~+/=-]+|session_key"
    r"|appsecret|app_secret|password\s*[:=]|passwd\s*[:=])",
    re.I,
)


def resolve_xsstrike_tool(
    registry_path: str | Path | None = None, root: str | Path | None = None
) -> dict:
    """从 tool registry 解析 xsstrike 状态；executable 只表示计划可交操作者执行。"""
    if root is None:
        root = Path(__file__).resolve().parents[3]
    if registry_path is None:
        registry_path = Path(root) / "tools" / "tool_registry.json"
    result = {
        "tool_id": XSSTRIKE_TOOL_ID,
        "registered": False,
        "status": "unregistered",
        "path": "",
        "version": "",
        "path_resolved": False,
        "executable": False,
        "reason": "xsstrike 未登记于 tools/tool_registry.json（规格 7.1：不得伪装可执行）",
    }
    data, err = tool_registry.load_registry(registry_path)
    if err or not isinstance(data, dict):
        result["status"] = "registry_unreadable"
        result["reason"] = f"tool registry 不可读：{err or '结构缺失'}"
        return result
    for entry in data.get("tools", []):
        if not isinstance(entry, dict) or str(entry.get("tool_id")) != XSSTRIKE_TOOL_ID:
            continue
        status = str(entry.get("status") or "")
        path = str(entry.get("path") or "")
        resolved = tool_registry.resolve_tool_path(path, Path(root)) if path else None
        exists = bool(resolved is not None and str(path).strip() and resolved.exists())
        result.update(
            registered=True, status=status, path=path,
            version=str(entry.get("version") or ""), path_resolved=exists,
        )
        if status != "active":
            result["reason"] = f"xsstrike registry 状态为 {status!r}，不可执行"
        elif not exists:
            result["reason"] = f"xsstrike 登记路径不可解析：{path!r}"
        else:
            result["reason"] = "xsstrike 已登记且路径可解析（计划可交操作者执行；本模块不代执行）"
            result["executable"] = True
        return result
    return result


def _screened_marker(candidate: dict) -> str:
    """返回命中的已筛选择标记；未筛选返回空串。"""
    for marker in SCREENED_CANDIDATE_MARKERS:
        value = candidate.get(marker)
        if value not in (None, "", 0):
            return marker
    return ""


def validate_screened_candidate(candidate: dict, label: str = "xsstrike_candidate") -> list[str]:
    """已筛选候选入口校验：字段、单参数、已筛选标记。"""
    violations: list[str] = []
    if not isinstance(candidate, dict):
        return [f"{label}: 候选必须是键值映射"]
    url = str(candidate.get("url") or "").strip()
    param = str(candidate.get("param") or "").strip()
    if not url:
        violations.append(f"{label}: 缺少 url（单目标硬约束）")
    if not param:
        violations.append(f"{label}: 缺少 param（单参数硬约束）")
    if param and ("," in param or " " in param):
        violations.append(f"{label}: param 含分隔符（单参数硬约束）")
    if not _screened_marker(candidate):
        violations.append(
            f"{label}: 缺少已筛选候选标记 {list(SCREENED_CANDIDATE_MARKERS)} 之一"
            "（规格 7.2：只处理已筛选的反射/DOM 候选，不接受未筛选 URL）"
        )
    return violations


def build_xsstrike_plan(
    candidate: dict,
    *,
    registry_path: str | Path | None = None,
    root: str | Path | None = None,
) -> tuple[dict, list[str]]:
    """构建单候选受控验证计划（纯数据；零执行、零网络）。

    违例：未筛选候选/缺 url/缺 param/多参数/registry 不可用。命令只含 -u 与
    --skip；plan 字段显式声明 no_crawl/no_blind/no_update。
    """
    violations = validate_screened_candidate(candidate)
    tool = resolve_xsstrike_tool(registry_path, root)
    url = str(candidate.get("url") or "").strip()
    param = str(candidate.get("param") or "").strip()
    args = [tool["path"] or "python xsstrike.py", "-u", url, "--skip"] if url and param else []
    plan = {
        "plan_only": True,
        "tool_id": XSSTRIKE_TOOL_ID,
        "tool_status": tool["status"],
        "tool_path": tool["path"],
        "executable": bool(tool["executable"] and not violations),
        "single_target": True,
        "single_param": True,
        "target": url,
        "param": param,
        "args": args,
        "command": " ".join(str(a) for a in args),
        "allowed_flags": list(PLAN_ALLOWED_FLAGS),
        "no_crawl": True,
        "no_blind": True,
        "no_update": True,
        "auth_note": "认证态由操作者环境决定；本模块不读取任何凭证文件",
        "note": "本模块只生成计划不执行；验证结果经 ingest 解析（单候选，无批量入口）",
        "reason": tool["reason"],
    }
    return plan, violations


def _derive_xss_validation_kinds(result: dict) -> list[str]:
    kinds: list[str] = []
    error = str(result.get("error") or "").strip()
    if result.get("waf_block"):
        kinds.append("waf_block")
    elif error or result.get("status") in (0, None, ""):
        kinds.append("error_or_timeout")
    elif result.get("dom_sink_hit"):
        kinds.append("dom_sink_reached")
    elif result.get("executable_context"):
        kinds.append("payload_reflected_in_executable_context")
    elif result.get("reflected"):
        kinds.append("reflected_not_executable")
    return kinds


def ingest_xsstrike_results(
    results: list[dict],
    *,
    label: str = "xsstrike_ingest",
) -> tuple[list[dict], dict, list[str]]:
    """单候选验证结果列表 → (候选行, 类别汇总行, 违例)。

    每条结果必须回指请求/响应/浏览器上下文/证据索引；param 错配、凭证类键、
    敏感值摘录拒绝。只产 signal/candidate/duplicate；confirmed 永不由本模块产生。
    """
    rows: list[dict] = []
    violations: list[str] = []
    seen: dict[str, int] = {}
    for index, raw in enumerate(results, start=1):
        row_label = f"{label}[{index}]"
        if not isinstance(raw, dict):
            violations.append(f"{row_label}: 验证结果必须是键值映射")
            continue
        violations += rb._credential_scan(raw, row_label)
        url = str(raw.get("url") or "").strip()
        param = str(raw.get("param") or "").strip()
        if not url or not param:
            violations.append(f"{row_label}: 缺少 url 或 param（结果必须回指请求）")
            continue
        excerpt = str(raw.get("console_excerpt") or "")
        if excerpt and SENSITIVE_VALUE_RE.search(excerpt):
            violations.append(
                f"{row_label}: console_excerpt 疑似含敏感值，已拒绝入行"
                "（凭证纪律：token/cookie/authorization 不进任何产物）"
            )
            raw = {k: v for k, v in raw.items() if k != "console_excerpt"}
        context = str(raw.get("context") or "unknown")
        if context not in BROWSER_CONTEXTS:
            violations.append(
                f"{row_label}: context 非法 {context!r}（允许值 {list(BROWSER_CONTEXTS)}）"
            )
            continue
        try:
            status = int(raw.get("status"))
        except (TypeError, ValueError):
            status = 0
        kinds = _derive_xss_validation_kinds(raw)
        satisfied, why = ic.rule_satisfied(
            XSS_VALIDATION_UPGRADE_RULE, kinds, XSS_VALIDATION_EVIDENCE_KINDS,
            XSS_VALIDATION_INSUFFICIENT_KINDS,
        )
        status_value = "candidate" if satisfied else "signal"
        evidence_ref = str(raw.get("evidence_ref") or "")
        if status_value == "candidate" and not evidence_ref:
            violations.append(f"{row_label}: candidate 缺少 evidence_ref（证据索引强制）")
            status_value = "signal"
            violations.append(f"{row_label}: 降级为 signal（证据索引缺失 fail-closed）")
        dedup_key = f"{url}|{param}"
        if dedup_key in seen:
            status_value = "duplicate"
            reason = f"与第 {seen[dedup_key]} 条结果重复（同 url+param）"
        elif status_value == "candidate":
            reason = "可执行上下文反射或 DOM sink 到达（candidate，待人工复核与浏览器上下文验证）"
        elif "reflected_not_executable" in kinds:
            reason = "反射但不可执行（13.2 负例），只记 signal"
        elif "waf_block" in kinds:
            reason = "WAF 拦截（停止条件信号），只记 signal"
        elif "error_or_timeout" in kinds:
            reason = "超时/错误，只记 signal"
        else:
            reason = "无升级证据：只记 signal"
        row = {
            "candidate_id": f"xssvalid-{index:04d}",
            "status": status_value,
            "evidence_kinds": kinds,
            "url": url,
            "param": param,
            "http_status": status,
            "browser_context": context,
            "source": f"{url} {param}",
            "evidence_ref": evidence_ref,
            "reason": reason,
        }
        rows.append(row)
        seen.setdefault(dedup_key, index)
        violations += validate_xss_validation_candidate(row, label=f"{label}[{row['candidate_id']}]")

    status_counts = {s: 0 for s in ic.CANDIDATE_STATUS_VALUES}
    for r in rows:
        status_counts[r["status"]] += 1
    tested_count = sum(status_counts[s] for s in ic.DEFINITIVE_RESULT_STATUSES)
    summary = {
        "category": XSS_VALIDATION_CATEGORY,
        "category_status": ic.aggregate_category_status([r["status"] for r in rows], False),
        "applicability_counts": {"applicable": len(rows), "not_applicable": 0, "unknown": 0},
        "status_counts": status_counts,
        "tested_count": tested_count,
        "reason": f"XSStrike 单候选验证：共 {len(rows)} 行（单目标单参数，无批量扫描）",
        "source": next((str(r["source"]) for r in rows if r.get("source")), ""),
        "precondition": "候选必须来自 xss_candidate_triage 已筛选反射/DOM 队列；验证由操作者执行",
    }
    violations += ic.validate_category_summary(summary, label=f"{label}.summary", categories=(XSS_VALIDATION_CATEGORY,))
    return rows, summary, violations


def validate_xss_validation_candidate(candidate: dict, label: str = "xss_validation_candidate") -> list[str]:
    """单候选验证行校验：8 状态 + 证据形态 + 升级规则 + 四要素回指。"""
    violations: list[str] = []
    if not isinstance(candidate, dict):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "status", "evidence_kinds", "url", "param"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    status = str(candidate.get("status") or "")
    if status and status not in ic.CANDIDATE_STATUS_VALUES:
        violations.append(f"{label}.status 非法: {status!r}（允许值 {list(ic.CANDIDATE_STATUS_VALUES)}）")
    if status == "confirmed":
        violations.append(f"{label}: confirmed 永不由单候选验证 ingest 产生（只产 signal/candidate/duplicate）")
    context = str(candidate.get("browser_context") or "unknown")
    if context not in BROWSER_CONTEXTS:
        violations.append(f"{label}.browser_context 非法: {context!r}")
    kinds = candidate.get("evidence_kinds")
    if kinds is not None:
        if not isinstance(kinds, (list, tuple)):
            violations.append(f"{label}.evidence_kinds 必须为列表")
        else:
            kind_list = [str(k) for k in kinds]
            unknown = sorted({k for k in kind_list if k not in XSS_VALIDATION_EVIDENCE_KINDS})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if status in ("candidate", "confirmed"):
                satisfied, why = ic.rule_satisfied(
                    XSS_VALIDATION_UPGRADE_RULE, kind_list, XSS_VALIDATION_EVIDENCE_KINDS,
                    XSS_VALIDATION_INSUFFICIENT_KINDS,
                )
                if not satisfied:
                    violations.append(f"{label}: status={status} 但升级证据不满足——{why}")
                present_negatives = [k for k in kind_list if k in XSS_VALIDATION_INSUFFICIENT_KINDS]
                if present_negatives:
                    violations.append(
                        f"{label}: status={status} 但含负例证据形态 {present_negatives}（永不升级）"
                    )
    if status in ("candidate", "confirmed", "needs_manual_validation"):
        for field in ("evidence_ref", "http_status", "browser_context"):
            if not candidate.get(field) and candidate.get(field) != 0:
                violations.append(f"{label}: status={status} 但 {field} 缺失（结果必须回指请求/响应/上下文/证据索引）")
    return violations
