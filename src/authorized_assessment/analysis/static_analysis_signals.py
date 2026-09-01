"""静态分析信号（实施规格 7.2 Semgrep/CodeQL 二选一：Semgrep；Batch 16）。

二选一决策（batch16_0 记录）：引入 Semgrep，不引入 CodeQL——单二进制、--json
结构化输出、本地规则目录即用，无需 CodeQL 数据库+查询套件的重型链路。

接入（规格 7.2）：static_analysis / whitebox_triage。为 whitebox-review skill
依赖的 sink_findings 管线提供离线信号层。

两个纯离线模式，模块自身永不执行工具、永不联网：

  plan   构建 Semgrep 离线扫描计划：--config 只允许本地规则目录/文件（显式拒绝
         auto / p/ / r/ / registry / http(s) 远程配置——"规则固定在本地，不联网
         拉规则"）；--metrics=off 禁遥测；--json 输出。工具状态来自
         tools/tool_registry.json（tool_id=semgrep）：未登记/非 active/路径不可
         解析 → executable=false fail-closed。

  ingest 解析操作者手工产出的 semgrep --json 输出（results/errors）：每条命中
         产一行 sink/source/path/上下文 signal 记录（check_id、path、起止行、
         message、代码摘录、证据索引）。静态命中硬编码 status=signal——validator
         拒绝 candidate/confirmed（规格 13.2：只有静态 sink、无可达链路，不能
         自动变成漏洞），需要后续可触达与影响验证。代码摘录命中疑似敏感值形态
         或凭证类键 → 丢弃摘录保留位置并记违例（凭证纪律）。同
         (check_id, path, start_line) 去重标 duplicate。semgrep errors 列表
         逐条进违例。
"""
from __future__ import annotations

import re
from pathlib import Path

from authorized_assessment.tools import registry as tool_registry
from authorized_assessment.triage import injection_candidates as ic
from authorized_assessment.triage import response_baseline as rb

SEMGREP_TOOL_ID = "semgrep"
STATIC_ANALYSIS_CATEGORY = "static_analysis"

# 禁止的规则配置来源（联网/registry 拉取）；--config 必须是本地路径。
FORBIDDEN_CONFIG_SOURCES: tuple[str, ...] = ("auto", "p/", "r/", "registry", "http://", "https://")

# 疑似敏感值形态（代码摘录值级扫描；命中即丢弃摘录）。
SENSITIVE_VALUE_RE = re.compile(
    r"(cookie\s*[:=]|authorization\s*[:=]|bearer\s+[A-Za-z0-9._~+/=-]+|session_key"
    r"|appsecret|app_secret|api[_-]?key\s*[:=]|password\s*[:=]|passwd\s*[:=]"
    r"|secret[a-z0-9_-]*\s*[:=])",
    re.I,
)

# 静态信号行合法状态（signal 为主；重复标 duplicate）。
STATIC_SIGNAL_STATUSES: tuple[str, ...] = ("signal", "duplicate")


def resolve_semgrep_tool(
    registry_path: str | Path | None = None, root: str | Path | None = None
) -> dict:
    """从 tool registry 解析 semgrep 状态；executable 只表示计划可交操作者执行。"""
    if root is None:
        root = Path(__file__).resolve().parents[3]
    root = Path(root)
    result = {
        "tool_id": SEMGREP_TOOL_ID,
        "registered": False,
        "status": "unregistered",
        "path": "",
        "version": "",
        "path_resolved": False,
        "executable": False,
        "reason": "semgrep 未登记于 tools/tool_registry.json（规格 7.1：不得伪装可执行）",
    }
    data, err = tool_registry.load_registry(root / "tools" / "tool_registry.json" if registry_path is None else registry_path)
    if err or not isinstance(data, dict):
        result["status"] = "registry_unreadable"
        result["reason"] = f"tool registry 不可读：{err or '结构缺失'}"
        return result
    for entry in data.get("tools", []):
        if not isinstance(entry, dict) or str(entry.get("tool_id")) != SEMGREP_TOOL_ID:
            continue
        status = str(entry.get("status") or "")
        path = str(entry.get("path") or "")
        resolved = tool_registry.resolve_tool_path(path, root) if path else None
        exists = bool(resolved is not None and str(path).strip() and resolved.exists())
        result.update(
            registered=True, status=status, path=path,
            version=str(entry.get("version") or ""), path_resolved=exists,
        )
        if status != "active":
            result["reason"] = f"semgrep registry 状态为 {status!r}，不可执行"
        elif not exists:
            result["reason"] = f"semgrep 登记路径不可解析：{path!r}"
        else:
            result["reason"] = "semgrep 已登记且路径可解析（计划可交操作者执行；本模块不代执行）"
            result["executable"] = True
        return result
    return result


def _validate_rules_config(rules_config: str) -> list[str]:
    violations: list[str] = []
    value = (rules_config or "").strip()
    if not value:
        violations.append("semgrep plan: --config 为空（本地规则路径必填）")
        return violations
    lowered = value.lower()
    for forbidden in FORBIDDEN_CONFIG_SOURCES:
        if lowered == forbidden or lowered.startswith(forbidden):
            violations.append(
                f"semgrep plan: --config {value!r} 命中禁用来源 {forbidden!r}"
                "（规格 7.2：规则固定在本地，不联网拉规则）"
            )
    if "://" in value:
        violations.append(f"semgrep plan: --config 必须是本地路径（不得带 scheme）: {value!r}")
    return violations


def build_semgrep_plan(
    source_root: str | Path,
    rules_config: str | Path,
    *,
    output_path: str | Path,
    registry_path: str | Path | None = None,
    root: str | Path | None = None,
) -> tuple[dict, list[str]]:
    """构建 Semgrep 离线扫描计划（纯数据；零执行、零联网）。

    违例：规则配置指向远程/registry、规则目录或源码根不存在、registry 不可用。
    计划固定 --metrics=off 与 --json（结构化、禁遥测）。
    """
    if root is None:
        root = Path(__file__).resolve().parents[3]
    root = Path(root)
    violations = _validate_rules_config(str(rules_config))
    rules_path = Path(rules_config)
    if str(rules_config).strip() and not rules_path.exists():
        violations.append(f"semgrep plan: 本地规则路径不存在：{rules_path}")
    source_path = Path(source_root)
    if not str(source_root).strip():
        violations.append("semgrep plan: 源码根为空")
    elif not source_path.exists():
        violations.append(f"semgrep plan: 源码根不存在：{source_path}")
    tool = resolve_semgrep_tool(registry_path, root)
    args = [
        tool["path"] or "semgrep",
        "scan",
        "--config",
        str(rules_path),
        "--json",
        "--metrics=off",
        "--output",
        str(output_path),
        str(source_path),
    ]
    plan = {
        "plan_only": True,
        "tool_id": SEMGREP_TOOL_ID,
        "tool_status": tool["status"],
        "tool_path": tool["path"],
        "executable": bool(tool["executable"] and not violations),
        "source_root": str(source_path),
        "rules_config": str(rules_path),
        "rules_local_only": True,
        "metrics_off": True,
        "output": str(output_path),
        "args": args,
        "command": " ".join(str(a) for a in args),
        "forbidden_config_sources": list(FORBIDDEN_CONFIG_SOURCES),
        "note": "静态命中只产 signal（sink/source/路径/上下文），不能自动变成漏洞；需后续可触达与影响验证",
        "reason": tool["reason"],
    }
    return plan, violations


def _sanitize_excerpt(excerpt: str) -> tuple[str, bool]:
    """摘录敏感值扫描：命中 → 返回 ("", True)（丢弃摘录保留位置）。"""
    if excerpt and SENSITIVE_VALUE_RE.search(excerpt):
        return "", True
    return excerpt, False


def ingest_semgrep_results(
    results: list[dict],
    *,
    evidence_ref: str = "",
    label: str = "semgrep_ingest",
) -> tuple[list[dict], dict, list[str]]:
    """semgrep --json 结果 → (静态信号行, 类别汇总, 违例)。

    results 为解析后的 JSON（含 results/errors 键）或单行 result 字典列表。
    每行强制 status=signal（validator 拒绝 candidate/confirmed）；重复命中标
    duplicate。excerpts 敏感值扫描命中即丢弃（保留位置）。
    """
    rows: list[dict] = []
    violations: list[str] = []
    seen: set[tuple[str, str, int]] = set()
    if isinstance(results, dict):
        hits = results.get("results") or []
        errors = results.get("errors") or []
    elif isinstance(results, list):
        hits = results
        errors = []
    else:
        return rows, {}, [f"{label}: 输入必须是 JSON object 或 result 行列表"]
    for index, error in enumerate(errors, start=1):
        violations.append(f"{label}.errors[{index}]: {error}")

    for index, raw in enumerate(hits, start=1):
        row_label = f"{label}.results[{index}]"
        if not isinstance(raw, dict):
            violations.append(f"{row_label}: 命中必须是键值映射")
            continue
        violations += rb._credential_scan(raw, row_label)
        check_id = str(raw.get("check_id") or "").strip()
        path = str(raw.get("path") or "").strip()
        start = raw.get("start") if isinstance(raw.get("start"), dict) else {}
        end = raw.get("end") if isinstance(raw.get("end"), dict) else {}
        try:
            start_line = int(start.get("line"))
        except (TypeError, ValueError):
            start_line = 0
        if not check_id or not path or not start_line:
            violations.append(f"{row_label}: 缺少 check_id/path/start.line（命中必须可定位）")
            continue
        extra = raw.get("extra") if isinstance(raw.get("extra"), dict) else {}
        message = str(extra.get("message") or "").strip()
        severity = str(extra.get("severity") or "").strip()
        excerpt, sanitized = _sanitize_excerpt(str(extra.get("lines") or ""))
        if sanitized:
            violations.append(
                f"{row_label}: 代码摘录疑似含敏感值，已丢弃摘录（保留位置；凭证纪律）"
            )
        key = (check_id, path, start_line)
        is_duplicate = key in seen
        seen.add(key)
        row = {
            "signal_id": f"staticsig-{index:04d}",
            "status": "duplicate" if is_duplicate else "signal",
            "check_id": check_id,
            "path": path,
            "start_line": start_line,
            "end_line": int(end.get("line")) if str(end.get("line") or "").isdigit() else start_line,
            "message": message,
            "severity": severity,
            "context": excerpt,
            "source": f"{path}:{start_line}",
            "evidence_ref": str(raw.get("evidence_ref") or evidence_ref),
            "reason": (
                "静态命中仅为 signal（sink/source/路径/上下文）；需后续可触达与影响验证"
                if not is_duplicate
                else f"重复命中（同 check_id/path/行）"
            ),
        }
        rows.append(row)
        violations += validate_static_signal(row, label=f"{label}[{row['signal_id']}]")

    status_counts = {s: 0 for s in ic.CANDIDATE_STATUS_VALUES}
    for r in rows:
        status_counts[r["status"]] += 1
    summary = {
        "category": STATIC_ANALYSIS_CATEGORY,
        "category_status": ic.aggregate_category_status([r["status"] for r in rows], False),
        "applicability_counts": {"applicable": len(rows), "not_applicable": 0, "unknown": 0},
        "status_counts": status_counts,
        "tested_count": sum(status_counts[s] for s in ic.DEFINITIVE_RESULT_STATUSES),
        "reason": f"静态分析信号：共 {len(rows)} 行（静态命中只产 signal，不确认漏洞）",
        "source": next((str(r["source"]) for r in rows if r.get("source")), ""),
        "precondition": "规则固定本地、--metrics=off；静态命中需人工可触达与影响验证",
    }
    violations += ic.validate_category_summary(summary, label=f"{label}.summary", categories=(STATIC_ANALYSIS_CATEGORY,))
    return rows, summary, violations


def validate_static_signal(row: dict, label: str = "static_signal") -> list[str]:
    """静态信号行校验：只允许 signal/duplicate；candidate/confirmed 一律拒绝。"""
    violations: list[str] = []
    if not isinstance(row, dict):
        return [f"{label}: 行必须是键值映射"]
    for field in ("signal_id", "status", "check_id", "path", "start_line"):
        if field not in row:
            violations.append(f"{label}: 缺少必需字段 {field}")
    status = str(row.get("status") or "")
    if status and status not in STATIC_SIGNAL_STATUSES:
        if status in ("candidate", "confirmed"):
            violations.append(
                f"{label}: status={status} 被拒绝——静态命中不能自动变成漏洞"
                "（规格 7.2/13.2：只有静态 sink、无可达链路）"
            )
        else:
            violations.append(
                f"{label}.status 非法: {status!r}（静态信号行只允许 {list(STATIC_SIGNAL_STATUSES)}）"
            )
    return violations
