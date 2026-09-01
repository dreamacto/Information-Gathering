"""ffuf 受控目录候选（实施规格 7.2 ffuf：受控目录候选能力；Batch 16）。

两个纯离线模式，模块自身永不执行 ffuf、永不发网络请求：

  plan   构建受控 ffuf 调用计划：固定小词表 wordlists/ffuf_dirs_small.txt（内置
         回退同文）、单目标、-t 1、-delay >= FFUF_MIN_DELAY 秒（ROE >=2s 间隔）、
         无递归参数（ffuf 默认不递归，计划显式不含 -recursion）、-of json。
         工具状态来自 tools/tool_registry.json（唯一事实源）：未登记或状态不是
         active 或路径不可解析 → executable=false fail-closed。executable 只表示
         "计划可交由操作者执行"，本模块任何情况下不代为执行。

  ingest 解析操作者手工产出的 ffuf `-of json` 结果行，与通配符基线（对随机不存在
         路径的响应）做 status/length/words/lines 数值差分，结合语义敏感名命中，
         只输出 signal/candidate（8 状态模型内）。升级规则复用
         injection_candidates.rule_satisfied（单一引擎）：required_all =
         baseline_differential + semantic_sensitive_name。负例（通配符 soft-404、
         登录页路径、WAF/403/429、超时/DNS、body 误报形态复用
         response_baseline 分类器）永不升级。200 不等于敏感资源存在；无基线
         fail-closed 全 signal。

与 dirsearch/根目录 dir_scanner.py 主链的关系：本模块是 ffuf 工具的受控接入
筛选层，不替换既有主链（tool_strategy 接线由 batch16_6 统一处理）。
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from authorized_assessment.tools import registry as tool_registry
from authorized_assessment.triage import injection_candidates as ic
from authorized_assessment.triage import response_baseline as rb

FFUF_TOOL_ID = "ffuf"

# ROE 速率红线：请求间隔 >=2s；ffuf -delay 单位为秒（计划取下限，操作者可调大）。
FFUF_MIN_DELAY_SECONDS = 2.0
FFUF_THREADS = 1
FFUF_TIMEOUT_SECONDS = 10

# 语义敏感目录名（语义证据：命中只算 supporting，不单独构成候选）。
SEMANTIC_SENSITIVE_NAMES: tuple[str, ...] = (
    "admin",
    "manager",
    "manage",
    "system",
    "backup",
    "bak",
    "db",
    "sql",
    "config",
    "conf",
    "upload",
    "download",
    "api-docs",
    "swagger",
    "actuator",
    "druid",
    "console",
    "jmx",
    "server-status",
    ".env",
    ".git",
    "web.config",
    "database",
    "phpinfo",
    "install",
    "setup",
    "debug",
    "log",
    "logs",
    "report",
)

# 登录页路径名（13.2 负例：登录页不可作目录候选升级）。
LOGIN_PAGE_PATH_NAMES: tuple[str, ...] = ("login", "signin", "sign-in", "auth", "sso", "logout")

# 证据形态：前两个为升级要件，其余为负例（永不升级）。
FFUF_EVIDENCE_KINDS: tuple[str, ...] = (
    "baseline_differential",
    "semantic_sensitive_name",
    "wildcard_soft404",
    "login_page_path",
    "waf_or_rate_block",
    "timeout_or_dns_error",
    "body_false_positive_pattern",
)
FFUF_INSUFFICIENT_KINDS: tuple[str, ...] = (
    "wildcard_soft404",
    "login_page_path",
    "waf_or_rate_block",
    "timeout_or_dns_error",
    "body_false_positive_pattern",
)

# 200 不等于敏感资源存在：候选必须同时有基线差分与语义命中（规格 7.2）。
FFUF_UPGRADE_RULE: dict[str, tuple[str, ...]] = {
    "required_all": ("baseline_differential", "semantic_sensitive_name"),
}

FFUF_CATEGORY = "ffuf_directory"

# 词表缺失时的内置回退（fail-soft：词表是计划入口不是安全边界；禁止联网下载）。
# 内容与 wordlists/ffuf_dirs_small.txt 保持一致（batch16_1 对齐，避免双表漂移）。
DEFAULT_FUZZ_DIRS: tuple[str, ...] = (
    "admin",
    "login",
    "manage",
    "manager",
    "system",
    "backup",
    "bak",
    "db",
    "sql",
    "config",
    "conf",
    "upload",
    "uploads",
    "download",
    "test",
    "api",
    "api-docs",
    "swagger",
    "swagger-ui",
    "actuator",
    "druid",
    "console",
    "jmx",
    "server-status",
    ".env",
    ".git",
    "web.config",
    "database",
    "phpinfo",
    "install",
    "setup",
    "debug",
    "tmp",
    "log",
    "logs",
    "report",
)


def load_ffuf_wordlist(path: str | Path | None = None) -> tuple[str, ...]:
    """加载固定小词表：默认 wordlists/ffuf_dirs_small.txt；缺失/不可读回退内置表。

    不下载、不扩充；词表内容为实施规格 7.2"固定小词表"的实现定义（batch16_1）。
    """
    if path is None:
        # src/authorized_assessment/triage/ → 项目根为 parents[3]
        root = Path(__file__).resolve().parents[3]
        path = root / "wordlists" / "ffuf_dirs_small.txt"
    try:
        words = tuple(
            w
            for w in Path(path).read_text(encoding="utf-8", errors="replace").split()
            if w.strip()
        )
    except OSError:
        return DEFAULT_FUZZ_DIRS
    return words or DEFAULT_FUZZ_DIRS


def resolve_ffuf_tool(
    registry_path: str | Path | None = None, root: str | Path | None = None
) -> dict:
    """从 tool registry 解析 ffuf 状态；executable 只表示计划可交操作者执行。

    未登记 / registry 不可读 / 状态非 active / 路径不可解析 → executable=false。
    """
    if root is None:
        root = Path(__file__).resolve().parents[3]
    if registry_path is None:
        registry_path = Path(root) / "tools" / "tool_registry.json"
    result = {
        "tool_id": FFUF_TOOL_ID,
        "registered": False,
        "status": "unregistered",
        "path": "",
        "version": "",
        "path_resolved": False,
        "executable": False,
        "reason": "ffuf 未登记于 tools/tool_registry.json（规格 7.1：不得伪装可执行）",
    }
    data, err = tool_registry.load_registry(registry_path)
    if err or not isinstance(data, dict):
        result["status"] = "registry_unreadable"
        result["reason"] = f"tool registry 不可读：{err or '结构缺失'}"
        return result
    for entry in data.get("tools", []):
        if not isinstance(entry, dict) or str(entry.get("tool_id")) != FFUF_TOOL_ID:
            continue
        status = str(entry.get("status") or "")
        path = str(entry.get("path") or "")
        resolved = tool_registry.resolve_tool_path(path, Path(root)) if path else None
        exists = bool(resolved is not None and str(path).strip() and resolved.exists())
        result.update(
            registered=True,
            status=status,
            path=path,
            version=str(entry.get("version") or ""),
            path_resolved=exists,
        )
        if status != "active":
            result["reason"] = f"ffuf registry 状态为 {status!r}，不可执行"
        elif not exists:
            result["reason"] = f"ffuf 登记路径不可解析：{path!r}"
        else:
            result["reason"] = "ffuf 已登记且路径可解析（计划可交操作者执行；本模块不代执行）"
            result["executable"] = True
        return result
    return result


_FORBIDDEN_TARGET_CHARS = set(" \t\r\n\"'`&|;<>(){}[]$!*?")

SHELL_UNSAFE_HINT = "target 含 shell 元字符或空白（计划串按原样展示，禁止注入面）"


def _validate_plan_target(target_url: str) -> list[str]:
    violations: list[str] = []
    target = (target_url or "").strip()
    if not target:
        violations.append("ffuf plan: 目标为空（单目标硬约束）")
        return violations
    if any(ch in _FORBIDDEN_TARGET_CHARS for ch in target):
        violations.append(f"ffuf plan: {SHELL_UNSAFE_HINT}")
    if "FUZZ" in target:
        violations.append("ffuf plan: 目标不得自带 FUZZ 关键字（由计划统一拼接 /FUZZ）")
    scheme = target.split("://", 1)[0].lower() if "://" in target else ""
    if scheme not in ("http", "https"):
        violations.append("ffuf plan: 目标必须是 http/https URL（单目标硬约束）")
    return violations


def build_ffuf_plan(
    target_url: str,
    *,
    output_path: str | Path,
    registry_path: str | Path | None = None,
    root: str | Path | None = None,
    wordlist_path: str | Path | None = None,
    delay_seconds: float = FFUF_MIN_DELAY_SECONDS,
) -> tuple[dict, list[str]]:
    """构建受控 ffuf 调用计划（纯数据；零执行、零网络）。

    违例：目标为空/多目标（空白分隔）/非 http(s)/自带 FUZZ/shell 元字符/词表缺失/
    工具未登记或不可用/delay 低于 ROE 下限。计划字段 recursion 恒为 False、
    threads 恒为 1（禁止默认递归、串行低速）。
    """
    violations = _validate_plan_target(target_url)
    tool = resolve_ffuf_tool(registry_path, root)
    if delay_seconds < FFUF_MIN_DELAY_SECONDS:
        violations.append(
            f"ffuf plan: delay_seconds={delay_seconds} 低于 ROE 下限 {FFUF_MIN_DELAY_SECONDS}s"
        )
        delay_seconds = FFUF_MIN_DELAY_SECONDS
    if wordlist_path is None:
        root_path = Path(root) if root is not None else Path(__file__).resolve().parents[3]
        wordlist_path = root_path / "wordlists" / "ffuf_dirs_small.txt"
    wordlist = load_ffuf_wordlist(wordlist_path)
    wordlist_file_exists = Path(wordlist_path).is_file()
    if not wordlist_file_exists:
        violations.append(f"ffuf plan: 固定词表不存在：{wordlist_path}")

    target = (target_url or "").strip().rstrip("/")
    fuzz_url = f"{target}/FUZZ" if target else ""
    args = [
        tool["path"] or "ffuf",
        "-w",
        str(wordlist_path),
        "-u",
        fuzz_url,
        "-t",
        str(FFUF_THREADS),
        "-delay",
        f"{delay_seconds:g}",
        "-timeout",
        str(FFUF_TIMEOUT_SECONDS),
        "-of",
        "json",
        "-o",
        str(output_path),
    ]
    plan = {
        "plan_only": True,
        "tool_id": FFUF_TOOL_ID,
        "tool_status": tool["status"],
        "tool_path": tool["path"],
        "executable": bool(tool["executable"] and not violations),
        "single_target": True,
        "target": fuzz_url,
        "wordlist": str(wordlist_path),
        "wordlist_size": len(wordlist) if wordlist_file_exists else 0,
        "threads": FFUF_THREADS,
        "delay_seconds": delay_seconds,
        "recursion": False,
        "args": args,
        "command": subprocess.list2cmdline(args),
        "note": "本模块只生成计划不执行；执行与否由操作者决定，结果经 ingest 解析",
        "reason": tool["reason"],
    }
    return plan, violations


def _normalize_result_row(row: dict) -> dict:
    """ffuf `-of json` 结果行 → 归一字段；input.FUZZ/keyword 兼容。"""
    input_map = row.get("input") if isinstance(row.get("input"), dict) else {}
    fuzz = str(input_map.get("FUZZ") or input_map.get("keyword") or "").strip()
    url = str(row.get("url") or "").strip()
    path = url if url else "/" + fuzz.lstrip("/")
    error = str(row.get("error") or "").strip()
    status_raw = row.get("status")
    try:
        status = int(status_raw)
    except (TypeError, ValueError):
        status = 0
    return {
        "url": url,
        "path": path,
        "fuzz": fuzz,
        "status": status,
        "length": row.get("length"),
        "words": row.get("words"),
        "lines": row.get("lines"),
        "content_type": str(row.get("content-type") or row.get("content_type") or ""),
        "error": error,
        "resultfile": str(row.get("resultfile") or ""),
        "text": str(row.get("text") or ""),
    }


def _derive_ffuf_kinds(normalized: dict, baseline: dict | None) -> list[str]:
    kinds: list[str] = []
    status = normalized["status"]
    error = normalized["error"].lower()
    if status in (403, 429):
        kinds.append("waf_or_rate_block")
    elif status == 0 or error:
        kinds.append("timeout_or_dns_error")
    elif status == 200:
        same_wildcard = bool(baseline) and all(
            normalized[field] == baseline.get(field)
            for field in ("length", "words", "lines")
        )
        if same_wildcard:
            kinds.append("wildcard_soft404")
        elif baseline:
            kinds.append("baseline_differential")
        # 无基线：fail-closed，不给差分证据（全 signal）。
    path_lower = normalized["path"].lower()
    last_segment = path_lower.rsplit("/", 1)[-1]
    if last_segment in LOGIN_PAGE_PATH_NAMES:
        kinds.append("login_page_path")
    # 语义命中按末段精确匹配（受控 ffuf 的 path 恒为 /FUZZ；子串匹配会把 log 误判到
    # login/catalog 等登录与业务路径上——batch16_1 实测负例修复）。
    if last_segment in SEMANTIC_SENSITIVE_NAMES:
        kinds.append("semantic_sensitive_name")
    if normalized["text"]:
        pattern = rb.detect_known_false_positive_pattern(
            {"url": normalized["url"], "status": normalized["status"], "text": normalized["text"]},
            rb.summarize_body(normalized["text"]),
        )
        if pattern:
            kinds.append("body_false_positive_pattern")
    return kinds


def ingest_ffuf_results(
    results: list[dict],
    baseline: dict | None = None,
    *,
    label: str = "ffuf_ingest",
) -> tuple[list[dict], dict, list[str]]:
    """ffuf 结果 → (候选行, 类别汇总行, 违例)。

    baseline 为通配符基线记录（对随机不存在路径的响应，含 status/length/words/
    lines）；缺省时 fail-closed：不可能产出 candidate（全 signal）。纯函数、
    幂等、确定性；只产 signal/candidate/duplicate（8 状态内），confirmed 永不由
    本模块产生。
    """
    rows: list[dict] = []
    violations: list[str] = []
    seen_urls: dict[str, int] = {}
    if baseline is not None and not isinstance(baseline, dict):
        violations.append(f"{label}: baseline 必须为键值映射或 null")
        baseline = None

    for index, raw in enumerate(results, start=1):
        if not isinstance(raw, dict):
            violations.append(f"{label}: 第 {index} 条结果必须是键值映射")
            continue
        normalized = _normalize_result_row(raw)
        if not normalized["url"] and not normalized["fuzz"]:
            violations.append(f"{label}: 第 {index} 条结果缺少 url 与 input.FUZZ")
            continue
        url = normalized["url"] or normalized["path"]
        if url in seen_urls:
            row = {
                "candidate_id": f"ffufdir-{index:04d}",
                "status": "duplicate",
                "evidence_kinds": [],
                "url": url,
                "path": normalized["path"],
                "status_code": normalized["status"],
                "content_type": normalized["content_type"],
                "source": url,
                "evidence_ref": normalized["resultfile"] or url,
                "reason": f"与第 {seen_urls[url]} 条结果重复（同 URL）",
            }
            rows.append(row)
            violations += validate_ffuf_candidate(row, label=f"{label}[{row['candidate_id']}]")
            continue
        seen_urls[url] = index

        kinds = _derive_ffuf_kinds(normalized, baseline)
        satisfied, why = ic.rule_satisfied(
            FFUF_UPGRADE_RULE, kinds, FFUF_EVIDENCE_KINDS, FFUF_INSUFFICIENT_KINDS
        )
        negatives = [k for k in kinds if k in FFUF_INSUFFICIENT_KINDS]
        # 负例在场即降级：升级要件齐全也只记 signal（13.2"命中就报漏洞"禁令）。
        status = "candidate" if satisfied and not negatives else "signal"
        if status == "signal":
            if "wildcard_soft404" in kinds:
                reason = "与通配符基线一致（soft-404），不构成候选"
            elif "waf_or_rate_block" in kinds:
                reason = "403/429 WAF 或限速响应（停止条件信号），不构成候选"
            elif "timeout_or_dns_error" in kinds:
                reason = "超时/DNS 错误，不构成候选"
            elif "login_page_path" in kinds:
                reason = "登录页路径，不构成目录候选升级"
            elif "body_false_positive_pattern" in kinds:
                reason = "响应体命中已知误报形态，不构成候选"
            elif normalized["status"] == 200 and not baseline:
                reason = "无基线 fail-closed：200 不等于敏感资源存在，只记 signal"
            elif "baseline_differential" in kinds:
                reason = "有基线差分但无语义命中：只记 signal"
            elif "semantic_sensitive_name" in kinds:
                reason = "仅语义名命中（无基线差分）：只记 signal"
            else:
                reason = "无升级证据：只记 signal"
        else:
            reason = "基线差分 + 语义敏感名同时命中（candidate，待人工复核）"
        row = {
            "candidate_id": f"ffufdir-{index:04d}",
            "status": status,
            "evidence_kinds": kinds,
            "url": url,
            "path": normalized["path"],
            "status_code": normalized["status"],
            "content_type": normalized["content_type"],
            "source": url,
            "evidence_ref": normalized["resultfile"] or url,
            "reason": reason + (f"；证据不足原因：{why}" if status == "signal" and negatives else ""),
            "baseline_available": baseline is not None,
        }
        rows.append(row)
        violations += validate_ffuf_candidate(row, label=f"{label}[{row['candidate_id']}]")

    status_counts = {s: 0 for s in ic.CANDIDATE_STATUS_VALUES}
    for r in rows:
        status_counts[r["status"]] += 1
    tested_count = sum(status_counts[s] for s in ic.DEFINITIVE_RESULT_STATUSES)
    category_status = ic.aggregate_category_status(
        [r["status"] for r in rows], False
    )
    summary = {
        "category": FFUF_CATEGORY,
        "category_status": category_status,
        "applicability_counts": {
            "applicable": len(rows),
            "not_applicable": 0,
            "unknown": 0,
        },
        "status_counts": status_counts,
        "tested_count": tested_count,
        "reason": (
            f"ffuf 受控目录候选：共 {len(rows)} 行（baseline_available={baseline is not None}）"
        ),
        "source": next((str(r["url"]) for r in rows if r.get("url")), ""),
        "precondition": "受控 ffuf（固定小词表/单目标/-t 1/-delay>=2s/无递归）由操作者执行",
    }
    violations += ic.validate_category_summary(summary, label=f"{label}.summary", categories=(FFUF_CATEGORY,))
    return rows, summary, violations


def validate_ffuf_candidate(candidate: dict, label: str = "ffuf_candidate") -> list[str]:
    """ffuf 候选行校验：8 状态 + 证据形态 + 升级规则（复用 injection_candidates 引擎）。"""
    violations: list[str] = []
    if not isinstance(candidate, dict):
        return [f"{label}: 候选必须是键值映射"]
    for field in ("candidate_id", "status", "evidence_kinds", "url"):
        if field not in candidate:
            violations.append(f"{label}: 缺少必需字段 {field}")
    status = str(candidate.get("status") or "")
    if status and status not in ic.CANDIDATE_STATUS_VALUES:
        violations.append(f"{label}.status 非法: {status!r}（允许值 {list(ic.CANDIDATE_STATUS_VALUES)}）")
    if status == "confirmed":
        violations.append(f"{label}: confirmed 永不由 ffuf ingest 产生（只产 signal/candidate/duplicate）")
    kinds = candidate.get("evidence_kinds")
    if kinds is not None:
        if not isinstance(kinds, (list, tuple)):
            violations.append(f"{label}.evidence_kinds 必须为列表")
        else:
            kind_list = [str(k) for k in kinds]
            unknown = sorted({k for k in kind_list if k not in FFUF_EVIDENCE_KINDS})
            if unknown:
                violations.append(f"{label}.evidence_kinds 未知形态: {unknown}")
            if status in ("candidate", "confirmed"):
                satisfied, why = ic.rule_satisfied(
                    FFUF_UPGRADE_RULE, kind_list, FFUF_EVIDENCE_KINDS, FFUF_INSUFFICIENT_KINDS
                )
                if not satisfied:
                    violations.append(f"{label}: status={status} 但升级证据不满足——{why}")
                present_negatives = [k for k in kind_list if k in FFUF_INSUFFICIENT_KINDS]
                if present_negatives:
                    violations.append(
                        f"{label}: status={status} 但含负例证据形态 {present_negatives}（永不升级）"
                    )
    if status in ("candidate", "confirmed", "needs_manual_validation") and not str(
        candidate.get("evidence_ref") or ""
    ).strip():
        violations.append(f"{label}: status={status} 但 evidence_ref 为空（候选必须可证明）")
    return violations
