#!/usr/bin/env python3
"""Offline post-fingerprint deepening plan.

This stage turns product/framework fingerprints into a structured next-step
matrix. It does not send requests or run exploit tools. The output is meant to
answer: "Now that this looks like Shiro/Spring/Druid/Nacos/OA/etc., what is the
best low-risk next check, which local tool can help, and which actions need
operator approval?"
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from .product_triage import build_findings


BASE_DIR = Path(__file__).resolve().parent
TOOLS_DIR = BASE_DIR / "tools"
MANAGED_DIR = TOOLS_DIR / "managed"


GENERIC_DEEPENING = {
    "safe_checks": [
        "确认产品/框架指纹是否来自真实页面而不是统一错误页或 WAF 页",
        "只读取标题、状态码、响应头、公开版本、公开文档、JSON schema 和字段名",
        "把同一 host 的 API、登录面、产品候选和二次复测结果合并判断",
    ],
    "approval_checks": [
        "漏洞模板主动验证",
        "批量扫描或高并发扫描",
        "任何写入、导出、下载、登录爆破、回连或命令执行动作",
    ],
    "tool_preference": ["nuclei", "afrog", "manual_browser_or_proxy"],
    "runner_followup": "review_only",
}


PRODUCT_DEEPENING: dict[str, dict] = {
    "shiro": {
        "safe_checks": [
            "复核 shiro_triage.py 的 rememberMe 行为、invalid rememberMe 是否被 deleteMe",
            "统计本地 Shiro key 字典来源和数量，但不自动爆破",
            "只在单目标审批后打开 ShiroAttack2 做 key/rememberMe 验证",
        ],
        "approval_checks": ["Shiro key brute force", "serialized payload", "command execution", "memory shell"],
        "tool_preference": ["shiro_triage.py", "ShiroAttack2", "manual_request_review"],
        "runner_followup": "shiro_triage",
    },
    "springboot": {
        "safe_checks": [
            "优先复核 /actuator、/actuator/health、/actuator/info、/actuator/mappings 这类只读元数据",
            "确认响应不是统一 404/403/login/WAF 页面",
            "只记录 endpoint、状态、字段名、hash，不保存 env/heapdump/logfile 内容",
        ],
        "approval_checks": ["heapdump download", "env secret extraction", "logfile download", "actuator exploit chain"],
        "tool_preference": ["springboot_triage.py", "SpringBoot-Scan.py", "nuclei springboot actuator templates", "manual_browser"],
        "runner_followup": "springboot_triage",
    },
    "druid": {
        "safe_checks": [
            "复核 Druid panel/basic.json/datasource.json 是否真实可访问",
            "只记录版本、登录态、字段名和状态码，不保存连接串/账号/SQL 明细",
        ],
        "approval_checks": ["credential testing", "datasource secret extraction", "SQL/query access"],
        "tool_preference": ["runner_high_value_paths", "nuclei", "manual_browser"],
        "runner_followup": "high_value_paths",
    },
    "swagger": {
        "safe_checks": [
            "读取 OpenAPI/Swagger/Knife4j schema，提取 GET-like API",
            "按业务字段、权限字段、列表/详情/查询接口提高优先级",
            "跳过 export/download/delete/update/submit/pay/password/file 等接口",
        ],
        "approval_checks": ["write endpoint call", "export/download", "bulk enumeration", "auth bypass"],
        "tool_preference": ["api_discovery.py", "api_endpoint_confirm.py", "nuclei"],
        "runner_followup": "api_discovery_api_confirm",
    },
    "nacos": {
        "safe_checks": [
            "确认 /nacos/ 面板、版本和登录/鉴权状态",
            "只做状态、标题、公开元数据复核，不拉取配置内容",
        ],
        "approval_checks": ["config retrieval", "auth bypass", "default token tricks", "namespace changes"],
        "tool_preference": ["nacos_triage.py", "nuclei nacos templates", "manual_request_review"],
        "runner_followup": "nacos_triage",
    },
    "tomcat": {
        "safe_checks": [
            "确认 Tomcat/Manager 页面是否真实存在，记录状态码、标题和 WWW-Authenticate",
            "不尝试默认口令，不上传 WAR",
        ],
        "approval_checks": ["default credential check", "WAR upload", "manager command execution"],
        "tool_preference": ["tomcat_triage.py", "nuclei weblogic/tomcat templates", "manual_request_review"],
        "runner_followup": "tomcat_triage",
    },
    "weblogic": {
        "safe_checks": [
            "确认 console/version/protocol 暴露和 WebLogic 指纹",
            "只做公开页面、响应头、版本线索复核",
        ],
        "approval_checks": ["T3/RCE exploit", "deserialization payload", "console credential testing"],
        "tool_preference": ["tomcat_triage.py", "nuclei weblogic/tomcat templates", "manual_request_review"],
        "runner_followup": "tomcat_triage",
    },
    "redis": {
        "safe_checks": [
            "只发送 PING / TCP connect / GET / 做无凭据可达性判断",
            "绝不执行 config/set/save、写 ssh 公钥或 crontab、读取 ES 索引",
        ],
        "approval_checks": ["redis command execution", "ssh-key/crontab write", "slaveof", "ES index data read"],
        "tool_preference": ["redis_triage.py", "nuclei redis/es templates", "redis-cli manual (approval only)"],
        "runner_followup": "redis_triage",
    },
    "fastjson": {
        "safe_checks": [
            "先找 Java/API/JSON-heavy 入口、错误栈、依赖或版本线索",
            "只把 Fastjson 作为候选组件，不直接发送反序列化 payload",
        ],
        "approval_checks": ["deserialization payload", "JNDI/DNSLog/callback", "command execution"],
        "tool_preference": ["fastjson_triage.py", "FastjsonScan.exe", "nuclei fastjson templates", "manual_request_review"],
        "runner_followup": "fastjson_triage",
    },
    "log4j": {
        "safe_checks": [
            "优先通过产品版本、依赖泄露、错误栈、供应商公告确认 Log4j 风险",
            "把 Java/OA/ERP/中间件指纹作为 Log4j 复核背景",
        ],
        "approval_checks": ["JNDI payload", "LDAP/RMI/DNS callback", "RCE validation"],
        "tool_preference": ["nuclei", "manual_version_review"],
        "runner_followup": "product_queue_only",
    },
    "struts2": {
        "safe_checks": [
            "收集 .action 路由、Struts 错误页、框架头、页面源码线索",
            "只确认框架存在和版本/路由特征",
        ],
        "approval_checks": ["OGNL payload", "RCE validation", "content-type exploit probes"],
        "tool_preference": ["struts2_triage.py", "Struts2Scan.py", "nuclei struts cves", "manual_request_review"],
        "runner_followup": "struts2_triage",
    },
    "thinkphp": {
        "safe_checks": [
            "确认 ThinkPHP 错误页、路由风格、版本线索、index.php?s= 入口",
            "先做指纹/版本/错误页证据，不发函数调用 payload",
        ],
        "approval_checks": ["RCE payload", "function call probes", "file write"],
        "tool_preference": ["nuclei", "afrog", "manual_browser"],
        "runner_followup": "product_queue_only",
    },
    "ruoyi": {
        "safe_checks": [
            "联动 Spring Boot、Druid、Shiro、Swagger/API、弱口令人工入口",
            "优先查看 /prod-api/、登录态、接口 schema 和权限字段",
        ],
        "approval_checks": ["default credential check", "auth bypass", "SQLMap", "file upload/RCE"],
        "tool_preference": ["api_discovery.py", "shiro_triage.py", "nuclei"],
        "runner_followup": "api_shiro_druid_chain",
    },
    "jeecgboot": {
        "safe_checks": [
            "联动 Swagger/API、Shiro/JWT、Druid、权限菜单/用户接口",
            "优先只读 schema 和业务字段复核",
        ],
        "approval_checks": ["default credential check", "auth bypass", "file upload/RCE", "SQLMap"],
        "tool_preference": ["api_discovery.py", "nuclei", "manual_browser"],
        "runner_followup": "api_product_chain",
    },
    "xxl_job": {
        "safe_checks": ["确认 XXL-Job Admin 面板和版本/登录状态", "只记录公开元数据和面板状态"],
        "approval_checks": ["default credential check", "executor token abuse", "RCE/task execution"],
        "tool_preference": ["nuclei", "manual_browser"],
        "runner_followup": "manual_single_target",
    },
    "yapi": {
        "safe_checks": ["确认 YApi 项目/API 是否公开", "只记录项目名、接口路径、字段名，不保存业务值"],
        "approval_checks": ["RCE checks", "account registration abuse", "data export"],
        "tool_preference": ["nuclei", "manual_browser"],
        "runner_followup": "api_docs_review",
    },
    "jenkins": {
        "safe_checks": ["确认 Jenkins 面板、版本、匿名可见范围", "不测试凭据，不执行脚本控制台"],
        "approval_checks": ["default credential check", "script console", "job execution", "plugin exploit"],
        "tool_preference": ["nuclei", "manual_browser"],
        "runner_followup": "manual_single_target",
    },
    "grafana": {
        "safe_checks": ["确认 Grafana 面板、版本、匿名 dashboard 可见范围", "不测试默认口令"],
        "approval_checks": ["default credential check", "plugin exploit", "snapshot/export data access"],
        "tool_preference": ["nuclei", "manual_browser"],
        "runner_followup": "manual_single_target",
    },
    "wordpress": {
        "safe_checks": ["确认 WordPress core/plugin/theme 公开版本", "只做公开元数据和目录暴露复核"],
        "approval_checks": ["user enumeration abuse", "credential testing", "plugin exploit"],
        "tool_preference": ["nuclei", "manual_browser"],
        "runner_followup": "cms_metadata_review",
    },
}


FAMILY_DEEPENING = {
    "oa": {
        "safe_checks": [
            "确认 OA 产品、版本、登录态、公开 API/附件/流程接口元数据",
            "优先信息泄露、认证边界、接口 schema，避免上传/导出/任意登录模板",
        ],
        "approval_checks": ["arbitrary login", "file upload", "file download", "RCE", "workflow operation"],
        "tool_preference": ["afrog", "nuclei", "OA-EXPTOOL legacy templates"],
        "runner_followup": "oa_queue_only",
    },
    "oa_erp": {
        "safe_checks": [
            "确认 ERP/OA 产品和业务 API 面，敏感业务数据只看字段名/数量/hash",
            "把文件、SQL、认证边界候选拆成单目标审批项",
        ],
        "approval_checks": ["SQLMap", "file read/export", "auth bypass", "upload", "business data access"],
        "tool_preference": ["afrog", "nuclei", "manual_browser_or_proxy"],
        "runner_followup": "erp_queue_only",
    },
    "cms": {
        "safe_checks": ["确认 CMS 版本、公开插件/主题、后台入口和目录暴露", "不做口令或插件利用"],
        "approval_checks": ["credential testing", "plugin exploit", "file upload"],
        "tool_preference": ["nuclei", "afrog", "manual_browser"],
        "runner_followup": "cms_metadata_review",
    },
    "middleware": {
        "safe_checks": ["确认中间件面板、版本、公开只读元数据", "拆分默认口令/RCE/文件读取为审批项"],
        "approval_checks": ["default credential check", "RCE", "file read", "config extraction"],
        "tool_preference": ["nuclei", "manual_browser"],
        "runner_followup": "middleware_metadata_review",
    },
}


TOOL_IMPORT_CANDIDATES = [
    {
        "name": "nuclei",
        "role": "通用模板引擎，适合做筛选后的低速单目标确认",
        "status": "already_installed_managed",
        "recommended": "primary_general_engine",
    },
    {
        "name": "afrog",
        "role": "中文/OA/常见 Web 漏洞模板覆盖",
        "status": "already_installed_managed",
        "recommended": "primary_china_oa_engine",
    },
    {
        "name": "ShiroAttack2",
        "role": "Shiro 单目标人工验证",
        "status": "already_installed_managed",
        "recommended": "manual_approval_only",
    },
    {
        "name": "xray",
        "role": "被动代理/主动扫描均可，但主动验证风险较高",
        "status": "local_legacy_present_if_xray.exe_exists",
        "recommended": "manual_proxy_or_approval_only",
    },
    {
        "name": "TscanPlus",
        "role": "综合 GUI 扫描器，适合人工单目标补充",
        "status": "local_present_if_TscanPlus_exists",
        "recommended": "manual_approval_only",
    },
    {
        "name": "Yakit/Yak",
        "role": "综合安全平台和 PoC/代理工作台",
        "status": "not_imported_by_default",
        "recommended": "candidate_for_later_manual_import",
    },
    {
        "name": "pocsuite3",
        "role": "PoC 框架，适合单目标审批后的验证",
        "status": "not_imported_by_default",
        "recommended": "candidate_for_later_manual_import",
    },
]


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict:
    if not path.exists() or not path.read_text(encoding="utf-8", errors="ignore").strip():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def csv_join(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(item) for item in value if item not in (None, ""))
    return str(value)


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: csv_join(row.get(field, "")) for field in fieldnames})


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or urlparse(url).netloc or "").lower()
    except Exception:
        return ""


def priority_from_score(score: int) -> str:
    if score >= 85:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    return "P3"


def count_nonempty_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())


def first_existing(*paths: Path) -> str:
    for path in paths:
        if path.exists():
            return str(path)
    return ""


def local_tool_inventory() -> dict:
    managed = read_json(MANAGED_DIR / "managed_inventory.json")
    tools: dict[str, dict] = {}
    for item in managed.get("tools", []) if isinstance(managed.get("tools"), list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").lower()
        if name:
            tools[name] = {
                "installed": bool(item.get("installed")),
                "version": item.get("version", ""),
                "path": item.get("path", ""),
                "release": item.get("release", ""),
                "sha256": item.get("sha256", ""),
            }

    extras = {
        "xray": TOOLS_DIR / "xray.exe",
        "ehole": TOOLS_DIR / "ehole.exe",
        "tscanplus": TOOLS_DIR / "TscanPlus",
        "dddd": TOOLS_DIR / "dddd",
        "oa-exptool": TOOLS_DIR / "OA-EXPTOOL",
        "oaexp": TOOLS_DIR / "OAexp",
    }
    for name, path in extras.items():
        tools[name] = {
            "installed": path.exists(),
            "version": "",
            "path": str(path) if path.exists() else "",
            "release": "",
            "sha256": "",
        }

    shiro_key_files = [
        TOOLS_DIR / "shiro_keys_master.txt",
        TOOLS_DIR / "shiro" / "shiro_attack2" / "data" / "shiro_keys.txt",
        TOOLS_DIR / "shiro" / "shiro" / "data" / "shiro_keys.txt",
        TOOLS_DIR / "dddd" / "common" / "config" / "pocs" / "helpers" / "wordlists" / "shiro_encrypted_keys.txt",
    ]
    return {
        "generated_at": now_iso(),
        "tools": tools,
        "shiro_key_wordlists": [
            {"path": str(path), "exists": path.exists(), "nonempty_lines": count_nonempty_lines(path)}
            for path in shiro_key_files
        ],
        "external_import_candidates": TOOL_IMPORT_CANDIDATES,
        "policy": "Inventory and planning only. Newly downloaded or active tools require operator approval before import or execution.",
    }


def load_product_findings(run_dir: Path) -> list[dict]:
    rows = read_jsonl(run_dir / "product_fingerprints.jsonl")
    if rows:
        return rows
    return build_findings(run_dir)


def deepening_rule(product_id: str, family: str) -> dict:
    rule = dict(GENERIC_DEEPENING)
    family_rule = FAMILY_DEEPENING.get(family, {})
    product_rule = PRODUCT_DEEPENING.get(product_id, {})
    for source in (family_rule, product_rule):
        for key, value in source.items():
            if isinstance(value, list):
                rule[key] = list(dict.fromkeys([*rule.get(key, []), *value]))
            else:
                rule[key] = value
    return rule


def template_names(rows: list[dict], limit: int = 8) -> list[str]:
    out = []
    for row in rows[:limit]:
        name = row.get("name") or Path(str(row.get("path") or "")).name
        if name:
            out.append(str(name))
    return out


def template_paths(rows: list[dict], limit: int = 4) -> list[str]:
    return [str(row.get("path") or "") for row in rows[:limit] if row.get("path")]


def command_previews(finding: dict, review_templates: list[dict], inventory: dict) -> list[str]:
    base_url = str(finding.get("base_url") or "")
    host = host_of(base_url) or str(finding.get("host") or "")
    tools = inventory.get("tools", {})
    nuclei = tools.get("nuclei", {}).get("path", "")
    previews: list[str] = []
    if nuclei and review_templates:
        target_out = f"manual_tool_outputs/{host}_nuclei_readonly.jsonl"
        for template in template_paths(review_templates, 3):
            previews.append(
                f'"{nuclei}" -u "{base_url}" -t "{template}" -rl 1 -c 1 -timeout 8 -retries 0 -no-color -jsonl -o "{target_out}"'
            )
    return previews


def build_plan(run_dir: Path) -> tuple[list[dict], list[dict], list[dict], list[dict], dict]:
    findings = load_product_findings(run_dir)
    inventory = local_tool_inventory()
    plan_rows: list[dict] = []
    safe_rows: list[dict] = []
    approval_rows: list[dict] = []
    command_rows: list[dict] = []

    for finding in findings:
        product_id = str(finding.get("product_id") or "")
        family = str(finding.get("family") or "")
        rule = deepening_rule(product_id, family)
        score = int(finding.get("score") or 0)
        priority = priority_from_score(score)
        templates = finding.get("template_matches") or {}
        review_templates = templates.get("review_readonly") or []
        approval_templates = templates.get("approval_required") or []
        unknown_templates = templates.get("review_unknown") or []
        tools = list(dict.fromkeys(rule.get("tool_preference") or []))
        base_url = str(finding.get("base_url") or "")
        host = str(finding.get("host") or host_of(base_url))
        safe_checks = rule.get("safe_checks") or []
        approval_checks = rule.get("approval_checks") or []
        previews = command_previews(finding, review_templates, inventory)
        row = {
            "checked_at": now_iso(),
            "priority": priority,
            "score": score,
            "confidence": finding.get("confidence") or "",
            "host": host,
            "base_url": base_url,
            "product_id": product_id,
            "product": finding.get("product") or product_id,
            "family": family,
            "branch": finding.get("branch") or "",
            "runner_followup": rule.get("runner_followup") or "review_only",
            "tool_preference": tools,
            "safe_checks": safe_checks,
            "review_templates": template_names(review_templates, 10),
            "unknown_templates": template_names(unknown_templates, 6),
            "approval_required_actions": approval_checks,
            "approval_templates": template_names(approval_templates, 10),
            "command_previews": previews,
            "default_action": "queue_only_no_auto_payload",
            "auto_run": False,
            "notes": finding.get("notes") or "Fingerprint-driven deepening plan. Manual verification required.",
        }
        plan_rows.append(row)
        safe_rows.append({
            "priority": priority,
            "score": score,
            "host": host,
            "base_url": base_url,
            "product": row["product"],
            "family": family,
            "runner_followup": row["runner_followup"],
            "tool_preference": tools,
            "safe_checks": safe_checks,
            "review_templates": row["review_templates"],
            "default_action": row["default_action"],
        })
        if approval_checks or approval_templates:
            approval_rows.append({
                "priority": priority,
                "score": score,
                "host": host,
                "base_url": base_url,
                "product": row["product"],
                "family": family,
                "approval_required_actions": approval_checks,
                "approval_templates": row["approval_templates"],
                "reason": "Product-specific active validation may involve exploit payloads, credentials, sensitive file/data access, or state changes.",
                "safe_alternative": "; ".join(safe_checks[:3]),
            })
        for preview in previews:
            command_rows.append({
                "priority": priority,
                "host": host,
                "base_url": base_url,
                "product": row["product"],
                "tool": "nuclei",
                "command_preview": preview,
                "execution_policy": "manual_single_target_only; review template before running; do not run approval_required templates",
            })

    plan_rows.sort(key=lambda item: (item["priority"], -int(item.get("score") or 0), item["host"], item["product_id"]))
    safe_rows.sort(key=lambda item: (item["priority"], -int(item.get("score") or 0), item["host"], item["product"]))
    approval_rows.sort(key=lambda item: (item["priority"], -int(item.get("score") or 0), item["host"], item["product"]))
    command_rows.sort(key=lambda item: (item["priority"], item["host"], item["product"]))
    return plan_rows, safe_rows, approval_rows, command_rows, inventory


def write_markdown(run_dir: Path, plan_rows: list[dict], safe_rows: list[dict], approval_rows: list[dict], command_rows: list[dict], inventory: dict) -> Path:
    reports = run_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    counts = defaultdict(int)
    family_counts = defaultdict(int)
    for row in plan_rows:
        counts[row["priority"]] += 1
        family_counts[row["family"]] += 1

    lines = [
        "# Fingerprint Deepening Plan",
        "",
        f"- Generated: {now_iso()}",
        f"- Fingerprint branches: {len(plan_rows)}",
        f"- Approval-gated branches: {len(approval_rows)}",
        f"- Manual command previews: {len(command_rows)}",
        "- Default policy: `queue_only_no_auto_payload`",
        "",
        "## Priority Counts",
        "",
        f"- P0: {counts['P0']}",
        f"- P1: {counts['P1']}",
        f"- P2: {counts['P2']}",
        f"- P3: {counts['P3']}",
        "",
        "## Tool Inventory",
        "",
        "| Tool | Installed | Version | Path |",
        "| --- | --- | --- | --- |",
    ]
    for name, item in sorted((inventory.get("tools") or {}).items()):
        if item.get("installed"):
            lines.append(f"| {name} | yes | {item.get('version', '')} | `{item.get('path', '')}` |")
    lines.extend([
        "",
        "## Shiro Key Wordlists",
        "",
        "| Path | Exists | Lines |",
        "| --- | --- | ---: |",
    ])
    for item in inventory.get("shiro_key_wordlists", []):
        lines.append(f"| `{item['path']}` | {item['exists']} | {item['nonempty_lines']} |")

    lines.extend([
        "",
        "## Deepening Queue",
        "",
        "| Priority | Score | Host | Product | Follow-up | Tools | Safe Checks |",
        "| --- | ---: | --- | --- | --- | --- | --- |",
    ])
    for row in safe_rows[:200]:
        lines.append(
            f"| {row['priority']} | {row['score']} | `{row['host']}` | {row['product']} | `{row['runner_followup']}` | "
            f"{csv_join(row['tool_preference'])[:120]} | {csv_join(row['safe_checks'])[:260]} |"
        )

    lines.extend([
        "",
        "## Approval Queue",
        "",
        "| Priority | Host | Product | Approval Actions | Safe Alternative |",
        "| --- | --- | --- | --- | --- |",
    ])
    for row in approval_rows[:200]:
        lines.append(
            f"| {row['priority']} | `{row['host']}` | {row['product']} | "
            f"{csv_join(row['approval_required_actions'])[:240]} | {row['safe_alternative'][:240]} |"
        )

    lines.extend([
        "",
        "## External Tool Import Candidates",
        "",
        "| Tool | Status | Recommended Use |",
        "| --- | --- | --- |",
    ])
    for item in inventory.get("external_import_candidates", []):
        lines.append(f"| {item['name']} | {item['status']} | {item['recommended']} |")

    lines.extend([
        "",
        "## Boundary",
        "",
        "- This file is a plan, not execution.",
        "- Review templates before running any command preview.",
        "- Do not run approval-required templates automatically.",
        "- Newly downloaded or backdoor-capable active tools require operator approval and tool review before import.",
    ])

    out = reports / "fingerprint_deepening.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Build offline post-fingerprint deepening queues")
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()

    plan_rows, safe_rows, approval_rows, command_rows, inventory = build_plan(args.run_dir)
    write_jsonl(args.run_dir / "fingerprint_deepening_plan.jsonl", plan_rows)
    write_csv(args.run_dir / "fingerprint_deepening_safe_queue.csv", safe_rows, [
        "priority",
        "score",
        "host",
        "base_url",
        "product",
        "family",
        "runner_followup",
        "tool_preference",
        "safe_checks",
        "review_templates",
        "default_action",
    ])
    write_csv(args.run_dir / "fingerprint_deepening_approval_queue.csv", approval_rows, [
        "priority",
        "score",
        "host",
        "base_url",
        "product",
        "family",
        "approval_required_actions",
        "approval_templates",
        "reason",
        "safe_alternative",
    ])
    write_csv(args.run_dir / "fingerprint_tool_command_queue.csv", command_rows, [
        "priority",
        "host",
        "base_url",
        "product",
        "tool",
        "command_preview",
        "execution_policy",
    ])
    write_json(args.run_dir / "fingerprint_tool_matrix.json", inventory)
    report = write_markdown(args.run_dir, plan_rows, safe_rows, approval_rows, command_rows, inventory)
    summary = {
        "created_at": now_iso(),
        "plan_count": len(plan_rows),
        "safe_queue_count": len(safe_rows),
        "approval_queue_count": len(approval_rows),
        "command_preview_count": len(command_rows),
        "report": str(report),
        "default_policy": "queue_only_no_auto_payload",
    }
    write_json(args.run_dir / "fingerprint_deepening_manifest.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
