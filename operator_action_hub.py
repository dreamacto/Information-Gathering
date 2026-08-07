#!/usr/bin/env python3
"""Build a prominent operator action hub from a run directory.

This module is intentionally offline. It does not attempt login, credentials, or
API requests. It reduces noisy scan artifacts into a small set of files the
operator can start from after each run.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


HUB_DIR_NAME = "00_重要_人工复核入口"
MINIAPP_BURP_DIR_NAME = "07_小程序Burp导入结果"

BUSINESS_KEYWORDS = {
    "user": "用户/账号",
    "users": "用户/账号",
    "person": "人员",
    "people": "人员",
    "patient": "患者/病人",
    "doctor": "医生",
    "hospital": "医院/机构",
    "medical": "医疗机构",
    "institution": "机构",
    "org": "组织机构",
    "dept": "部门",
    "role": "角色权限",
    "permission": "权限",
    "menu": "菜单权限",
    "list": "列表查询",
    "page": "分页查询",
    "query": "查询",
    "search": "搜索",
    "record": "记录",
    "records": "记录",
    "detail": "详情",
    "info": "详情",
    "idcard": "身份证字段",
    "phone": "手机号字段",
    "mobile": "手机号字段",
    "realname": "姓名字段",
    "身份证": "身份证字段",
    "手机号": "手机号字段",
    "姓名": "姓名字段",
    "患者": "患者/病人",
    "病人": "患者/病人",
    "机构": "机构",
    "人员": "人员",
    "监督": "监督业务",
    "检查": "检查记录",
}

RISKY_API_KEYWORDS = (
    "upload",
    "import",
    "export",
    "download",
    "delete",
    "remove",
    "drop",
    "update",
    "modify",
    "edit",
    "save",
    "create",
    "add",
    "submit",
    "approve",
    "audit",
    "send",
    "sms",
    "mail",
    "reset",
    "password",
    "passwd",
    "logout",
    "file",
    "attachment",
)

HIGH_VALUE_REASON_LABELS = {
    "authenticated_json_sensitive_schema": "认证后 JSON 出现敏感字段名",
    "authenticated_boundary_opened_json_api": "认证后边界打开",
    "openapi_json_with_paths": "OpenAPI/Swagger 有真实 paths",
    "high_priority_endpoint": "高优先级业务接口",
    "js_sensitive_keyword": "JS 中出现敏感关键字",
    "source_map_reference": "source map 线索",
    "api_endpoint_json_confirmed": "API 返回 JSON 结构",
}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict:
    if not path.exists() or not path.read_text(encoding="utf-8", errors="ignore").strip():
        return {}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def origin_of(url: str) -> str:
    try:
        parsed = urlparse(url)
    except Exception:
        return url.rstrip("/")
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return url.rstrip("/")


def csv_join(values) -> str:
    if values is None:
        return ""
    if isinstance(values, (list, tuple, set)):
        return ";".join(str(v) for v in values if v not in (None, ""))
    return str(values)


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_join(row.get(key, "")) for key in fieldnames})


def write_md_table(path: Path, title: str, fieldnames: list[str], rows: list[dict], notes: list[str] | None = None) -> None:
    lines = [
        f"# {title}",
        "",
        f"- Generated: {now_iso()}",
        f"- Items: {len(rows)}",
        "",
    ]
    if notes:
        lines.extend(notes)
        lines.append("")
    if rows:
        lines.append("| " + " | ".join(fieldnames) + " |")
        lines.append("| " + " | ".join("---" for _ in fieldnames) + " |")
        for row in rows[:120]:
            values = [csv_join(row.get(key, "")).replace("|", "/")[:180] for key in fieldnames]
            lines.append("| " + " | ".join(values) + " |")
    else:
        lines.append("No items.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def business_api_score(row: dict) -> tuple[int, list[str], str]:
    url = str(row.get("url") or row.get("base_url") or "")
    lower = url.lower()
    score = int(row.get("priority_score") or row.get("source_priority_score") or 0)
    reasons: list[str] = []
    for keyword, label in BUSINESS_KEYWORDS.items():
        if keyword.lower() in lower:
            score += 3
            reasons.append(label)
    tags = row.get("tags") or row.get("source_tags") or []
    if "data_query" in tags:
        score += 4
        reasons.append("数据查询")
    if "admin_or_portal" in tags:
        score += 3
        reasons.append("后台/管理")
    if "openapi_or_docs" in tags:
        score += 3
        reasons.append("接口文档")
    if any(token in lower for token in RISKY_API_KEYWORDS):
        return score, sorted(set(reasons)), "skip_risky_keyword"
    if not reasons and score < 5:
        return score, [], "low_business_signal"
    return score, sorted(set(reasons)), ""


def build_login_rows(run_dir: Path) -> list[dict]:
    data = read_json(run_dir / "manual_auth_queue.json")
    rows: list[dict] = []
    for item in data.get("items", []) if isinstance(data.get("items"), list) else []:
        if not isinstance(item, dict):
            continue
        rows.append({
            "priority": "P1" if item.get("scope_state") == "in_current_scope" else "P2",
            "base_url": item.get("base_url"),
            "host": item.get("host"),
            "scope_state": item.get("scope_state"),
            "registration_candidate": item.get("registration_candidate"),
            "reasons": item.get("reasons", []),
            "evidence_urls": item.get("evidence_urls", [])[:5],
            "operator_action": item.get("manual_action") or "Open in browser, login if authorized, then fill auth_sessions.local.json.",
        })
    return rows


def build_weak_credential_rows(run_dir: Path) -> list[dict]:
    rows: dict[str, dict] = {}

    def add(base_url: str, reason: str, evidence: str = "") -> None:
        if not base_url:
            return
        key = origin_of(base_url)
        row = rows.setdefault(key, {
            "priority": "P2",
            "base_url": key,
            "host": host_of(key),
            "reason": [],
            "evidence": [],
            "default_attempt_policy": "manual_gate_only; max_3_common_pairs_after_operator_confirms_scope_and_lockout_risk",
            "do_not_auto_run": "true",
        })
        row["reason"].append(reason)
        if evidence:
            row["evidence"].append(evidence)

    auth_queue = read_json(run_dir / "manual_auth_queue.json")
    for item in auth_queue.get("items", []) if isinstance(auth_queue.get("items"), list) else []:
        add(str(item.get("base_url") or ""), "login_or_auth_surface", csv_join(item.get("evidence_urls", [])[:2]))

    for row in read_jsonl(run_dir / "fingerprints.jsonl"):
        cats = set(row.get("categories") or [])
        if cats.intersection({"login", "oa", "java", "api"}):
            add(str(row.get("url") or ""), "fingerprint_" + ",".join(sorted(cats)), str(row.get("title") or ""))

    product_queue = run_dir / "product_triage_queue.csv"
    if product_queue.exists():
        try:
            with product_queue.open("r", encoding="utf-8-sig", newline="") as handle:
                for row in csv.DictReader(handle):
                    product = " ".join(str(row.get(key) or "") for key in row.keys())
                    if any(token in product.lower() for token in ("oa", "jeecg", "ruoyi", "shiro", "admin", "login", "sso")):
                        add(str(row.get("url") or row.get("base_url") or ""), "product_login_default_credential_review", product[:160])
        except OSError:
            pass

    output = []
    for row in rows.values():
        row["reason"] = sorted(set(row["reason"]))
        row["evidence"] = sorted(set(row["evidence"]))[:5]
        output.append(row)
    output.sort(key=lambda item: (item["priority"], item["host"], item["base_url"]))
    return output


def build_business_api_rows(run_dir: Path) -> list[dict]:
    rows: dict[str, dict] = {}

    def add(url: str, source: str, finding: str, base_url: str = "", tags=None, extra=None) -> None:
        if not url:
            return
        row = dict(extra or {})
        row.update({"url": url, "base_url": base_url or row.get("base_url") or url, "tags": tags or row.get("tags") or []})
        score, reasons, skip_reason = business_api_score(row)
        if skip_reason:
            return
        key = url.rstrip("/")
        item = rows.setdefault(key, {
            "priority": "P1" if score >= 10 else "P2",
            "score": score,
            "host": host_of(url) or host_of(str(base_url)),
            "base_url": base_url or row.get("base_url") or "",
            "url": key,
            "source": [],
            "finding": [],
            "why_it_matters": [],
            "safe_manual_check": "Open/read schema only; if live review is needed use pageSize=1 and do not call write/export/download endpoints.",
            "submit_if": "Unauthenticated/authorized read returns real JSON schema, business fields, totals, or sensitive field names.",
            "reject_if": "Login page, empty docs, unified 200/error page, write/export/download only, or out-of-scope host.",
        })
        item["score"] = max(int(item["score"]), score)
        item["priority"] = "P1" if int(item["score"]) >= 10 else "P2"
        item["source"].append(source)
        item["finding"].append(finding)
        item["why_it_matters"].extend(reasons)

    for row in read_jsonl(run_dir / "api_candidates.jsonl"):
        add(str(row.get("url") or ""), "api_candidates", "business_api_candidate", str(row.get("base_url") or ""), row.get("tags"), row)

    for row in read_jsonl(run_dir / "impact_candidates.jsonl"):
        finding = str(row.get("finding") or "impact_candidate")
        url = str(row.get("url") or row.get("base_url") or "")
        reasons = HIGH_VALUE_REASON_LABELS.get(finding, finding)
        extra = dict(row)
        extra["priority_score"] = int(extra.get("priority_score") or 0) + 6
        add(url, "impact_candidates", reasons, str(row.get("base_url") or ""), row.get("tags"), extra)

    for row in read_jsonl(run_dir / "api_interesting.jsonl"):
        extra = dict(row)
        extra["priority_score"] = int(extra.get("source_priority_score") or 0) + 8
        add(str(row.get("url") or ""), "api_interesting", "confirmed_json_schema", str(row.get("base_url") or ""), row.get("source_tags"), extra)

    for row in read_jsonl(run_dir / "authenticated_impact_candidates.jsonl"):
        finding = str(row.get("finding") or "authenticated_impact")
        extra = dict(row)
        extra["priority_score"] = 14
        extra["tags"] = ["authenticated", "data_query"]
        add(str(row.get("url") or row.get("base_url") or ""), "authenticated_impact_candidates", HIGH_VALUE_REASON_LABELS.get(finding, finding), str(row.get("base_url") or ""), extra.get("tags"), extra)

    output = []
    for item in rows.values():
        item["source"] = sorted(set(item["source"]))
        item["finding"] = sorted(set(item["finding"]))
        item["why_it_matters"] = sorted(set(item["why_it_matters"]))
        output.append(item)
    output.sort(key=lambda item: (-int(item["score"]), item["host"], item["url"]))
    return output


def build_reportable_rows(run_dir: Path) -> list[dict]:
    priority = read_json(run_dir / "priority_targets.json")
    rows: list[dict] = []
    for idx, item in enumerate(priority.get("items", [])[:50] if isinstance(priority.get("items"), list) else [], 1):
        reasons = item.get("reasons", [])
        rows.append({
            "rank": idx,
            "score": item.get("score", 0),
            "host": item.get("host", ""),
            "url": item.get("url", ""),
            "reasons": reasons,
            "sources": item.get("sources", []),
            "manual_check": "Confirm content differs from random 404/unified page; screenshot minimal proof with sensitive values redacted.",
        })
    return rows


def build_candidate_confidence_rows(run_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for row in read_jsonl(run_dir / "candidate_confidence.jsonl"):
        rows.append({
            "priority": row.get("priority") or "P3",
            "score": row.get("score") or 0,
            "family": row.get("family") or "",
            "host": row.get("host") or host_of(str(row.get("target") or "")),
            "target": row.get("target") or "",
            "param": row.get("param") or "",
            "reasons": row.get("reasons") or [],
            "sources": row.get("sources") or [],
            "manual_next_step": row.get("manual_next_step") or "",
            "claim_boundary": row.get("claim_boundary") or "Candidate only; manual verification required.",
        })
    rows.sort(key=lambda item: (str(item.get("priority") or "P3"), -int(item.get("score") or 0), str(item.get("host") or "")))
    return rows


def build_dossier_index_rows(run_dir: Path) -> list[dict]:
    manifest = read_json(run_dir / "target_dossier_manifest.json")
    output: list[dict] = []
    for item in manifest.get("items", []) if isinstance(manifest.get("items"), list) else []:
        if not isinstance(item, dict):
            continue
        output.append({
            "host": item.get("host") or "",
            "candidate_count": item.get("candidate_count") or 0,
            "p0": item.get("p0") or 0,
            "p1": item.get("p1") or 0,
            "p2": item.get("p2") or 0,
            "p3": item.get("p3") or 0,
            "file": item.get("file") or "",
        })
    output.sort(key=lambda item: (-int(item.get("p0") or 0), -int(item.get("p1") or 0), -int(item.get("candidate_count") or 0), str(item.get("host") or "")))
    return output


def build_product_vuln_rows(run_dir: Path) -> list[dict]:
    rows = []
    for row in read_jsonl(run_dir / "product_vuln_candidates.jsonl"):
        rows.append({
            "priority": row.get("confidence") or "review",
            "score": row.get("score") or 0,
            "host": row.get("host") or host_of(str(row.get("base_url") or "")),
            "base_url": row.get("base_url") or "",
            "product": row.get("product") or row.get("product_id") or "",
            "candidate_type": row.get("candidate_type") or "",
            "teacher_focus": row.get("teacher_focus") or "",
            "safe_review": row.get("safe_review") or "",
            "approval_gate": row.get("approval_gate") or "",
            "evidence_to_collect": row.get("evidence_to_collect") or "",
            "recommended_review": row.get("recommended_review") or "",
            "do_not_do": row.get("do_not_do") or "",
            "default_action": row.get("default_action") or "queue_only",
        })
    rows.sort(key=lambda item: (-(int(item.get("score") or 0)), str(item.get("candidate_type") or ""), str(item.get("host") or "")))
    return rows


def build_fingerprint_deepening_rows(run_dir: Path) -> list[dict]:
    rows = []
    for row in read_jsonl(run_dir / "fingerprint_deepening_plan.jsonl"):
        rows.append({
            "priority": row.get("priority") or "P3",
            "score": row.get("score") or 0,
            "host": row.get("host") or host_of(str(row.get("base_url") or "")),
            "base_url": row.get("base_url") or "",
            "product": row.get("product") or row.get("product_id") or "",
            "family": row.get("family") or "",
            "runner_followup": row.get("runner_followup") or "",
            "tool_preference": row.get("tool_preference") or [],
            "safe_checks": row.get("safe_checks") or [],
            "review_templates": row.get("review_templates") or [],
            "approval_required_actions": row.get("approval_required_actions") or [],
            "approval_templates": row.get("approval_templates") or [],
            "default_action": row.get("default_action") or "queue_only_no_auto_payload",
        })
    rows.sort(key=lambda item: (str(item.get("priority") or "P3"), -int(item.get("score") or 0), str(item.get("host") or "")))
    return rows


def build_xss_rows(run_dir: Path) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for row in read_jsonl(run_dir / "xss_reflection_checks.jsonl"):
        if not row.get("marker_reflected"):
            continue
        confidence = str(row.get("confidence") or "low")
        item = {
            "priority": "P1" if confidence == "medium" else "P2",
            "confidence": confidence,
            "host": row.get("host") or host_of(str(row.get("url") or "")),
            "param": row.get("param") or "",
            "reflection_context": row.get("reflection_context") or "",
            "url": row.get("probe_url") or row.get("url") or "",
            "source": row.get("source") or "",
            "safe_manual_check": "Use Burp Repeater on this single URL; inspect response context and encoding.",
            "submit_if": "Marker reaches an executable context and a minimal single-candidate proof is allowed by rules.",
            "reject_if": "JSON/text-only echo, HTML-encoded output, login/unified error page, or out-of-scope host.",
        }
        key = (str(item["host"]), str(item["param"]), str(item["url"]))
        if key not in seen:
            seen.add(key)
            rows.append(item)

    for row in read_jsonl(run_dir / "xss_candidates.jsonl"):
        if row.get("default_action") != "manual_only" or int(row.get("score") or 0) < 8:
            continue
        item = {
            "priority": "P3",
            "confidence": "manual_only",
            "host": row.get("host") or host_of(str(row.get("url") or "")),
            "param": row.get("param") or "",
            "reflection_context": row.get("skip_reason") or "manual_only",
            "url": row.get("url") or "",
            "source": row.get("source") or "",
            "safe_manual_check": "Potential stored/write context. Review manually only if you own the record and rules allow this action.",
            "submit_if": "A harmless self-owned record proves stored/reflected execution without affecting others.",
            "reject_if": "Would write shared data, affect other users/admins, require callbacks, or need broad payload spraying.",
        }
        key = (str(item["host"]), str(item["param"]), str(item["url"]))
        if key not in seen:
            seen.add(key)
            rows.append(item)
    rows.sort(key=lambda item: (item["priority"], item["host"], item["param"], item["url"]))
    return rows


def count_named_jsonl(root: Path, filename: str) -> int:
    total = len(read_jsonl(root / filename))
    if root.exists():
        for path in root.glob(f"*/{filename}"):
            total += len(read_jsonl(path))
    return total


def write_manual_review_guides(hub: Path) -> list[str]:
    guides: dict[str, list[str]] = {
        "08_SQL注入手工确认.md": [
            "# SQL 注入手工确认",
            "",
            "先看本轮输出：",
            "",
            "- `sqli_high_probability.txt`：优先级最高。",
            "- `sqli_candidates.jsonl`：参数化 URL 原始候选。",
            "- `sqli_500_or_error_anomalies.txt`：弱线索，500 不等于漏洞。",
            "",
            "安全确认思路：",
            "",
            "- 只在授权目标、低频、单 URL 下复核。",
            "- 先比较正常参数变化带来的状态码、长度、字段名、页面提示差异。",
            "- 报告截图保留 URL、参数位置、差异摘要和系统时间。",
            "- 不导出表数据，不跑批量 SQLMap，不做延时/堆叠/写入类验证，除非演练规则明确批准。",
        ],
        "09_文件上传安全测试.md": [
            "# 文件上传安全测试",
            "",
            "安全确认思路：",
            "",
            "- 只上传你自己创建的无害文件，例如 `.txt`、普通图片或不含脚本的 HTML 文本。",
            "- 只验证自己上传的文件是否可访问、是否被改名、Content-Type 是否正确、是否能删除自己的文件。",
            "- 如果界面提供“删除我的文件”，可以删除自己刚上传的测试文件；看不到删除入口时不要猜接口删。",
            "- 截图要展示上传入口、文件类型限制、访问结果、删除结果或无法删除的状态。",
            "- 不上传 JSP/PHP/ASPX/JSPX/WAR、宏文件、木马、反弹连接、内存马或任何会执行的脚本。",
            "- 不修改、覆盖、删除别人的文件或业务数据。",
        ],
        "10_越权和接口泄露复核.md": [
            "# 越权和接口泄露复核",
            "",
            "先看本轮输出：",
            "",
            "- `02_业务API只读复核队列.md`：最贴近你现在擅长的接口泄露。",
            "- `authenticated_impact_candidates.jsonl`：登录态只读复核后的字段/数量线索。",
            "- `reports/screenshot_queue.md`：报告截图待办。",
            "",
            "安全确认思路：",
            "",
            "- 优先 GET/read-only 接口，只看字段名、数量、状态码、权限边界。",
            "- 对比未登录、低权限登录、自己账号登录下的返回差异。",
            "- 换参数时只换自己可证明拥有的数据编号；不要批量枚举 ID。",
            "- 截图前打码姓名、手机号、身份证、Cookie、Token、Authorization。",
            "- 不调用新增、删除、审批、导出、发短信、改密码、支付等写操作接口。",
        ],
        "11_Fastjson_Log4j_Struts2候选判断.md": [
            "# Fastjson / Log4j / Struts2 候选判断",
            "",
            "先看本轮输出：",
            "",
            "- `04B_产品漏洞候选队列.md`：产品漏洞候选总入口。",
            "- `product_vuln_candidates.jsonl`：机器可读候选。",
            "",
            "安全确认思路：",
            "",
            "- Fastjson：找 Java/API、JSON-heavy 接口、异常栈、依赖或版本线索。",
            "- Log4j：找 Java 产品版本、错误页、依赖泄露、供应商公告对应关系。",
            "- Struts2：找 `.action` 路由、Struts 错误页、框架头、页面源码线索。",
            "- 截图只证明产品/框架/版本/入口存在，不代表漏洞成立。",
            "- 不发送 JNDI、DNSLog、OGNL、反序列化、命令执行或回连 payload，除非单目标审批通过。",
        ],
        "12_Shiro候选判断.md": [
            "# Shiro 候选判断",
            "",
            "先看本轮输出：",
            "",
            "- `shiro_candidates.jsonl`：Shiro 安全筛选候选。",
            "- `shiro_manual_queue.csv`：值得人工单目标复核的入口。",
            "- `04B_产品漏洞候选队列.md`：Java/OA/ERP 背景下的 Shiro 候选。",
            "",
            "安全确认思路：",
            "",
            "- 先看登录页、rememberMe 行为、Java/OA 产品背景和 triage 置信度。",
            "- 截图只展示入口、Cookie 行为和候选理由。",
            "- ShiroAttack2 这类工具只适合审批后的单目标验证。",
            "- 不爆破 key，不发序列化 payload，不测命令执行或内存马。",
        ],
        "13_XSS候选手工确认.md": [
            "# XSS 候选手工确认",
            "",
            "先看本轮输出：",
            "",
            "- `xss_manual_review.md`：自动反射检查摘要。",
            "- `xss_reflection_candidates.txt`：反射出随机标记的参数。",
            "- `04C_XSS反射候选队列.md`：操作台聚合后的优先队列。",
            "",
            "安全确认思路：",
            "",
            "- 自动结果只说明随机标记被反射，不等于 XSS 成立。",
            "- 优先看 marker 是否落在 script、HTML 属性、标签附近；JSON/普通文本反射多数只是线索。",
            "- 只在单个授权候选上用 Burp Repeater 复核编码和上下文。",
            "- stored/blind/admin XSS、评论/昵称/工单/公告写入、外连回调、批量 payload 都不要默认自动跑。",
            "- 截图保留参数、响应上下文和系统时间；打码用户信息、Cookie、Token、Authorization。",
        ],
    }
    written = []
    for filename, lines in guides.items():
        path = hub / filename
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(str(path))
    return written


def build_operator_action_hub(run_dir: Path) -> dict:
    hub = run_dir / HUB_DIR_NAME
    hub.mkdir(parents=True, exist_ok=True)
    manual_guides = write_manual_review_guides(hub)

    login_rows = build_login_rows(run_dir)
    weak_rows = build_weak_credential_rows(run_dir)
    api_rows = build_business_api_rows(run_dir)
    reportable_rows = build_reportable_rows(run_dir)
    confidence_rows = build_candidate_confidence_rows(run_dir)
    dossier_rows = build_dossier_index_rows(run_dir)
    product_vuln_rows = build_product_vuln_rows(run_dir)
    fingerprint_deepening_rows = build_fingerprint_deepening_rows(run_dir)
    xss_rows = build_xss_rows(run_dir)

    write_csv(hub / "00_P0-P3候选总表.csv", [
        "priority", "score", "family", "host", "target", "param", "reasons", "sources", "manual_next_step", "claim_boundary",
    ], confidence_rows)
    write_md_table(hub / "00_P0-P3候选总表.md", "P0-P3 候选总表（自动线索，不是漏洞结论）", [
        "priority", "score", "family", "host", "target", "param", "reasons", "manual_next_step",
    ], confidence_rows, [
        "- P0/P1/P2/P3 只代表复核优先级；提交前必须人工复现、确认作用域和影响面。",
        "- 这张表来自 second-pass、SQLi、XSS、API、产品、指纹后深入分支、认证、弱口令等结果的离线合并。",
    ])

    write_csv(hub / "00B_目标画像索引.csv", [
        "host", "candidate_count", "p0", "p1", "p2", "p3", "file",
    ], dossier_rows)
    write_md_table(hub / "00B_目标画像索引.md", "目标画像索引", [
        "host", "candidate_count", "p0", "p1", "p2", "p3", "file",
    ], dossier_rows, [
        "- 每个画像文件把该 host 的指纹、API、二次复测、弱口令成功候选和最高优先级线索放在一起。",
        "- 原始画像目录：`target_dossiers/`。",
    ])

    write_csv(hub / "01_需要你登录拿Cookie.csv", [
        "priority", "base_url", "host", "scope_state", "registration_candidate", "reasons", "evidence_urls", "operator_action",
    ], login_rows)
    write_md_table(hub / "01_需要你登录拿Cookie.md", "需要你登录拿 Cookie 的站点", [
        "priority", "base_url", "scope_state", "reasons", "operator_action",
    ], login_rows, [
        "- Fill cookies into `auth_sessions.local.json`; that local file must not be submitted.",
        "- Only login/register where the target is in scope and you have authorization.",
    ])

    write_csv(hub / "02_业务API只读复核队列.csv", [
        "priority", "score", "host", "base_url", "url", "source", "finding", "why_it_matters", "safe_manual_check", "submit_if", "reject_if",
    ], api_rows)
    write_md_table(hub / "02_业务API只读复核队列.md", "业务 API 只读复核队列", [
        "priority", "score", "host", "url", "why_it_matters", "submit_if", "reject_if",
    ], api_rows, [
        "- This queue is for read-only/schema review. Do not call write, export, download, delete, SMS, password, or approval endpoints.",
        "- Evidence should keep field names, totals, status, and screenshots with sensitive values redacted.",
    ])

    write_csv(hub / "03_弱口令人工确认队列_不自动跑.csv", [
        "priority", "base_url", "host", "reason", "evidence", "default_attempt_policy", "do_not_auto_run",
    ], weak_rows)
    write_md_table(hub / "03_弱口令人工确认队列_不自动跑.md", "弱口令人工确认队列（不自动跑）", [
        "priority", "base_url", "reason", "default_attempt_policy", "do_not_auto_run",
    ], weak_rows, [
        "- The project does not attempt weak credentials unless you explicitly add `--weak-credential-review`.",
        "- Explicit mode uses up to 5 product-aware common pairs per target and stops on CAPTCHA, lockout, rate-limit, or warning prompts.",
    ])

    write_csv(hub / "04_可报告候选_TOP.csv", [
        "rank", "score", "host", "url", "reasons", "sources", "manual_check",
    ], reportable_rows)
    write_md_table(hub / "04_可报告候选_TOP.md", "可报告候选 Top 队列", [
        "rank", "score", "host", "url", "reasons", "manual_check",
    ], reportable_rows, [
        "- High score is a review priority, not proof.",
        "- Submit only after minimal manual confirmation and evidence capture.",
    ])

    write_csv(hub / "04B_产品漏洞候选队列.csv", [
        "priority", "score", "host", "base_url", "product", "candidate_type", "teacher_focus", "safe_review", "evidence_to_collect", "recommended_review", "approval_gate", "do_not_do", "default_action",
    ], product_vuln_rows)
    write_md_table(hub / "04B_产品漏洞候选队列.md", "产品漏洞候选队列（不自动利用）", [
        "priority", "score", "host", "product", "candidate_type", "safe_review", "evidence_to_collect", "do_not_do",
    ], product_vuln_rows, [
        "- This queue covers Fastjson, Log4j, Struts2, Spring Boot, Nacos, ThinkPHP, Shiro, and common domestic OA/ERP products.",
        "- It is a review queue only. Active RCE, deserialization, upload, SQLMap, auth bypass, and callback validation require explicit approval.",
    ])

    write_csv(hub / "04D_指纹后深入分支.csv", [
        "priority", "score", "host", "base_url", "product", "family", "runner_followup", "tool_preference", "safe_checks", "review_templates", "approval_required_actions", "approval_templates", "default_action",
    ], fingerprint_deepening_rows)
    write_md_table(hub / "04D_指纹后深入分支.md", "指纹后深入分支（工具/模板/审批队列）", [
        "priority", "score", "host", "product", "runner_followup", "tool_preference", "safe_checks", "approval_required_actions",
    ], fingerprint_deepening_rows, [
        "- This queue maps detected products/frameworks to the safest next checks and local tool/template candidates.",
        "- It is offline planning only. Command previews and approval queues are not executed automatically.",
        "- Full details: `fingerprint_deepening_plan.jsonl`, `fingerprint_tool_command_queue.csv`, `fingerprint_deepening_approval_queue.csv`, and `reports/fingerprint_deepening.md`.",
    ])

    write_csv(hub / "04C_XSS反射候选队列.csv", [
        "priority", "confidence", "host", "param", "reflection_context", "url", "source", "safe_manual_check", "submit_if", "reject_if",
    ], xss_rows)
    write_md_table(hub / "04C_XSS反射候选队列.md", "XSS 反射候选队列（低风险自动筛选）", [
        "priority", "confidence", "host", "param", "reflection_context", "url", "submit_if", "reject_if",
    ], xss_rows, [
        "- The automatic stage only checks whether an inert random marker is reflected in GET responses.",
        "- Reflected marker is a lead, not a confirmed executable XSS proof.",
        "- Stored/blind/admin XSS and write locations remain manual-only.",
    ])

    commands = [
        "# 05 认证态复核命令",
        "",
        "1. Open `01_需要你登录拿Cookie.md`, login manually where authorized, then fill `auth_sessions.local.json` in the project root.",
        "2. Resume authenticated read-only review:",
        "",
        "```powershell",
        "<python.exe> .\\gov_exercise_runner.py --targets <same-targets-file> --resume-run-dir " + str(run_dir) + " --auth-review --auth-cookie-file .\\auth_sessions.local.json --delay 3",
        "```",
        "",
        "The review keeps cookies in memory and writes only metadata/schema results.",
    ]
    (hub / "05_认证态复核命令.md").write_text("\n".join(commands) + "\n", encoding="utf-8")

    weak_commands = [
        "# 06 弱口令显式复核命令",
        "",
        "This stage is not part of the default run. Use it only when the exercise rules allow weak-credential checks for the selected targets.",
        "By default it only records attempt metadata. Add `--weak-credential-auto-auth-review` when you want successful login responses to feed the bounded authenticated read-only review before manual Cookie handoff.",
        "",
        "Weak-credential review only:",
        "",
        "```powershell",
        "<python.exe> .\\gov_exercise_runner.py --targets <same-targets-file> --resume-run-dir " + str(run_dir) + " --weak-credential-review --weak-credential-max-pairs 5 --weak-credential-max-targets 10 --delay 3",
        "```",
        "",
        "Weak-credential review + transient auto-auth read-only review:",
        "",
        "```powershell",
        "<python.exe> .\\gov_exercise_runner.py --targets <same-targets-file> --resume-run-dir " + str(run_dir) + " --weak-credential-review --weak-credential-auto-auth-review --weak-credential-max-pairs 5 --weak-credential-max-targets 10 --auth-max-js 20 --auth-max-endpoints 30 --delay 3",
        "```",
        "",
        "Outputs:",
        "",
        "- `weak_credential_attempts.jsonl`: attempt metadata only; no raw passwords, cookies, tokens, or response bodies.",
        "- `weak_credential_successes.jsonl`: success candidates with username, password profile, and transient-session flags, still no cookie/token values.",
        "- `weak_credential_skips.jsonl`: CAPTCHA, lockout, unsupported form, and boundary skips.",
        "- `weak_auto_authenticated_review_manifest.json`: created only when auto-auth review runs; contains counts/limits only.",
        "- `authenticated_api_results.jsonl` / `authenticated_impact_candidates.jsonl`: schema/status metadata from the transient authenticated read-only review.",
        "- `weak_credential_success_sessions.local.template.json`: local-only template for manually pasting a browser session if needed.",
    ]
    (hub / "06_弱口令显式复核命令.md").write_text("\n".join(weak_commands) + "\n", encoding="utf-8")

    miniapp_commands = [
        "# 07 小程序人工搜索与 Burp 导入",
        "",
        "The old mini-program web clue discovery is not part of the one-click flow. Use this branch when you search mini-programs manually by organization name and capture backend URLs with Burp.",
        "",
        "Generate keyword/search pack:",
        "",
        "```powershell",
        "<python.exe> .\\gov_exercise_runner.py --targets <same-targets-file> --resume-run-dir " + str(run_dir) + " --miniapp-search-pack",
        "```",
        "",
        "Import a Burp export after you capture the mini-program traffic:",
        "",
        "```powershell",
        "<python.exe> .\\gov_exercise_runner.py --targets <same-targets-file> --resume-run-dir " + str(run_dir) + " --miniapp-burp-export <burp_http_history.xml> --api-confirm --delay 3",
        "```",
        "",
        "If you already have unpacked mini-program source:",
        "",
        "```powershell",
        "<python.exe> .\\gov_exercise_runner.py --targets <same-targets-file> --resume-run-dir " + str(run_dir) + " --miniapp-source-dir <unpacked_wxapp_source_dir> --api-confirm --delay 3",
        "```",
        "",
        "Outputs:",
        "",
        "- `07_小程序Burp导入结果/<Burp文件名>_导入结果/`：每个小程序单独一个目录，报告、范围内候选、待确认域名和日志都在这里。",
        "- `miniapp_source_api_candidates.jsonl` / `miniapp_source_new_assets_pending.txt`",
    ]
    (hub / "07_小程序人工搜索与Burp导入.md").write_text("\n".join(miniapp_commands) + "\n", encoding="utf-8")

    readme = [
        "# 先看这里：本轮人工复核入口",
        "",
        f"- Generated: {now_iso()}",
        f"- Run dir: `{run_dir}`",
        "",
        "## 文件怎么用",
        "",
        "1. `00_P0-P3候选总表.md`：最优先看。这里合并二次复测、SQLi、XSS、API、产品、弱口令等候选。",
        "2. `00B_目标画像索引.md`：按 host 查看画像，减少你在原始 JSONL 里来回翻。",
        "3. `01_需要你登录拿Cookie.md`：列出需要你人工登录/注册/拿 cookie 的站点。",
        "4. `02_业务API只读复核队列.md`：登录或未登录条件下最值得看的业务 API，只做字段/数量/结构复核。",
        "5. `03_弱口令人工确认队列_不自动跑.md`：登录页和产品入口清单。弱口令尝试仍是人工门控，不会默认自动跑。",
        "6. `04_可报告候选_TOP.md`：从所有扫描结果里压缩出的可报告候选。",
        "7. `04B_产品漏洞候选队列.md`：Fastjson、Log4j、Struts2、Spring Boot、Nacos、ThinkPHP、OA/ERP 等产品漏洞候选，不自动利用。",
        "8. `04D_指纹后深入分支.md`：识别到产品/框架后，下一步安全复核、工具、模板和审批门槛。",
        "9. `04C_XSS反射候选队列.md`：GET 随机标记反射出来的 XSS 线索；不是确认漏洞。",
        "10. `05_认证态复核命令.md`：你填好本地 cookie 后的恢复命令。",
        "11. `06_弱口令显式复核命令.md`：如果规则允许，显式启动最多 5 组动态弱口令复核；可加参数在成功后先自动跑认证态只读复核。",
        "12. `07_小程序人工搜索与Burp导入.md`：按单位名手工找小程序，再导入 Burp 抓到的后端 URL。",
        "13. `08-13_*手工确认/候选判断.md`：SQLi、上传、越权、Java 产品漏洞、Shiro、XSS 的新手复核小抄。",
        "",
        "## 当前数量",
        "",
        f"- P0-P3 候选总数: {len(confidence_rows)}",
        f"- 目标画像: {len(dossier_rows)}",
        f"- 需要登录拿 Cookie: {len(login_rows)}",
        f"- 业务 API 只读复核: {len(api_rows)}",
        f"- 弱口令人工确认入口: {len(weak_rows)}",
        f"- 可报告候选 Top: {len(reportable_rows)}",
        f"- 产品漏洞候选: {len(product_vuln_rows)}",
        f"- 指纹后深入分支: {len(fingerprint_deepening_rows)}",
        f"- XSS 反射候选: {len(xss_rows)}",
        f"- 弱口令成功候选: {len(read_jsonl(run_dir / 'weak_credential_successes.jsonl'))}",
        f"- 小程序源码 API 候选: {len(read_jsonl(run_dir / 'miniapp_source_api_candidates.jsonl'))}",
        f"- Burp 小程序 API 候选: {count_named_jsonl(run_dir / MINIAPP_BURP_DIR_NAME, 'burp_miniapp_api_candidates.jsonl')}",
        "",
        "## 边界",
        "",
        "- 默认不自动尝试密码、不爆破、不注册账号、不绕过认证。",
        "- 弱口令复核只有显式加 `--weak-credential-review` 才会运行；自动认证态只读复核还需要额外加 `--weak-credential-auto-auth-review`。",
        "- 自动认证态复核只使用弱口令成功当次响应里的 Cookie/JWT；不抓浏览器 token，不保存 token 或 cookie。",
        "- 不保存敏感字段值、响应正文、下载文件、token 或 cookie。",
        "- 业务 API 复核只保存状态、长度、hash、字段名、数量等最小证据。",
    ]
    (hub / "README_先看这里.md").write_text("\n".join(readme) + "\n", encoding="utf-8")

    return {
        "directory": str(hub),
        "candidate_confidence_queue": len(confidence_rows),
        "target_dossiers": len(dossier_rows),
        "login_cookie_queue": len(login_rows),
        "business_api_review_queue": len(api_rows),
        "weak_credential_manual_queue": len(weak_rows),
        "reportable_candidates": len(reportable_rows),
        "product_vuln_candidates": len(product_vuln_rows),
        "fingerprint_deepening_queue": len(fingerprint_deepening_rows),
        "xss_review_queue": len(xss_rows),
        "manual_guides": len(manual_guides),
        "miniapp_source_api_candidates": len(read_jsonl(run_dir / "miniapp_source_api_candidates.jsonl")),
        "burp_miniapp_api_candidates": count_named_jsonl(run_dir / MINIAPP_BURP_DIR_NAME, "burp_miniapp_api_candidates.jsonl"),
        "readme": str(hub / "README_先看这里.md"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build prominent operator action hub for a run directory")
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_operator_action_hub(args.run_dir), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
