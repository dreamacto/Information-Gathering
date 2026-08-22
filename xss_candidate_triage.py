#!/usr/bin/env python3
"""Safe reflected-XSS candidate triage for authorized run directories.

The default mode only builds a queue from URLs already discovered by the main
workflow.  With --reflect-check it sends one GET request per selected parameter
using a random inert marker, then records metadata about whether that marker was
reflected.  It does not use <script>, event handlers, external callbacks, stored
forms, POST bodies, cookies, tokens, or response-body persistence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from api_discovery import FetchResult, append_jsonl, fetch, find_tool, now_iso


MINIAPP_BURP_DIR_NAME = "07_小程序Burp导入结果"
SOURCE_FILES = (
    "api_candidates.jsonl",
    "api_confirmed.jsonl",
    "api_interesting.jsonl",
    "authenticated_impact_candidates.jsonl",
    "miniapp_source_api_candidates.jsonl",
)

STATIC_EXT_RE = re.compile(
    r"\.(?:png|jpe?g|gif|ico|css|woff2?|ttf|map|mp4|pdf|docx?|xlsx?|zip|rar|7z)(?:[?#].*)?$",
    re.I,
)
STATE_CHANGING_PATH_RE = re.compile(
    r"(/|\b)(upload|import|export|download|delete|remove|drop|update|modify|edit|save|create|add|submit|"
    r"approve|audit|pay|payment|refund|send|sms|mail|reset|password|passwd|logout|file|attachment)(/|\b|[A-Z_-])",
    re.I,
)
STORED_CONTEXT_RE = re.compile(
    r"(comment|feedback|message|notice|article|content|remark|profile|nickname|avatar|address|reply|post|留言|评论|反馈|昵称)",
    re.I,
)
LOW_VALUE_PARAM_RE = re.compile(
    r"^(_|csrf|_csrf|token|access_token|authorization|auth|sign|signature|nonce|timestamp|ts|time|random|sid|session|cookie)$",
    re.I,
)
SENSITIVE_PARAM_RE = re.compile(r"(token|authorization|cookie|session|secret|password|passwd|pwd|sign|openid|unionid)", re.I)
XSS_PARAM_PRIORITY_RE = re.compile(
    r"^(q|s|kw|keyword|key|query|search|name|title|text|content|html|body|msg|message|desc|description|"
    r"callback|jsonp|redirect|url|link|next|return|returnurl|path|page|remark|nickname)$",
    re.I,
)
SEARCH_PATH_RE = re.compile(r"(/|\b)(search|query|list|page|find|lookup|suggest|select|dict|tag)(/|\b|[A-Z_-])", re.I)
ERROR_OR_BLOCK_PAGE_RE = re.compile(
    r"(404|not found|forbidden|access denied|request rejected|blocked|waf|captcha|验证码|访问出错|访问禁止|"
    r"页面不存在|系统繁忙|服务器错误|请稍后再试)",
    re.I,
)
PARAM_PRIORITY = {
    "q": 0,
    "s": 0,
    "kw": 0,
    "keyword": 0,
    "key": 0,
    "query": 0,
    "search": 0,
    "name": 1,
    "title": 1,
    "text": 1,
    "html": 1,
    "body": 1,
    "msg": 1,
    "message": 1,
    "desc": 1,
    "description": 1,
    "callback": 1,
    "jsonp": 1,
    "content": 2,
    "remark": 2,
    "nickname": 2,
    "redirect": 3,
    "url": 3,
    "link": 3,
    "next": 3,
    "return": 3,
    "returnurl": 3,
    "path": 3,
    "page": 4,
}


@dataclass(frozen=True)
class XssCandidate:
    url: str
    param: str
    base_url: str = ""
    source: str = ""
    method: str = "GET"
    source_priority_score: int = 0
    score: int = 0
    reasons: tuple[str, ...] = ()
    default_action: str = "auto_reflection_check"
    skip_reason: str = ""


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def endpoint_key(url: str, param: str) -> str:
    # 键归一化：参数值不影响反射行为，同端点同参数名只算一个候选
    # （20260822 复盘：BrandCarModel.html?source=ID3/ID4X/… 生成了 8 条实质相同的候选）
    parsed = urlparse(url.rstrip())
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    normalized_query = "&".join(sorted(f"{safe_param_name(name)}=" for name, _v in pairs))
    normalized = urlunparse(parsed._replace(query=normalized_query))
    return hashlib.sha256(f"{normalized}#{param}".encode("utf-8", errors="ignore")).hexdigest()


def safe_param_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-\[\]]+", "_", name)[:80] or "param"


def redacted_url(url: str, marker_param: str = "", marker_value: str = "") -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url[:180]
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = "&".join(
        f"{safe_param_name(name)}={marker_value if name == marker_param and marker_value else '<redacted>'}"
        for name, _value in pairs
    )
    return urlunparse(parsed._replace(query=query))


def is_http_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def is_parameterized_http_url(url: str) -> bool:
    parsed = urlparse(url)
    return is_http_url(url) and bool(parsed.query) and not STATIC_EXT_RE.search(parsed.path or "")


def method_of(row: dict) -> str:
    for key in ("method", "http_method", "request_method"):
        value = str(row.get(key) or "").strip().upper()
        if value:
            return value
    return "GET"


def choose_params(url: str, max_params: int) -> list[str]:
    params = parse_qsl(urlparse(url).query, keep_blank_values=True)
    accepted: list[str] = []
    for name, value in params:
        if not name or LOW_VALUE_PARAM_RE.search(name):
            continue
        if SENSITIVE_PARAM_RE.search(name):
            continue
        if len(value) > 200:
            continue
        accepted.append(name)
    return sorted(set(accepted), key=lambda name: (PARAM_PRIORITY.get(name.lower(), 9), name.lower()))[:max_params]


def mutate_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = [(name, value if name == param else old_value) for name, old_value in pairs]
    return urlunparse(parsed._replace(query=urlencode(replaced, doseq=True)))


def classify_candidate(url: str, param: str, row: dict) -> tuple[int, list[str], str, str]:
    parsed = urlparse(url)
    lower_path = (parsed.path or "").lower()
    param_lower = param.lower()
    reasons: list[str] = []
    score = int(row.get("priority_score") or row.get("source_priority_score") or 0)
    default_action = "auto_reflection_check"
    skip_reason = ""

    if method_of(row) != "GET":
        default_action = "manual_only"
        skip_reason = "non_get_request"
    elif STATE_CHANGING_PATH_RE.search(lower_path):
        default_action = "manual_only"
        skip_reason = "state_changing_path"
    elif STORED_CONTEXT_RE.search(lower_path) or STORED_CONTEXT_RE.search(param_lower):
        default_action = "manual_only"
        skip_reason = "possible_stored_context"

    if XSS_PARAM_PRIORITY_RE.search(param_lower):
        score += 8
        reasons.append("xss_like_param_name")
    if SEARCH_PATH_RE.search(lower_path):
        score += 4
        reasons.append("search_or_query_path")
    if param_lower in {"callback", "jsonp"}:
        score += 5
        reasons.append("jsonp_callback_param")
    if any(token in lower_path for token in ("/api", "/gateway", "/service", "/rest")):
        score += 2
        reasons.append("api_endpoint")
    if default_action == "manual_only":
        reasons.append(skip_reason)

    if not reasons:
        reasons.append("parameterized_url")
    return score, sorted(set(reasons)), default_action, skip_reason


def source_rows(run_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for name in SOURCE_FILES:
        for row in read_jsonl(run_dir / name):
            if row.get("url"):
                rows.append({**row, "_source_file": name})

    katana_path = run_dir / "katana_urls.txt"
    if katana_path.exists():
        for line in katana_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.strip()
            if value:
                rows.append({"url": value, "_source_file": "katana_urls.txt"})

    targets_csv = run_dir / "targets.csv"
    if targets_csv.exists():
        with targets_csv.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            for row in csv.DictReader(handle):
                if row.get("url"):
                    rows.append({"url": row["url"], "_source_file": "targets.csv"})

    miniapp_root = run_dir / MINIAPP_BURP_DIR_NAME
    if miniapp_root.exists():
        for path in miniapp_root.glob("*/burp_miniapp_in_scope_api_candidates.jsonl"):
            for row in read_jsonl(path):
                if row.get("url"):
                    rows.append({**row, "_source_file": str(path.relative_to(run_dir))})
    return rows


def load_url_params(
    run_dir: Path,
    max_params_per_url: int,
    max_per_host: int,
    limit: int,
    force: bool,
) -> list[XssCandidate]:
    rows = sorted(
        source_rows(run_dir),
        key=lambda row: int(row.get("priority_score") or row.get("source_priority_score") or 0),
        reverse=True,
    )
    completed: set[str] = set()
    if not force:
        completed.update(str(row.get("source_key_sha256") or "") for row in read_jsonl(run_dir / "xss_candidates.jsonl"))
        completed.update(str(row.get("source_key_sha256") or "") for row in read_jsonl(run_dir / "xss_reflection_checks.jsonl"))

    accepted: list[XssCandidate] = []
    seen: set[str] = set()
    auto_per_host: dict[str, int] = defaultdict(int)
    for row in rows:
        url = str(row.get("url") or "").strip()
        if not is_parameterized_http_url(url):
            continue
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        for param in choose_params(url, max_params_per_url):
            key = endpoint_key(url, param)
            if key in seen or key in completed:
                continue
            score, reasons, default_action, skip_reason = classify_candidate(url, param, row)
            if default_action == "auto_reflection_check" and auto_per_host[host] >= max_per_host:
                default_action = "manual_only"
                skip_reason = "per_host_auto_budget_reached"
                reasons = sorted(set([*reasons, skip_reason]))
            seen.add(key)
            accepted.append(XssCandidate(
                url=url,
                param=param,
                base_url=str(row.get("base_url") or ""),
                source=str(row.get("_source_file") or row.get("family") or ""),
                method=method_of(row),
                source_priority_score=int(row.get("priority_score") or row.get("source_priority_score") or 0),
                score=score,
                reasons=tuple(reasons),
                default_action=default_action,
                skip_reason=skip_reason,
            ))
            if default_action == "auto_reflection_check":
                auto_per_host[host] += 1
            if limit and len(accepted) >= limit:
                return accepted
    return accepted


def candidate_record(candidate: XssCandidate) -> dict:
    return {
        "checked_at": now_iso(),
        "source_key_sha256": endpoint_key(candidate.url, candidate.param),
        "url": redacted_url(candidate.url),
        "param": candidate.param,
        "host": urlparse(candidate.url).netloc.lower(),
        "base_url": candidate.base_url,
        "source": candidate.source,
        "method": candidate.method,
        "score": candidate.score,
        "candidate_priority": priority_tier(candidate.score),
        "source_priority_score": candidate.source_priority_score,
        "reasons": list(candidate.reasons),
        "default_action": candidate.default_action,
        "skip_reason": candidate.skip_reason,
        "safe_default": True,
        "notes": "Query values are redacted. Auto mode only uses a random inert marker in a GET parameter.",
    }


def reflection_context(text: str, marker: str, content_type: str) -> str:
    if marker not in text:
        return ""
    ctype = content_type.lower()
    if "json" in ctype:
        return "json_data"
    idx = text.find(marker)
    before = text[:idx].lower()
    script_start = before.rfind("<script")
    script_end = before.rfind("</script")
    if script_start > script_end:
        return "script_block"
    if before.rfind("<") > before.rfind(">"):
        return "html_tag_or_attribute"
    window = text[max(0, idx - 120): idx + len(marker) + 120].lower()
    if re.search(r"<(?:textarea|title|style)\b", window):
        return "special_html_text"
    if "html" in ctype:
        return "html_text"
    if "javascript" in ctype or "ecmascript" in ctype:
        return "script_response"
    return "plain_or_unknown"


def context_confidence(context: str) -> str:
    if context in {"script_block", "script_response", "html_tag_or_attribute"}:
        return "medium"
    if context:
        return "low"
    return "none"


def priority_tier(score: int) -> str:
    if score >= 85:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    return "P3"


def reflection_candidate_score(candidate: XssCandidate, reflected: bool, context: str, status: int, text: str) -> tuple[int, list[str]]:
    score = int(candidate.score or 0)
    notes: list[str] = []
    if reflected:
        score += 28
        notes.append("marker_reflected")
    if context in {"script_block", "script_response", "html_tag_or_attribute"}:
        score += 18
        notes.append("potentially_executable_context")
    elif context in {"html_text", "special_html_text"}:
        score += 8
        notes.append("html_text_reflection")
    elif context == "json_data":
        score += 5
        notes.append("json_reflection")
    if status in (200, 206):
        score += 4
        notes.append("http_ok")
    if ERROR_OR_BLOCK_PAGE_RE.search((text or "")[:80000]):
        score -= 16
        notes.append("likely_error_or_block_page")
    return max(0, min(100, score)), sorted(set(notes))


def fetch_wait(url: str, run_dir: Path, timeout: int, delay: float) -> FetchResult:
    result = fetch(url, timeout, min(4, timeout), run_dir / ".xss_tmp")
    if delay > 0:
        time.sleep(delay)
    return result


def analyze_reflection(candidate: XssCandidate, run_dir: Path, timeout: int, delay: float, marker: str) -> dict:
    probe_url = mutate_param(candidate.url, candidate.param, marker)
    result = fetch_wait(probe_url, run_dir, timeout, delay)
    reflected = marker in (result.text or "")
    reflection_count = (result.text or "").count(marker)
    context = reflection_context(result.text or "", marker, result.content_type)
    candidate_score, score_notes = reflection_candidate_score(candidate, reflected, context, result.status, result.text or "")
    signals: list[str] = []
    if result.error:
        signals.append("request_error")
    if reflected:
        signals.append("marker_reflected")
    if context in {"script_block", "script_response", "html_tag_or_attribute"}:
        signals.append("potentially_executable_context")
    if "likely_error_or_block_page" in score_notes:
        signals.append("likely_error_or_block_page")

    return {
        "checked_at": now_iso(),
        "source_key_sha256": endpoint_key(candidate.url, candidate.param),
        "url": redacted_url(candidate.url),
        "probe_url": redacted_url(candidate.url, candidate.param, marker),
        "param": candidate.param,
        "host": urlparse(candidate.url).netloc.lower(),
        "base_url": candidate.base_url,
        "source": candidate.source,
        "status": result.status,
        "final_url": redacted_url(result.final_url or probe_url),
        "content_type": result.content_type,
        "content_length": result.content_length,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "sample_sha256": result.sample_sha256,
        "marker_reflected": reflected,
        "reflection_count": reflection_count,
        "reflection_context": context,
        "confidence": context_confidence(context),
        "candidate_score": candidate_score,
        "candidate_priority": priority_tier(candidate_score),
        "score_notes": score_notes,
        "signals": signals,
        "manual_check_recommended": reflected,
        "manual_focus": "response_context_and_output_encoding" if reflected else "none",
        "error": result.error,
        "notes": "This is an inert marker reflection check, not a confirmed executable XSS proof.",
    }


def md_safe(value: object, limit: int = 180) -> str:
    text = str(value or "").replace("|", "/").replace("\n", " ")
    return text[:limit]


def refresh_text_outputs(run_dir: Path) -> None:
    candidates = read_jsonl(run_dir / "xss_candidates.jsonl")
    checks = read_jsonl(run_dir / "xss_reflection_checks.jsonl")
    reflected = [row for row in checks if row.get("marker_reflected")]
    risky = [row for row in reflected if row.get("confidence") == "medium"]

    txt_lines = [
        f"[{row.get('confidence')}] {row.get('host')} param={row.get('param')} context={row.get('reflection_context')} {row.get('probe_url')}"
        for row in reflected
    ]
    (run_dir / "xss_reflection_candidates.txt").write_text("\n".join(txt_lines) + ("\n" if txt_lines else ""), encoding="utf-8")

    lines = [
        "# XSS 候选与安全反射检查",
        "",
        f"- Generated: {now_iso()}",
        f"- Candidate params: {len(candidates)}",
        f"- Reflection checks: {len(checks)}",
        f"- Reflected markers: {len(reflected)}",
        f"- Medium-confidence contexts: {len(risky)}",
        "",
        "## 这一步做了什么",
        "",
        "- 自动阶段只对已发现的参数化 GET URL 放入随机无害标记，例如 `xssprobe_<random>`。",
        "- 只判断响应里是否反射这个标记，以及大概落在 HTML 文本、属性、script 或 JSON 里。",
        "- 不发送 `<script>`、事件处理器、DNSLog/Blind XSS、外连回调，也不提交评论、昵称、工单等可能存储的内容。",
        "- 所有 URL 查询值已打码；不保存 Cookie、Token、Authorization 或响应正文。",
        "",
        "## 优先人工复核",
        "",
        "| Confidence | Host | Param | Context | Probe URL |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in sorted(reflected, key=lambda item: (item.get("confidence") != "medium", item.get("host") or "", item.get("param") or ""))[:120]:
        lines.append(
            f"| {md_safe(row.get('confidence'))} | `{md_safe(row.get('host'))}` | `{md_safe(row.get('param'))}` | "
            f"{md_safe(row.get('reflection_context'))} | `{md_safe(row.get('probe_url'), 240)}` |"
        )
    if not reflected:
        lines.append("|  |  |  |  | No reflected marker in sampled responses. |")

    lines.extend([
        "",
        "## 怎么继续看",
        "",
        "- `medium` 表示标记落在 script、JS 响应、HTML 标签或属性附近，优先用 Burp Repeater 单条复核上下文。",
        "- `low` 通常只是页面文本或 JSON 反射，很多时候不能直接形成 XSS，但仍可作为输入过滤线索。",
        "- 如果入口是评论、留言、昵称、工单、公告等可能写入的位置，本脚本只排队，不自动请求。",
        "- 报告时需要证明可执行上下文和影响面；仅“参数原样返回”通常只能作为候选线索。",
    ])
    (run_dir / "xss_manual_review.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def tool_manifest() -> dict:
    return {
        "curl": find_tool("curl", ["curl.exe"]),
        "nuclei": find_tool("nuclei"),
        "dalfox": find_tool("dalfox"),
        "xsstrike": find_tool("xsstrike"),
        "policy": "External XSS scanners are not launched by default. Use them only for one approved candidate at a time.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe reflected-XSS candidate triage for discovered parameterized GET URLs")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--max-per-host", type=int, default=3)
    parser.add_argument("--max-params-per-url", type=int, default=2)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--reflect-check", action="store_true", help="Send one inert marker GET request per auto-safe candidate")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    args.run_dir.mkdir(parents=True, exist_ok=True)
    candidates = load_url_params(args.run_dir, args.max_params_per_url, args.max_per_host, args.limit, args.force)
    manifest = {
        "created_at": now_iso(),
        "candidate_param_count": len(candidates),
        "reflect_check": bool(args.reflect_check),
        "delay": args.delay,
        "timeout": args.timeout,
        "max_per_host": args.max_per_host,
        "max_params_per_url": args.max_params_per_url,
        "request_budget_per_auto_param": 1 if args.reflect_check else 0,
        "disabled_tests": [
            "stored_xss_auto_submit",
            "blind_xss_callbacks",
            "script_payloads",
            "event_handler_payloads",
            "post_body_mutation",
            "cookie_or_token_capture",
            "response_body_persistence",
        ],
        "tools": tool_manifest(),
    }
    (args.run_dir / "xss_triage_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    marker_prefix = "xssprobe_" + uuid.uuid4().hex[:10]
    tested = 0
    for index, candidate in enumerate(candidates, start=1):
        append_jsonl(args.run_dir / "xss_candidates.jsonl", candidate_record(candidate))
        if not args.reflect_check or candidate.default_action != "auto_reflection_check":
            continue
        marker = f"{marker_prefix}_{index}"
        try:
            record = analyze_reflection(candidate, args.run_dir, args.timeout, args.delay, marker)
        except Exception as exc:  # noqa: BLE001
            record = {
                "checked_at": now_iso(),
                "source_key_sha256": endpoint_key(candidate.url, candidate.param),
                "url": redacted_url(candidate.url),
                "param": candidate.param,
                "host": urlparse(candidate.url).netloc.lower(),
                "signals": ["probe_error"],
                "confidence": "none",
                "marker_reflected": False,
                "error": str(exc)[:300],
            }
        append_jsonl(args.run_dir / "xss_reflection_checks.jsonl", record)
        tested += 1

    refresh_text_outputs(args.run_dir)
    print(json.dumps({
        "candidates": len(candidates),
        "tested": tested,
        "run_dir": str(args.run_dir),
        "manual_review": str(args.run_dir / "xss_manual_review.md"),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
