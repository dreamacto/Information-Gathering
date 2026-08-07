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
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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


def mutate_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = [(name, value if name == param else old_value) for name, old_value in pairs]
    return urlunparse(parsed._replace(query=urlencode(replaced, doseq=True)))


def param_value(url: str, param: str) -> str:
    for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if name == param:
            return value
    return ""


def boolean_payloads(value: str) -> tuple[str, str]:
    if re.fullmatch(r"-?\d+(?:\.\d+)?", value.strip()):
        return f"{value} AND 1=1", f"{value} AND 1=2"
    return f"{value}' AND '1'='1", f"{value}' AND '1'='2"


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


def sample_meta(result: FetchResult) -> dict:
    return {
        "status": result.status,
        "final_url": result.final_url,
        "content_type": result.content_type,
        "content_length": result.content_length,
        "sample_sha256": result.sample_sha256,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "error": result.error,
    }


def fetch_wait(url: str, run_dir: Path, timeout: int, delay: float) -> FetchResult:
    result = fetch(url, timeout, min(4, timeout), run_dir / ".sqli_tmp")
    if delay > 0:
        time.sleep(delay)
    return result


def analyze_probe(url_param: UrlParam, run_dir: Path, timeout: int, delay: float) -> dict:
    original_value = param_value(url_param.url, url_param.param)
    quote_url = mutate_param(url_param.url, url_param.param, original_value + "'")
    true_value, false_value = boolean_payloads(original_value)
    true_url = mutate_param(url_param.url, url_param.param, true_value)
    false_url = mutate_param(url_param.url, url_param.param, false_value)

    base1 = fetch_wait(url_param.url, run_dir, timeout, delay)
    base2 = fetch_wait(url_param.url, run_dir, timeout, delay)
    quote = fetch_wait(quote_url, run_dir, timeout, delay)
    bool_true = fetch_wait(true_url, run_dir, timeout, delay)
    bool_false = fetch_wait(false_url, run_dir, timeout, delay)

    base_stability = similarity(base1.text, base2.text)
    true_similarity = similarity(base1.text, bool_true.text)
    false_similarity = similarity(base1.text, bool_false.text)
    true_false_similarity = similarity(bool_true.text, bool_false.text)
    quote_similarity = similarity(base1.text, quote.text)

    baseline_error = db_error_family(base1.text + "\n" + base2.text)
    quote_error = db_error_family(quote.text)
    false_error = db_error_family(bool_false.text)

    signals: list[str] = []
    confidence = "none"
    high_probability = False

    baseline_stable = base1.status == base2.status and base_stability >= 0.90 and length_delta_ratio(base1.text, base2.text) <= 0.25
    if not baseline_stable:
        signals.append("unstable_baseline")
    if quote.status >= 500 and base1.status < 500:
        signals.append("quote_status_5xx_delta")
        confidence = "medium"
    if bool_false.status >= 500 and base1.status < 500:
        signals.append("boolean_false_status_5xx_delta")
        confidence = "medium"
    if quote_error and quote_error != baseline_error:
        signals.append(f"db_error_signature:{quote_error}")
        confidence = "high"
        high_probability = True
    if false_error and false_error != baseline_error:
        signals.append(f"db_error_signature:{false_error}")
        confidence = "high"
        high_probability = True
    if (
        baseline_stable
        and bool_true.status == base1.status
        and true_similarity >= 0.90
        and false_similarity <= 0.75
        and true_false_similarity <= 0.85
    ):
        signals.append("boolean_differential")
        confidence = "high"
        high_probability = True
    if not signals and quote_similarity <= 0.70 and baseline_stable:
        signals.append("quote_response_delta")
        confidence = "low"

    env_notes = environment_notes(base1.text, base2.text, quote.text, bool_true.text, bool_false.text)
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
        "boolean_true_similarity": round(true_similarity, 3),
        "boolean_false_similarity": round(false_similarity, 3),
        "boolean_true_false_similarity": round(true_false_similarity, 3),
        "baseline": sample_meta(base1),
        "baseline_repeat": sample_meta(base2),
        "quote_probe": sample_meta(quote),
        "boolean_true_probe": sample_meta(bool_true),
        "boolean_false_probe": sample_meta(bool_false),
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
    args = parser.parse_args()

    url_params = load_url_params(args.run_dir, args.max_params_per_url, args.max_per_host, args.limit, args.force)
    manifest = {
        "created_at": now_iso(),
        "candidate_param_count": len(url_params),
        "delay": args.delay,
        "timeout": args.timeout,
        "max_per_host": args.max_per_host,
        "max_params_per_url": args.max_params_per_url,
        "request_budget_per_param": 5,
        "disabled_tests": ["time_based", "union_select", "stacked_queries", "database_dump", "write_payloads"],
    }
    (args.run_dir / "sqli_triage_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for url_param in url_params:
        try:
            record = analyze_probe(url_param, args.run_dir, args.timeout, args.delay)
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
