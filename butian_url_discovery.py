#!/usr/bin/env python3
"""Discover official URL candidates for Butian vendor-name exports.

This script is intentionally conservative:

- It queries public search pages for organization names.
- It scores likely official homepages.
- It writes high-confidence targets separately from manual-review candidates.
- If requested, it runs the existing gov_exercise_runner only on high-confidence
  official candidates, without weak-credential review.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable

from exercise_runtime import now_iso

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


EXCLUDED_HOST_PARTS = (
    "bing.com",
    "baidu.com",
    "sogou.com",
    "so.com",
    "google.com",
    "duckduckgo.com",
    "butian.net",
    "zhihu.com",
    "wikipedia.org",
    "baike.",
    "qcc.com",
    "tianyancha.com",
    "aiqicha.baidu.com",
    "weibo.com",
    "douyin.com",
    "bilibili.com",
    "news.",
    "sohu.com",
    "sina.com",
    "163.com",
    "toutiao.com",
    "thepaper.cn",
    "map.baidu.com",
    "mp.weixin.qq.com",
    "weixin.qq.com",
)

GOOD_SUFFIXES = (
    ".edu.cn",
    ".ac.cn",
    ".org.cn",
    ".gov.cn",
    ".edu",
)

OK_SUFFIXES = (
    ".cn",
    ".com.cn",
    ".net.cn",
    ".org",
    ".com",
)


@dataclass
class VendorName:
    rank: str
    name: str
    type_hint: str
    source_urls: str


@dataclass
class Candidate:
    name: str
    type_hint: str
    candidate_url: str
    host: str
    score: int
    status: str
    provider: str
    query: str
    result_rank: int
    result_title: str
    result_url: str
    reasons: str
    checked_at: str


class LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        attrs_dict = {k.lower(): v for k, v in attrs if k}
        href = attrs_dict.get("href")
        if not href:
            return
        self._href = href
        self._text = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or not self._href:
            return
        title = normalize_space(" ".join(self._text))
        self.links.append((self._href, title))
        self._href = None
        self._text = []


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(value or "")).strip()


def host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def root_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def decode_bing_a1(value: str) -> str:
    if not value.startswith("a1"):
        return value
    payload = value[2:]
    payload += "=" * (-len(payload) % 4)
    try:
        return urllib.parse.unquote(
            __import__("base64").urlsafe_b64decode(payload.encode("ascii")).decode("utf-8", "replace")
        )
    except Exception:
        return value


def unwrap_result_url(href: str, base_url: str) -> str:
    href = html.unescape(href)
    absolute = urllib.parse.urljoin(base_url, href)
    parsed = urllib.parse.urlparse(absolute)
    query = urllib.parse.parse_qs(parsed.query)
    for key in ("url", "u", "uddg", "target"):
        if key in query and query[key]:
            value = query[key][0]
            if key == "u":
                value = decode_bing_a1(value)
            return urllib.parse.unquote(value)
    if parsed.netloc.endswith("bing.com") and parsed.path.startswith("/ck/") and "u" in query:
        return decode_bing_a1(query["u"][0])
    return absolute


def is_excluded_host(host: str) -> bool:
    if not host:
        return True
    return any(part in host for part in EXCLUDED_HOST_PARTS)


def likely_detail_page(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    if path in ("", "/"):
        return False
    bad_parts = ("/news/", "/article/", "/content/", "/info/", "/view/", "/show/", ".pdf", ".doc", ".xls")
    return any(part in path for part in bad_parts)


def score_candidate(name: str, type_hint: str, result_url: str, title: str) -> tuple[int, list[str]]:
    host = host_of(result_url)
    score = 0
    reasons: list[str] = []
    haystack = f"{title} {result_url}"
    exact_name = name and name in haystack

    if exact_name:
        score += 45
        reasons.append("exact_name_in_result")
    if any(word in title for word in ("官网", "官方网站", "首页", "学校概况", "医院概况")):
        score += 18
        reasons.append("official_title_word")
    if any(host.endswith(suffix) for suffix in GOOD_SUFFIXES):
        score += 24
        reasons.append("good_public_sector_suffix")
    elif any(host.endswith(suffix) for suffix in OK_SUFFIXES):
        score += 10
        reasons.append("common_domain_suffix")
    if type_hint in {"college", "university", "vocational_college"} and (host.endswith(".edu.cn") or ".edu." in host):
        score += 12
        reasons.append("education_domain_for_school")
    if type_hint == "hospital_or_medical_school" and any(token in host for token in ("hospital", "hosp", "yfy", "fy", "120")):
        score += 10
        reasons.append("medical_host_token")
    if is_excluded_host(host):
        score -= 80
        reasons.append("excluded_host")
    if likely_detail_page(result_url):
        score -= 12
        reasons.append("likely_detail_or_news_page")
    if urllib.parse.urlparse(result_url).scheme == "https":
        score += 3
        reasons.append("https")
    return score, reasons


def status_for_score(score: int, name: str, result_url: str, title: str, min_score: int) -> str:
    if score >= min_score and name in f"{title} {result_url}" and not is_excluded_host(host_of(result_url)):
        return "auto_high_confidence"
    if score >= 55 and not is_excluded_host(host_of(result_url)):
        return "manual_review"
    return "low_confidence"


def search_url(provider: str, query: str) -> str:
    encoded = urllib.parse.urlencode({"q": query})
    if provider == "duckduckgo":
        return "https://duckduckgo.com/html/?" + encoded
    return "https://www.bing.com/search?" + urllib.parse.urlencode({"q": query, "count": "10", "mkt": "zh-CN"})


def build_queries(name: str, type_hint: str, max_queries: int) -> list[str]:
    queries = [
        f'"{name}" 官网',
        f"{name} 官网",
        f'"{name}" 官方网站',
    ]
    if type_hint in {"college", "university", "vocational_college"}:
        queries.append(f"site:edu.cn {name}")
    elif type_hint == "hospital_or_medical_school":
        queries.append(f"{name} 医院 官网")
    else:
        queries.append(f"{name} 官方")
    deduped: list[str] = []
    for query in queries:
        if query not in deduped:
            deduped.append(query)
    return deduped[: max(1, max_queries)]


def fetch_search(provider: str, query: str, timeout: int) -> tuple[str, str]:
    url = search_url(provider, query)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.7",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(1024 * 1024)
        charset = resp.headers.get_content_charset() or "utf-8"
    return url, raw.decode(charset, errors="replace")


def parse_results(provider: str, base_url: str, body: str, limit: int) -> list[tuple[str, str]]:
    collector = LinkCollector()
    collector.feed(body)
    output: list[tuple[str, str]] = []
    seen: set[str] = set()
    for href, title in collector.links:
        url = unwrap_result_url(href, base_url)
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            continue
        host = host_of(url)
        if not host or is_excluded_host(host):
            continue
        clean = root_url(url)
        if not clean or clean in seen:
            continue
        seen.add(clean)
        output.append((clean, title[:240]))
        if len(output) >= limit:
            break
    return output


def load_vendor_names(run_dir: Path) -> list[VendorName]:
    path = run_dir / "butian_vendor_names.csv"
    rows: list[VendorName] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            name = (row.get("name") or "").strip()
            if not name:
                continue
            rows.append(
                VendorName(
                    rank=row.get("rank", ""),
                    name=name,
                    type_hint=row.get("type_hint", "organization"),
                    source_urls=row.get("source_urls", ""),
                )
            )
    return rows


def append_jsonl(path: Path, item: dict) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(item, ensure_ascii=False) + "\n")


def write_candidates(path: Path, candidates: Iterable[Candidate]) -> None:
    rows = list(candidates)
    fields = list(asdict(rows[0]).keys()) if rows else [
        "name",
        "type_hint",
        "candidate_url",
        "host",
        "score",
        "status",
        "provider",
        "query",
        "result_rank",
        "result_title",
        "result_url",
        "reasons",
        "checked_at",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in rows:
            writer.writerow(asdict(item))


def write_targets(path: Path, candidates: Iterable[Candidate]) -> int:
    count = 0
    seen: set[str] = set()
    with path.open("w", encoding="utf-8") as handle:
        handle.write("# Auto high-confidence official URL candidates from Butian vendor names.\n")
        handle.write("# Format: URL|organization name. Do not add weak-credential flags by default.\n")
        for item in candidates:
            if item.status != "auto_high_confidence" or item.candidate_url in seen:
                continue
            handle.write(f"{item.candidate_url}|{item.name}\n")
            seen.add(item.candidate_url)
            count += 1
    return count


def run_gov_runner(run_dir: Path, target_file: Path, gov_delay: float, python_exe: str) -> dict:
    log_path = run_dir / "logs" / "gov_exercise_high_confidence.log"
    command = [
        python_exe,
        str(Path.cwd() / "gov_exercise_runner.py"),
        "--targets",
        str(target_file),
        "--resume-run-dir",
        str(run_dir),
        "--label",
        "butian_academy_auto",
        "--probe",
        "--fingerprint",
        "--high-value-paths",
        "--api-discovery",
        "--api-confirm",
        "--sqli-triage",
        "--shiro-triage",
        "--wechat-miniapp",
        "--healthcare-profile",
        "--delay",
        str(gov_delay),
    ]
    (run_dir / "butian_gov_command.json").write_text(
        json.dumps({"started_at": now_iso(), "command": command, "log": str(log_path)}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        proc = subprocess.run(command, cwd=Path.cwd(), stdout=log, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    return {"returncode": proc.returncode, "log": str(log_path), "command": command}


def discover(args: argparse.Namespace) -> dict:
    run_dir = args.run_dir
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    progress_path = run_dir / "butian_url_discovery_progress.jsonl"
    candidates_path = run_dir / "butian_url_candidates.csv"
    review_path = run_dir / "butian_url_manual_review.csv"
    target_path = run_dir / "butian_auto_high_confidence_targets.txt"

    names = load_vendor_names(run_dir)
    if args.limit and args.limit > 0:
        names = names[: args.limit]

    candidates: list[Candidate] = []
    failures: list[dict] = []
    provider_failures = 0

    for index, vendor in enumerate(names, 1):
        queries = build_queries(vendor.name, vendor.type_hint, args.max_queries)
        item_log = {"checked_at": now_iso(), "index": index, "total": len(names), "name": vendor.name, "queries": []}
        seen_for_name: set[str] = set()
        found_high_confidence = False
        for query in queries:
            query_log = {"query": query, "results": 0}
            try:
                search_page, body = fetch_search(args.provider, query, args.timeout)
                results = parse_results(args.provider, search_page, body, args.max_results)
                query_log["results"] = len(results)
                for result_rank, (candidate_url, title) in enumerate(results, 1):
                    if candidate_url in seen_for_name:
                        continue
                    seen_for_name.add(candidate_url)
                    score, reasons = score_candidate(vendor.name, vendor.type_hint, candidate_url, title)
                    status = status_for_score(score, vendor.name, candidate_url, title, args.min_score)
                    if status == "auto_high_confidence":
                        found_high_confidence = True
                    candidates.append(
                        Candidate(
                            name=vendor.name,
                            type_hint=vendor.type_hint,
                            candidate_url=candidate_url,
                            host=host_of(candidate_url),
                            score=score,
                            status=status,
                            provider=args.provider,
                            query=query,
                            result_rank=result_rank,
                            result_title=title,
                            result_url=candidate_url,
                            reasons=";".join(reasons),
                            checked_at=now_iso(),
                        )
                    )
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                provider_failures += 1
                failures.append({"name": vendor.name, "query": query, "error": repr(exc), "checked_at": now_iso()})
                query_log["error"] = repr(exc)
            item_log["queries"].append(query_log)
            if found_high_confidence:
                break
            if args.query_delay > 0 and query != queries[-1]:
                time.sleep(args.query_delay + random.uniform(0, min(args.jitter, 0.5)))
        append_jsonl(progress_path, item_log)
        if args.delay > 0 and index < len(names):
            time.sleep(args.delay + random.uniform(0, args.jitter))

    candidates.sort(key=lambda c: (c.name, -c.score, c.result_rank))
    write_candidates(candidates_path, candidates)
    write_candidates(review_path, [c for c in candidates if c.status != "auto_high_confidence"])
    target_count = write_targets(target_path, candidates)

    summary = {
        "finished_at": now_iso(),
        "run_dir": str(run_dir),
        "provider": args.provider,
        "names_processed": len(names),
        "candidate_rows": len(candidates),
        "auto_high_confidence_targets": target_count,
        "manual_review_rows": sum(1 for c in candidates if c.status != "auto_high_confidence"),
        "failures": len(failures),
        "provider_failures": provider_failures,
        "min_score": args.min_score,
        "target_file": str(target_path),
        "candidates_csv": str(candidates_path),
        "manual_review_csv": str(review_path),
        "network_requests_sent": True,
        "gov_runner": None,
    }
    (run_dir / "butian_url_discovery_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if failures:
        (run_dir / "butian_url_discovery_failures.json").write_text(json.dumps(failures, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.run_gov_on_high_confidence and target_count > 0:
        summary["gov_runner"] = run_gov_runner(run_dir, target_path, args.gov_delay, args.python_exe or sys.executable)
        (run_dir / "butian_url_discovery_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Discover official URL candidates for Butian vendor-name runs")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--provider", choices=["bing", "duckduckgo"], default="bing")
    parser.add_argument("--delay", type=float, default=2.5)
    parser.add_argument("--jitter", type=float, default=0.8)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--max-results", type=int, default=8)
    parser.add_argument("--max-queries", type=int, default=3)
    parser.add_argument("--query-delay", type=float, default=0.8)
    parser.add_argument("--min-score", type=int, default=82)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--run-gov-on-high-confidence", action="store_true")
    parser.add_argument("--gov-delay", type=float, default=3.0)
    parser.add_argument("--python-exe", default=sys.executable)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    summary = discover(args)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
