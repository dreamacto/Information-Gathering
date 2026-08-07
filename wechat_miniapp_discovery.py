#!/usr/bin/env python3
"""Batch WeChat mini-program OSINT candidate generator.

This stage does not attack targets. It turns known domains/probe titles into
unit-name seeds, search dorks, and optional read-only homepage clues such as
wx appids, mp.weixin links, gh_ ids, wxaurl links, and QR-code image URLs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import http.client
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


APPID_RE = re.compile(r"\bwx[0-9a-fA-F]{16,20}\b")
GH_RE = re.compile(r"\bgh_[0-9a-zA-Z]{8,32}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:gov\.cn|org\.cn|com\.cn|net\.cn|edu\.cn|cn|com|net|org|store)\b",
    re.I,
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
WECHAT_URL_RE = re.compile(
    r"https?://[^\s\"'<>]*(?:mp\.weixin\.qq\.com|weixin\.qq\.com|wxaurl\.cn|servicewechat\.com)[^\s\"'<>]*",
    re.I,
)
SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
IMG_RE = re.compile(r"<img[^>]+src=[\"']([^\"']+)[\"'][^>]*>", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
COPYRIGHT_RE = re.compile(r"(?:主办|承办|版权所有|版权归|技术支持)[:：\s]*([^<\n\r]{2,80})", re.I)
ORG_SUFFIX_RE = re.compile(
    r"([\u4e00-\u9fff]{2,40}(?:人民政府|政府|委员会|办公室|公安局|财政局|自然资源局|自然资源厅|"
    r"生态环境局|生态环境厅|政务服务中心|政务服务和大数据发展局|大数据发展局|市场监督管理局|"
    r"人力资源和社会保障局|医保局|教育局|交通运输局|住房和城乡建设局|农业农村局|"
    r"商务局|文广旅局|文化广电和旅游局|税务局|法院|检察院|厅|局|办|中心))"
)
NOISE_TITLE_RE = re.compile(r"(404|403|not found|error|forbidden|登录|访问禁止|找不到网页|提示信息)", re.I)
AUTH_URL_RE = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|register|signup|sign-up|oauth|authorize|auth|token|session|"
    r"wxlogin|wx-login|wechat-login|phone-login|sms-login|user/login|user/register)(?:/|$|[?&#_-])",
    re.I,
)
REGISTER_URL_RE = re.compile(r"(?:^|/)(?:register|signup|sign-up|user/register)(?:/|$|[?&#_-])", re.I)
BACKEND_URL_RE = re.compile(
    r"(?:^|/)(?:api|gateway|prod-api|miniapp|mini-program|wechat|wx|patient|report|his|lis|pacs)(?:/|$|[?&#_-])",
    re.I,
)
STATIC_SUFFIXES = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf")
WECHAT_PLATFORM_HOSTS = {
    "mp.weixin.qq.com", "weixin.qq.com", "open.weixin.qq.com", "servicewechat.com", "wxaurl.cn",
}


SEARCH_PATTERNS = [
    '"{seed}" "小程序"',
    '"{seed}" "微信小程序"',
    '"{seed}" "扫码"',
    '"{seed}" "掌上办"',
    '"{seed}" "移动端"',
    '"{seed}" "公众号"',
    '"{seed}" site:mp.weixin.qq.com',
    '"{seed}" site:weixin.qq.com',
]


@dataclass
class Seed:
    url: str
    host: str
    title: str = ""
    name: str = ""
    source: str = ""
    keywords: set[str] = field(default_factory=set)


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def normalize_url(raw: str) -> str:
    raw = raw.strip().lstrip("\ufeff")
    if not raw:
        return ""
    raw = raw.split("|", 1)[0].strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def redact_url_values(raw: str) -> str:
    """Keep endpoint shape and parameter names, never URL credentials or values."""
    parsed = urlparse(raw)
    if not parsed.hostname:
        return ""
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        return ""
    netloc = f"{host}:{port}" if port is not None else host
    names = sorted({part.split("=", 1)[0] for part in parsed.query.split("&") if part})
    query = "&".join(f"{name}=<redacted>" for name in names)
    return parsed._replace(netloc=netloc, query=query, fragment="").geturl()


def clean_text(value: str) -> str:
    value = html.unescape(value or "")
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:160]


def host_tokens(host: str) -> list[str]:
    if is_ip_like(host):
        return []
    parts = host.lower().split(".")
    out = []
    for part in parts:
        if part in {"www", "com", "cn", "gov", "gxzf", "net", "org"}:
            continue
        if len(part) >= 2 and not part.isdigit():
            out.append(part)
    return out[:5]


def is_ip_like(host: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host or ""))


def useful_keyword(value: str) -> bool:
    value = (value or "").strip()
    if len(value) < 2:
        return False
    if value.isdigit():
        return False
    if re.fullmatch(r"[\d.:-]+", value):
        return False
    if value.lower() in {"www", "http", "https", "index", "login", "admin"}:
        return False
    return True


def title_keywords(title: str) -> set[str]:
    title = clean_text(title)
    if not title or NOISE_TITLE_RE.search(title):
        return set()
    pieces = re.split(r"[-_—|｜·,，;；]", title)
    seeds = {piece.strip() for piece in pieces if 2 <= len(piece.strip()) <= 32}
    for match in ORG_SUFFIX_RE.finditer(title):
        seeds.add(match.group(1).strip())
    return seeds


def likely_guangxi_government(host: str, text: str = "") -> bool:
    hay = f"{host} {text}".lower()
    return any(
        token in hay
        for token in [
            "gxzf.gov.cn",
            ".gx.gov.cn",
            "guangxi",
            "gx",
            "nanning",
            "liuzhou",
            "guilin",
            "wuzhou",
            "beihai",
            "fangchenggang",
            "qinzhou",
            "guigang",
            "yulin",
            "baise",
            "hezhou",
            "hechi",
            "laibin",
            "chongzuo",
            "广西",
            "南宁",
            "柳州",
            "桂林",
            "梧州",
            "北海",
            "防城港",
            "钦州",
            "贵港",
            "玉林",
            "百色",
            "贺州",
            "河池",
            "来宾",
            "崇左",
        ]
    )


def read_jsonl(path: Path) -> list[dict]:
    rows = []
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


def collect_from_target_file(path: Path, seeds: dict[str, Seed]) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8-sig", errors="ignore").splitlines():
        url = normalize_url(line)
        if not url:
            continue
        host = urlparse(url).hostname or ""
        seeds.setdefault(url, Seed(url=url, host=host, source=str(path)))


def add_url_seed(raw: str, seeds: dict[str, Seed], source: str, title: str = "") -> None:
    url = normalize_url(raw)
    if not url:
        return
    host = urlparse(url).hostname or ""
    if not host:
        return
    seed = seeds.setdefault(url, Seed(url=url, host=host, source=source))
    if title and not seed.title:
        seed.title = clean_text(title)
    seed.keywords.update(title_keywords(title))


def collect_from_input_dir(path: Path, seeds: dict[str, Seed], max_file_size: int = 5_000_000) -> None:
    if not path.exists():
        return
    allowed_suffixes = {".txt", ".csv", ".json", ".jsonl", ".html", ".htm", ".md", ""}
    for file_path in path.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in allowed_suffixes:
            continue
        try:
            if file_path.stat().st_size > max_file_size:
                continue
        except OSError:
            continue

        # afrog-style filenames often contain the target even when file content
        # is only a rendered report fragment.
        filename_text = file_path.stem.replace("_", " ").replace("-", " ")
        for domain in DOMAIN_RE.findall(filename_text):
            add_url_seed(domain, seeds, str(file_path))

        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        title = ""
        title_match = TITLE_RE.search(text)
        if title_match:
            title = clean_text(title_match.group(1))
        for raw_url in URL_RE.findall(text):
            add_url_seed(raw_url, seeds, str(file_path), title)
        for domain in DOMAIN_RE.findall(text):
            add_url_seed(domain, seeds, str(file_path), title)
        for match in COPYRIGHT_RE.finditer(text):
            org = clean_text(match.group(1))
            if org:
                for seed in list(seeds.values())[-20:]:
                    if str(file_path) == seed.source:
                        seed.keywords.add(org)


def collect_from_run_dir(run_dir: Path, seeds: dict[str, Seed]) -> None:
    targets_csv = run_dir / "targets.csv"
    if targets_csv.exists():
        with targets_csv.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            for row in csv.DictReader(handle):
                url = normalize_url(row.get("url", ""))
                if not url:
                    continue
                host = urlparse(url).hostname or row.get("host", "")
                seed = seeds.setdefault(url, Seed(url=url, host=host, source=str(targets_csv)))
                if row.get("name"):
                    seed.name = row["name"]
                    seed.keywords.add(row["name"])
    for probe in read_jsonl(run_dir / "probe_results.jsonl"):
        url = normalize_url(probe.get("url") or probe.get("final_url") or "")
        if not url:
            continue
        host = urlparse(url).hostname or probe.get("host", "")
        seed = seeds.setdefault(url, Seed(url=url, host=host, source=str(run_dir / "probe_results.jsonl")))
        title = clean_text(probe.get("title", ""))
        if title and not seed.title:
            seed.title = title
        seed.keywords.update(title_keywords(title))


def fetch_text(url: str, timeout: int) -> tuple[int, str, str, str]:
    ctx = ssl._create_unverified_context()
    req = Request(
        url,
        headers={
            "User-Agent": "Authorized-WeChat-MiniApp-OSINT/1.0",
            "Accept": "text/html,application/xhtml+xml,application/javascript,text/plain,*/*;q=0.8",
            "Range": "bytes=0-524287",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(524288)
            ctype = resp.headers.get("content-type", "")
            final_url = resp.geturl()
            status = int(getattr(resp, "status", 0) or 0)
    except HTTPError as exc:
        body = exc.read(524288)
        ctype = exc.headers.get("content-type", "")
        final_url = exc.geturl()
        status = int(exc.code or 0)
    except (URLError, TimeoutError, socket.timeout, ssl.SSLError, http.client.HTTPException) as exc:
        return 0, "", "", str(exc)[:220]
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", ctype, re.I)
    if match:
        charset = match.group(1)
    return status, final_url, body.decode(charset, errors="ignore"), ""


def extract_clues(base_url: str, text: str) -> list[dict]:
    clues: list[dict] = []
    decoded_text = text.replace("\\/", "/").replace(r"\u002F", "/").replace(r"\u002f", "/")
    for appid in sorted(set(APPID_RE.findall(text))):
        clues.append({"kind": "wx_appid", "value": appid, "confidence": "high"})
    for gh in sorted(set(GH_RE.findall(text))):
        clues.append({"kind": "gh_id", "value": gh, "confidence": "medium"})
    for url in sorted(set(WECHAT_URL_RE.findall(text))):
        clues.append({"kind": "wechat_url", "value": url[:300], "confidence": "high"})
    for raw_url in sorted(set(URL_RE.findall(decoded_text))):
        value = redact_url_values(raw_url.rstrip("\"'();,]}>"))[:500]
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        path_and_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
        if not host or any(host == item or host.endswith("." + item) for item in WECHAT_PLATFORM_HOSTS):
            continue
        if parsed.path.lower().endswith(STATIC_SUFFIXES):
            continue
        if AUTH_URL_RE.search(path_and_query):
            clues.append({
                "kind": "auth_endpoint_candidate",
                "value": value,
                "confidence": "high",
                "registration_candidate": bool(REGISTER_URL_RE.search(path_and_query)),
            })
        elif BACKEND_URL_RE.search(path_and_query):
            clues.append({"kind": "candidate_backend_url", "value": value, "confidence": "review"})
    for match in IMG_RE.finditer(text):
        tag = match.group(0)
        raw = match.group(1)
        lower = tag.lower() + raw.lower()
        if any(token in lower for token in ["weixin", "wechat", "wx", "qrcode", "qr", "小程序", "公众号", "二维码"]):
            clues.append({
                "kind": "qr_or_wechat_image",
                "value": urljoin(base_url.rstrip("/") + "/", raw)[:300],
                "confidence": "review",
            })
    return clues


def discover_live(seed: Seed, out_dir: Path, delay: float, timeout: int, max_js: int) -> None:
    status, final_url, text, error = fetch_text(seed.url, timeout)
    append_jsonl(out_dir / "wechat_home_checks.jsonl", {
        "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "url": seed.url,
        "status": status,
        "final_url": final_url,
        "title": clean_text(TITLE_RE.search(text).group(1)) if TITLE_RE.search(text) else "",
        "error": error,
        "sample_sha256": hashlib.sha256(text[:65536].encode("utf-8", errors="ignore")).hexdigest() if text else "",
    })
    for clue in extract_clues(seed.url, text):
        append_jsonl(out_dir / "wechat_miniapp_candidates.jsonl", {
            "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "domain": seed.host,
            "url": seed.url,
            "source": "homepage",
            **clue,
        })
    scripts = []
    for match in SCRIPT_RE.finditer(text):
        js_url = urljoin(seed.url.rstrip("/") + "/", match.group(1))
        if urlparse(js_url).hostname == seed.host:
            scripts.append(js_url)
    time.sleep(delay)
    for js_url in sorted(set(scripts))[:max_js]:
        status, final_url, js_text, error = fetch_text(js_url, timeout)
        append_jsonl(out_dir / "wechat_js_checks.jsonl", {
            "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "base_url": seed.url,
            "js_url": js_url,
            "status": status,
            "final_url": final_url,
            "error": error,
            "sample_sha256": hashlib.sha256(js_text[:65536].encode("utf-8", errors="ignore")).hexdigest() if js_text else "",
        })
        for clue in extract_clues(seed.url, js_text):
            append_jsonl(out_dir / "wechat_miniapp_candidates.jsonl", {
                "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "domain": seed.host,
                "url": seed.url,
                "source": "javascript",
                "js_url": js_url,
                **clue,
            })
        time.sleep(delay)


def write_outputs(seeds: list[Seed], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    seed_csv = out_dir / "wechat_unit_keyword_seeds.csv"
    with seed_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["priority", "host", "url", "title", "name", "keywords"])
        writer.writeheader()
        for seed in seeds:
            keywords = sorted(k for k in (seed.keywords | title_keywords(seed.name) | title_keywords(seed.title)) if useful_keyword(k))
            writer.writerow({
                "priority": "high" if likely_guangxi_government(seed.host, " ".join(keywords)) else "normal",
                "host": seed.host,
                "url": seed.url,
                "title": seed.title,
                "name": seed.name,
                "keywords": " | ".join(keywords[:20]),
            })

    dork_rows = []
    dork_lines = []
    for seed in seeds:
        keywords = sorted(k for k in (seed.keywords | title_keywords(seed.name) | title_keywords(seed.title)) if useful_keyword(k))
        if not keywords:
            if is_ip_like(seed.host):
                continue
            host_seed = seed.host.replace("www.", "")
            keywords = [host_seed, *host_tokens(seed.host)]
        keywords = [keyword for keyword in keywords if useful_keyword(keyword)]
        for keyword in keywords[:8]:
            for pattern in SEARCH_PATTERNS:
                dork = pattern.format(seed=keyword)
                row = {
                    "priority": "high" if likely_guangxi_government(seed.host, keyword) else "normal",
                    "domain": seed.host,
                    "url": seed.url,
                    "seed": keyword,
                    "dork": dork,
                }
                dork_rows.append(row)
                dork_lines.append(dork)

    (out_dir / "wechat_search_dorks.txt").write_text("\n".join(sorted(set(dork_lines))) + "\n", encoding="utf-8")
    (out_dir / "wechat_search_dorks.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in dork_rows),
        encoding="utf-8",
    )
    with (out_dir / "wechat_search_dorks.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["priority", "domain", "url", "seed", "dork"])
        writer.writeheader()
        writer.writerows(dork_rows)


def write_scan_targets(seeds: list[Seed], out_dir: Path) -> dict:
    """Write scan handoff files for the main subdomain/alive workflow.

    We keep platform-owned WeChat domains out of the scan-ready file and put
    them in the pending/review file instead. The scan-ready list is meant for
    authorized source domains that showed WeChat/mini-program signals.
    """
    platform_hosts = WECHAT_PLATFORM_HOSTS
    scan_ready: set[str] = set()
    pending_review: set[str] = set()
    candidate_rows = read_jsonl(out_dir / "wechat_miniapp_candidates.jsonl")
    candidate_domains = {row.get("domain", "") for row in candidate_rows if row.get("domain")}

    for seed in seeds:
        if candidate_domains and seed.host not in candidate_domains:
            continue
        if seed.host and not is_ip_like(seed.host):
            scan_ready.add(seed.url)

    for row in candidate_rows:
        value = str(row.get("value", ""))
        parsed = urlparse(value)
        host = parsed.hostname or ""
        if not host:
            continue
        if any(host == item or host.endswith("." + item) for item in platform_hosts):
            pending_review.add(value)
        elif host in {seed.host for seed in seeds}:
            scheme = parsed.scheme or "https"
            scan_ready.add(f"{scheme}://{host}")
        else:
            pending_review.add(value)

    scan_path = out_dir / "wechat_subdomain_scan_targets.txt"
    pending_path = out_dir / "wechat_pending_extra_assets.txt"
    scan_path.write_text("\n".join(sorted(scan_ready)) + ("\n" if scan_ready else ""), encoding="utf-8")
    pending_path.write_text("\n".join(sorted(pending_review)) + ("\n" if pending_review else ""), encoding="utf-8")
    return {
        "scan_ready_count": len(scan_ready),
        "pending_review_count": len(pending_review),
        "scan_ready_file": scan_path.name,
        "pending_review_file": pending_path.name,
    }


def write_auth_handoff(seeds: list[Seed], out_dir: Path) -> dict:
    """Create an operator login/register queue without collecting credentials."""
    seed_hosts = {seed.host.lower() for seed in seeds if seed.host}
    items: dict[str, dict] = {}
    for row in read_jsonl(out_dir / "wechat_miniapp_candidates.jsonl"):
        if row.get("kind") != "auth_endpoint_candidate":
            continue
        value = str(row.get("value") or "").strip()
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}"
        platform = any(host == item or host.endswith("." + item) for item in WECHAT_PLATFORM_HOSTS)
        if platform:
            scope_state = "platform_excluded"
        elif host in seed_hosts:
            scope_state = "in_current_scope"
        else:
            scope_state = "ownership_confirmation_required"
        item = items.setdefault(host, {
            "host": host,
            "base_url": base_url,
            "login_urls": [],
            "login_detected": True,
            "registration_candidate": False,
            "scope_state": scope_state,
            "source_hosts": [],
            "operator_status": "pending_login",
            "cookie_handoff_file": "auth_sessions.local.json",
        })
        item["login_urls"].append(value)
        item["source_hosts"].append(str(row.get("domain") or ""))
        item["registration_candidate"] = bool(item["registration_candidate"] or row.get("registration_candidate"))

    output = []
    for item in items.values():
        item["login_urls"] = sorted(set(item["login_urls"]))[:20]
        item["source_hosts"] = sorted(set(filter(None, item["source_hosts"])))[:10]
        if item["scope_state"] == "in_current_scope":
            item["manual_action"] = "Open the login URL, use an authorized test account, then place the session in auth_sessions.local.json."
        elif item["scope_state"] == "ownership_confirmation_required":
            item["manual_action"] = "Confirm ownership and target approval before login or any request."
        else:
            item["manual_action"] = "Do not test the WeChat platform domain."
        output.append(item)
    output.sort(key=lambda row: (row["scope_state"] != "in_current_scope", not row["registration_candidate"], row["host"]))

    json_path = out_dir / "wechat_auth_domains.json"
    json_path.write_text(json.dumps({
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "count": len(output),
        "cookie_policy": "operator-provided local file only; never written to scan outputs",
        "items": output,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    csv_path = out_dir / "wechat_auth_domains.csv"
    fields = [
        "host", "base_url", "login_detected", "registration_candidate", "scope_state",
        "login_urls", "source_hosts", "operator_status", "cookie_handoff_file", "manual_action",
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in output:
            row = dict(item)
            row["login_urls"] = ";".join(item["login_urls"])
            row["source_hosts"] = ";".join(item["source_hosts"])
            writer.writerow({key: row.get(key, "") for key in fields})
    (out_dir / "wechat_auth_domains.txt").write_text(
        "\n".join(item["host"] for item in output if item["scope_state"] == "in_current_scope")
        + ("\n" if any(item["scope_state"] == "in_current_scope" for item in output) else ""),
        encoding="utf-8",
    )
    session_rows = [
        {
            "base_url": item["base_url"],
            "entry_url": item["login_urls"][0],
            "cookie": "<paste locally after manual login; never submit this file with reports>",
            "headers": {},
        }
        for item in output if item["scope_state"] == "in_current_scope"
    ]
    (out_dir / "wechat_auth_sessions.template.json").write_text(
        json.dumps({"sessions": session_rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    reports = out_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    lines = [
        "# WeChat Mini-Program Authentication Handoff", "",
        f"- Pending domains: {len(output)}",
        "- Cookies must stay in a local `auth_sessions.local.json` file and are never copied into results.",
        "", "| Scope | Registration | Domain | Login URL | Operator status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in output:
        login_url = item["login_urls"][0] if item["login_urls"] else item["base_url"]
        lines.append(
            f"| {item['scope_state']} | {'yes' if item['registration_candidate'] else 'unknown'} | "
            f"`{item['host']}` | `{login_url}` | {item['operator_status']} |"
        )
    (reports / "wechat_auth_domains.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "count": len(output),
        "in_scope_count": sum(item["scope_state"] == "in_current_scope" for item in output),
        "ownership_review_count": sum(item["scope_state"] == "ownership_confirmation_required" for item in output),
        "json": json_path.name,
        "csv": csv_path.name,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Batch WeChat mini-program OSINT candidate generator")
    parser.add_argument("--target-file", type=Path, action="append", default=[])
    parser.add_argument("--input-dir", type=Path, action="append", default=[])
    parser.add_argument("--run-dir", type=Path, action="append", default=[])
    parser.add_argument("--all-runs", action="store_true")
    parser.add_argument("--out-dir", type=Path, default=Path("runs") / f"{now_stamp()}_wechat_miniapp_discovery")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--live", action="store_true", help="Fetch homepage and same-host JS for WeChat clues")
    parser.add_argument("--delay", type=float, default=2.0)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--max-js", type=int, default=8)
    args = parser.parse_args()

    seeds: dict[str, Seed] = {}
    for path in args.target_file:
        collect_from_target_file(path, seeds)
    for path in args.input_dir:
        collect_from_input_dir(path, seeds)
    run_dirs = list(args.run_dir)
    if args.all_runs:
        run_dirs.extend(path for path in Path("runs").iterdir() if path.is_dir())
    for run_dir in run_dirs:
        collect_from_run_dir(run_dir, seeds)

    seed_list = sorted(seeds.values(), key=lambda s: (not likely_guangxi_government(s.host, s.title), s.host, s.url))
    if args.limit:
        seed_list = seed_list[: args.limit]
    write_outputs(seed_list, args.out_dir)

    if args.live:
        completed_live = {
            row.get("url")
            for row in read_jsonl(args.out_dir / "wechat_home_checks.jsonl")
            if row.get("url")
        }
        for seed in seed_list:
            if seed.url in completed_live:
                continue
            discover_live(seed, args.out_dir, args.delay, args.timeout, args.max_js)

    scan_target_summary = write_scan_targets(seed_list, args.out_dir)
    auth_handoff_summary = write_auth_handoff(seed_list, args.out_dir)

    summary = {
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "out_dir": str(args.out_dir),
        "seed_count": len(seed_list),
        "live": args.live,
        "scan_target_summary": scan_target_summary,
        "auth_handoff_summary": auth_handoff_summary,
        "outputs": [
            "wechat_unit_keyword_seeds.csv",
            "wechat_search_dorks.txt",
            "wechat_search_dorks.csv",
            "wechat_search_dorks.jsonl",
            "wechat_miniapp_candidates.jsonl" if args.live else "",
            "wechat_subdomain_scan_targets.txt",
            "wechat_pending_extra_assets.txt",
            "wechat_auth_domains.json",
            "wechat_auth_domains.csv",
            "wechat_auth_domains.txt",
            "wechat_auth_sessions.template.json",
            "reports/wechat_auth_domains.md",
        ],
    }
    (args.out_dir / "wechat_miniapp_discovery_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
