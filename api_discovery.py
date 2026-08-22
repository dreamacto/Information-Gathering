#!/usr/bin/env python3
"""Read-only JS/API discovery and impact triage.

This module is intentionally focused on evidence-producing discovery instead of
fixed path existence checks. It fetches home/robots/sitemap, extracts JavaScript
assets and API-looking routes, lightly confirms JSON/OpenAPI endpoints, and
scores targets that are worth manual review.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse


USER_AGENT = "Authorized-ReadOnly-API-Discovery/1.0"

SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
HREF_RE = re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"']", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+\.map)", re.I)
ENDPOINT_RE = re.compile(
    r"""(?:"|')("""
    r"""(?:https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)|"""
    r"""(?:/(?:api|apis|gateway|service|services|auth|oauth|sso|login|logout|admin|"""
    r"""system|portal|eportal|open|rest|v\d+|upload|file|download|common|user|org|"""
    r"""dept|dict|search|query|list|page|export|import|data|business|workflow|"""
    r"""approval|apply|matter|zwfw|oauth2|cas)[A-Za-z0-9_./?=&:%#,+;\-]*)"""
    r""")(?:"|')""",
    re.I,
)
OPENAPI_HINT_RE = re.compile(r"(swagger|openapi|api-docs|swagger-ui|knife4j|doc\.html)", re.I)
SENSITIVE_NAME_RE = re.compile(
    r"(password|passwd|pwd|secret|token|apikey|api_key|access[_-]?key|private|"
    r"connectionstring|jdbc|datasource|mysql|oracle|redis|mongodb|user(name)?|"
    r"idcard|phone|mobile|email|address|身份证|手机号|电话|姓名)",
    re.I,
)
STATIC_EXT_RE = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|map|mp4|pdf|docx?|xlsx?)(?:[?#].*)?$", re.I)
NOISE_TITLE_RE = re.compile(r"(404|not found|访问出错|访问禁止|error|forbidden|login|登录)", re.I)

BUSINESS_VALUE_KEYWORDS: list[tuple[str, int, str]] = [
    ("patient", 6, "patient_data"),
    ("patients", 6, "patient_data"),
    ("doctor", 5, "medical_staff"),
    ("hospital", 5, "medical_org"),
    ("medical", 4, "medical_business"),
    ("idcard", 6, "identity_field"),
    ("id_card", 6, "identity_field"),
    ("身份证", 6, "identity_field"),
    ("mobile", 5, "phone_field"),
    ("phone", 5, "phone_field"),
    ("手机号", 5, "phone_field"),
    ("realname", 5, "name_field"),
    ("name", 2, "name_field"),
    ("姓名", 5, "name_field"),
    ("user", 4, "user_account"),
    ("users", 4, "user_account"),
    ("account", 4, "user_account"),
    ("person", 4, "person_data"),
    ("people", 4, "person_data"),
    ("org", 3, "organization"),
    ("dept", 3, "department"),
    ("institution", 4, "organization"),
    ("role", 4, "permission"),
    ("permission", 5, "permission"),
    ("menu", 3, "permission"),
    ("record", 4, "record"),
    ("records", 4, "record"),
    ("detail", 3, "detail"),
    ("info", 3, "detail"),
    ("list", 3, "list_query"),
    ("page", 3, "list_query"),
    ("query", 3, "query"),
    ("search", 3, "query"),
    ("order", 3, "order_or_payment"),
    ("payment", 5, "order_or_payment"),
    ("pay", 4, "order_or_payment"),
    ("bill", 4, "finance"),
    ("invoice", 4, "finance"),
    ("finance", 5, "finance"),
    ("audit", 4, "workflow"),
    ("approve", 4, "workflow"),
    ("workflow", 4, "workflow"),
    ("export", 4, "bulk_export_risk"),
    ("download", 4, "bulk_export_risk"),
]


@dataclass
class FetchResult:
    url: str
    status: int = 0
    final_url: str = ""
    content_type: str = ""
    content_length: str = ""
    elapsed_seconds: float = 0.0
    sample_sha256: str = ""
    text: str = ""
    error: str = ""
    tool_used: str = "curl"


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def title_of(text: str) -> str:
    match = TITLE_RE.search(text)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160]


def parse_headers(raw: str) -> dict[str, str]:
    blocks = [block for block in raw.replace("\r\n", "\n").split("\n\n") if block.strip()]
    block = blocks[-1] if blocks else ""
    headers: dict[str, str] = {}
    for line in block.splitlines()[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return headers


def fetch(url: str, timeout: int, connect_timeout: int, tmp_dir: Path,
          extra_headers: dict | None = None) -> FetchResult:
    curl = shutil.which("curl.exe") or shutil.which("curl")
    result = FetchResult(url=url, final_url=url)
    if not curl:
        result.error = "curl_not_found"
        return result
    tmp_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False) as body_f, tempfile.NamedTemporaryFile(
        dir=tmp_dir, delete=False
    ) as header_f:
        body_path = Path(body_f.name)
        header_path = Path(header_f.name)
    extra = dict(extra_headers or {})
    ua = extra.pop("user-agent", None) or extra.pop("User-Agent", None)
    cmd = [
        curl,
        "-k",
        "-L",
        "--silent",
        "--show-error",
        "--max-time",
        str(timeout),
        "--connect-timeout",
        str(connect_timeout),
        "--range",
        "0-1048575",
        "-A",
        ua if ua else USER_AGENT,
        "-D",
        str(header_path),
        "-o",
        str(body_path),
        "-w",
        "%{http_code} %{url_effective} %{time_total}",
    ]
    for name, value in extra.items():
        cmd.extend(["-H", f"{name}: {value}"])
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3, check=False)
        parts = proc.stdout.strip().split(" ", 2)
        result.status = int(parts[0]) if parts and parts[0].isdigit() else 0
        result.final_url = parts[1] if len(parts) > 1 else url
        result.elapsed_seconds = float(parts[2]) if len(parts) > 2 else 0.0
        body = body_path.read_bytes() if body_path.exists() else b""
        headers_raw = header_path.read_text(encoding="utf-8", errors="ignore") if header_path.exists() else ""
        headers = parse_headers(headers_raw)
        ctype = headers.get("content-type", "")
        charset = "utf-8"
        charset_match = re.search(r"charset=([^;\s]+)", ctype, re.I)
        if charset_match:
            charset = charset_match.group(1)
        result.content_type = ctype
        result.content_length = headers.get("content-length", "")
        result.sample_sha256 = sha256(body[:65536])
        result.text = body.decode(charset, errors="ignore")
        if proc.returncode not in (0,):
            result.error = proc.stderr.strip()[:300]
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)[:300]
    finally:
        for path in (body_path, header_path):
            try:
                path.unlink()
            except OSError:
                pass
    return result


def configured_tool_path(name: str) -> str:
    config_path = Path(__file__).with_name("config.py")
    if not config_path.exists():
        return ""
    try:
        spec = importlib.util.spec_from_file_location("local_project_config", config_path)
        if not spec or not spec.loader:
            return ""
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tool_path = getattr(module, "tool_path", None)
        if callable(tool_path):
            value = tool_path(name)
            if value and Path(value).exists():
                return str(value)
    except Exception:
        return ""
    return ""


def find_tool(name: str, aliases: list[str] | None = None) -> str:
    names = [name] + (aliases or [])
    for candidate in names:
        path = shutil.which(candidate) or shutil.which(candidate + ".exe")
        if path:
            return path
    for candidate in names:
        path = configured_tool_path(candidate)
        if path:
            return path
    local = Path(__file__).with_name("tools") / (name + ".exe")
    if local.exists():
        return str(local)
    return ""


def fetch_record(result: FetchResult, family: str, path: str = "") -> dict:
    return {
        "checked_at": now_iso(),
        "family": family,
        "url": result.url,
        "path": path,
        "status": result.status,
        "final_url": result.final_url,
        "content_type": result.content_type,
        "content_length": result.content_length,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "sample_sha256": result.sample_sha256,
        "title": title_of(result.text),
        "error": result.error,
        "tool_used": result.tool_used,
    }


def normalize_url(base_url: str, value: str) -> str:
    value = value.strip()
    if not value or value.startswith(("javascript:", "mailto:", "tel:", "#")):
        return ""
    return urljoin(base_url.rstrip("/") + "/", value)


def in_same_host(base_url: str, url: str) -> bool:
    base_host = urlparse(base_url).hostname or ""
    host = urlparse(url).hostname or ""
    return host == base_host


def extract_assets(base_url: str, html: str) -> tuple[set[str], set[str], set[str]]:
    scripts: set[str] = set()
    links: set[str] = set()
    endpoints: set[str] = set()
    for match in SCRIPT_RE.finditer(html):
        url = normalize_url(base_url, match.group(1))
        if url and in_same_host(base_url, url):
            scripts.add(url)
    for match in HREF_RE.finditer(html):
        url = normalize_url(base_url, match.group(1))
        if url and in_same_host(base_url, url) and not STATIC_EXT_RE.search(url):
            links.add(url)
    for match in ENDPOINT_RE.finditer(html):
        url = normalize_url(base_url, match.group(1))
        if url and in_same_host(base_url, url) and not STATIC_EXT_RE.search(url):
            endpoints.add(url)
    return scripts, links, endpoints


# 第三方前端库 denylist（20260822 首跑复盘 P0-3）：jquery/bootstrap/swiper 等压缩库里的
# mobile/user/password/token 关键词命中是纯噪声，59 条 impact 候选里 54 条来自它们。
THIRD_PARTY_JS_RE = re.compile(
    r"(?:^|[/.\-])"
    r"(?:jquery|bootstrap|swiper|tweenmax|nicescroll|layui|element[-.]?(?:ui|plus)|"
    r"vue(?:\.runtime)?|react|angular|axios|echarts|antd|vant|webpack|polyfill|"
    r"modernizr|underscore|moment|dayjs|lodash|animate|slick|owl\.carousel|wow|jweixin)"
    r"(?:[/.\-]|$)",
    re.I,
)


def extract_js_findings(base_url: str, js_url: str, text: str) -> tuple[set[str], set[str], list[dict]]:
    endpoints: set[str] = set()
    source_maps: set[str] = set()
    secrets: list[dict] = []
    for match in ENDPOINT_RE.finditer(text):
        url = normalize_url(base_url, match.group(1))
        if url and in_same_host(base_url, url) and not STATIC_EXT_RE.search(url):
            endpoints.add(url)
    for match in SOURCE_MAP_RE.finditer(text):
        map_url = normalize_url(js_url, match.group(1))
        if map_url and in_same_host(base_url, map_url):
            source_maps.add(map_url)
    for match in SENSITIVE_NAME_RE.finditer(text):
        start = max(0, match.start() - 90)
        end = min(len(text), match.end() + 140)
        snippet = text[start:end].replace("\n", " ")[:260]
        snippet = re.sub(r"(?i)(password|passwd|pwd|secret|token|apikey|api_key|access[_-]?key)(\s*[:=]\s*)([^&\s\"']+)", r"\1\2<redacted>", snippet)
        secrets.append({"source": js_url, "keyword": match.group(1), "snippet": snippet})
        if len(secrets) >= 20:
            break
    return endpoints, source_maps, secrets


def business_value_score(*values: object) -> dict:
    text = " ".join(
        " ".join(str(item) for item in value) if isinstance(value, (list, tuple, set)) else str(value or "")
        for value in values
    ).lower()
    score = 0
    reasons: list[str] = []
    tags: list[str] = []
    for keyword, weight, tag in BUSINESS_VALUE_KEYWORDS:
        if keyword.lower() in text:
            score += weight
            reasons.append(keyword)
            tags.append(tag)
    return {
        "business_value_score": min(30, score),
        "business_value_reasons": sorted(set(reasons))[:20],
        "business_tags": sorted(set(tags)),
    }


def classify_endpoint(url: str) -> dict:
    lower = url.lower()
    tags = []
    score = 0
    if OPENAPI_HINT_RE.search(lower):
        tags.append("openapi_or_docs")
        score += 5
    if any(x in lower for x in ("/login", "/sso", "/auth", "/oauth", "/cas")):
        tags.append("auth_or_login")
        score += 3
    if any(x in lower for x in ("/upload", "/file", "/download", "/export", "/import")):
        tags.append("file_or_upload")
        score += 4
    if any(x in lower for x in ("/admin", "/system", "/manage", "/portal")):
        tags.append("admin_or_portal")
        score += 4
    if any(x in lower for x in ("/api", "/service", "/gateway", "/rest", "/v1/", "/v2/", "/v3/")):
        tags.append("api")
        score += 3
    if any(x in lower for x in ("/user", "/org", "/dept", "/dict", "/list", "/page", "/query", "/search")):
        tags.append("data_query")
        score += 3
    if any(x in lower for x in ("test", "dev", "debug", "swagger", "doc.html")):
        tags.append("dev_or_test")
        score += 2
    business = business_value_score(url)
    score += min(15, int(business["business_value_score"]))
    tags.extend(business["business_tags"])
    return {"url": url, "tags": sorted(set(tags)), "priority_score": score, **business}


def analyze_openapi(result: FetchResult) -> dict:
    out = {
        "is_json": "json" in result.content_type.lower() or result.text.strip().startswith("{"),
        "path_count": 0,
        "sample_paths": [],
        "sensitive_path_count": 0,
    }
    if not out["is_json"]:
        return out
    try:
        parsed = json.loads(result.text)
    except Exception:
        return out
    paths = parsed.get("paths") if isinstance(parsed, dict) else None
    if isinstance(paths, dict):
        keys = list(paths.keys())
        out["path_count"] = len(keys)
        out["sample_paths"] = keys[:25]
        out["sensitive_path_count"] = sum(1 for key in keys if classify_endpoint(key)["priority_score"] >= 4)
    return out


def discover_target(base_url: str, out_dir: Path, delay: float, timeout: int, max_js: int) -> None:
    tmp_dir = out_dir / ".api_tmp"
    discovery_path = out_dir / "api_discovery.jsonl"
    endpoints_path = out_dir / "api_candidates.jsonl"
    impact_path = out_dir / "impact_candidates.jsonl"

    base_url = base_url.rstrip("/")
    seed_paths = ["/", "/robots.txt", "/sitemap.xml", "/v2/api-docs", "/v3/api-docs", "/swagger-resources", "/doc.html"]
    scripts: set[str] = set()
    links: set[str] = set()
    endpoints: set[str] = set()

    for seed in seed_paths:
        url = urljoin(base_url + "/", seed.lstrip("/"))
        result = fetch(url, timeout, min(4, timeout), tmp_dir)
        record = fetch_record(result, "seed", seed)
        record["base_url"] = base_url
        append_jsonl(discovery_path, record)
        if result.status in (200, 206) and result.text:
            new_scripts, new_links, new_endpoints = extract_assets(base_url, result.text)
            scripts.update(new_scripts)
            links.update(new_links)
            endpoints.update(new_endpoints)
            if OPENAPI_HINT_RE.search(seed):
                openapi = analyze_openapi(result)
                if openapi["path_count"] > 0:
                    impact = dict(record)
                    impact.update({"finding": "openapi_json_with_paths", **openapi, "priority": "high"})
                    append_jsonl(impact_path, impact)
                elif openapi["is_json"]:
                    impact = dict(record)
                    impact.update({"finding": "openapi_json_empty_or_no_paths", **openapi, "priority": "low"})
                    append_jsonl(impact_path, impact)
        time.sleep(delay)

    for js_url in sorted(scripts)[:max_js]:
        result = fetch(js_url, timeout, min(4, timeout), tmp_dir)
        record = fetch_record(result, "javascript", urlparse(js_url).path)
        record["base_url"] = base_url
        append_jsonl(discovery_path, record)
        if result.status in (200, 206) and result.text:
            eps, maps, secrets = extract_js_findings(base_url, js_url, result.text)
            endpoints.update(eps)
            for map_url in sorted(maps):
                impact = {
                    "checked_at": now_iso(),
                    "base_url": base_url,
                    "finding": "source_map_reference",
                    "url": map_url,
                    "source": js_url,
                    "priority": "medium",
                }
                append_jsonl(impact_path, impact)
            # 第三方库的关键词命中直接丢弃；自研 JS 按 (source, keyword) 去重
            if THIRD_PARTY_JS_RE.search(js_url):
                secrets = []
            deduped, seen = [], set()
            for secret in secrets:
                key = (secret.get("source"), (secret.get("keyword") or "").lower())
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(secret)
            for secret in deduped[:10]:
                impact = {
                    "checked_at": now_iso(),
                    "base_url": base_url,
                    "finding": "js_sensitive_keyword",
                    "priority": "review",
                    **secret,
                }
                append_jsonl(impact_path, impact)
        time.sleep(delay)

    for endpoint in sorted(endpoints | links):
        classified = classify_endpoint(endpoint)
        row = {
            "checked_at": now_iso(),
            "base_url": base_url,
            **classified,
        }
        append_jsonl(endpoints_path, row)
        if classified["priority_score"] >= 5:
            impact = dict(row)
            impact.update({"finding": "high_priority_endpoint", "priority": "medium"})
            append_jsonl(impact_path, impact)


def run_katana_if_available(targets: list[str], out_dir: Path, delay: float) -> None:
    katana = find_tool("katana")
    if not katana:
        return
    target_file = out_dir / "katana_targets.txt"
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    output_file = out_dir / "katana_urls.txt"
    cmd = [
        katana,
        "-list",
        str(target_file),
        "-silent",
        "-jc",
        "-kf",
        "all",
        "-d",
        "2",
        "-c",
        "1",
        "-p",
        "1",
        "-rl",
        "1",
        "-delay",
        f"{max(1, int(delay))}s",
        "-o",
        str(output_file),
    ]
    try:
        subprocess.run(cmd, cwd=str(out_dir), timeout=1800, check=False)
    except Exception as exc:  # noqa: BLE001
        append_jsonl(out_dir / "api_discovery_tool_errors.jsonl", {
            "checked_at": now_iso(),
            "tool": "katana",
            "error": str(exc)[:300],
        })


def load_targets(path: Path) -> list[str]:
    targets = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        value = value.split("|", 1)[0].strip()
        if not value.startswith(("http://", "https://")):
            value = "https://" + value
        targets.append(value.rstrip("/"))
    return sorted(set(targets))


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only JS/API discovery and impact triage")
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=2.0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--max-js", type=int, default=20)
    parser.add_argument("--use-katana", action="store_true", help="Use katana if installed, then built-in parser")
    args = parser.parse_args()

    targets = load_targets(args.targets)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "created_at": now_iso(),
        "targets": str(args.targets),
        "target_count": len(targets),
        "delay": args.delay,
        "timeout": args.timeout,
        "tools": {
            "curl": shutil.which("curl.exe") or shutil.which("curl"),
            "katana": find_tool("katana"),
            "httpx": find_tool("httpx"),
            "nuclei": find_tool("nuclei"),
            "afrog": find_tool("afrog"),
            "packerfuzzer": find_tool("packerfuzzer"),
            "api_tool": find_tool("api_tool"),
            "api_explorer": find_tool("api_explorer"),
        },
    }
    (args.out_dir / "api_discovery_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.use_katana:
        run_katana_if_available(targets, args.out_dir, args.delay)
    for target in targets:
        discover_target(target, args.out_dir, args.delay, args.timeout, args.max_js)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
