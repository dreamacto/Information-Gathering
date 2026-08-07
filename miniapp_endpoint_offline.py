from __future__ import annotations

import json
import os
import re
import sys
import argparse
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


DEFAULT_SOURCE = Path(r"C:\Users\ASUS\AppData\Local\Temp\wxapp_unpack\__APP__")
DEFAULT_OUT = Path(r"D:\PythonSource\PythonProjects\PythonProject4\runs\manual_wxapp_source_review_20260725")


TEXT_SUFFIXES = {
    ".js", ".json", ".wxml", ".wxss", ".xml", ".html", ".htm", ".txt", ".map",
    ".ts", ".vue", ".css", ".md",
}

URL_RE = re.compile(r"https?://[^\s\"'`<>\\)]+", re.I)
APPID_RE = re.compile(r"\bwx[a-f0-9]{12,32}\b", re.I)
ENDPOINT_RE = re.compile(
    r"(?P<quote>[\"'`])(?P<path>/(?:api|gateway|prod-api|mini|wx|wechat|app|water|user|system|sys|common|file|upload|download|login|register|operation|order|pay|card|student|member|visitor|repair)[^\"'`\s<>]*)\1",
    re.I,
)
QUOTED_VALUE_RE = re.compile(r"([\"'`])([^\"'`]{2,240})\1")
API_FRAGMENT_RE = re.compile(
    r"^(?:main|api|gateway|prod-api|mini|wx|wechat|app|water|user|system|sys|common|file|upload|download|login|register|operation|order|pay|card|student|member|visitor|repair|protocal)/[a-z0-9_./-]+$",
    re.I,
)
DIRECT_API_FRAGMENT_RE = re.compile(
    r"\b((?:main|api|gateway|prod-api|mini|wx|wechat|app|water|user|system|sys|common|file|upload|download|login|register|operation|order|pay|card|student|member|visitor|repair|protocal)/[A-Za-z0-9_./-]+)\b"
)
STATIC_PATH_RE = re.compile(r"\.(?:jpg|jpeg|png|gif|svg|css|wxss|wxml|html|htm|ico|woff|woff2|ttf)$", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|cn|net|org|edu|gov)(?::\d+)?\b", re.I)

SENSITIVE_VALUE_RE = re.compile(
    r"(?i)((?:access_?)?token|authorization|secret|appsecret|password|passwd|pwd|session_key|openid|unionid|key)\s*[:=]\s*([\"']?)[^\"'\s,;{}]{4,}\2"
)
HIGH_VALUE_RE = re.compile(
    r"(?i)(list|page|query|detail|info|user|member|student|phone|mobile|idcard|identity|realname|name|order|pay|fee|balance|card|water|operation|record|upload|download|export|admin|role|sys|login|register|sms|phoneNumber|getPhoneNumber|openid|unionid)"
)
AUTH_RE = re.compile(r"(?i)(token|authorization|cookie|session|login|openid|unionid|phoneNumber|getPhoneNumber|code2Session|session_key)")
SIGN_RE = re.compile(r"(?i)(sign|signature|sha256|sha1|md5|hmac|crypto|encrypt|decrypt|timestamp|nonce|salt|secret)")
WRITE_RE = re.compile(r"(?i)(upload|save|add|create|update|delete|remove|pay|submit|bind|register|login)")
SAFE_GET_RE = re.compile(r"(?i)(list|page|query|detail|info|get|search|record|order|card|user|member|student|consume)")
PLATFORM_HOST_RE = re.compile(r"(?i)(weixin\.qq\.com|mp\.weixin\.qq\.com|servicewechat\.com|qpic\.cn|qq\.com|wxaurl\.cn)$")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def setup() -> None:
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def redact(text: str) -> str:
    return SENSITIVE_VALUE_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)


def read_text(path: Path) -> str:
    try:
        if path.stat().st_size > 5_000_000:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        try:
            return path.read_text(encoding="gb18030", errors="replace")
        except Exception:
            return ""


def line_no(text: str, needle: str) -> int:
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def context_line(text: str, needle: str) -> str:
    for line in text.splitlines():
        if needle in line:
            return redact(line.strip())[:500]
    return ""


def score_endpoint(value: str) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    low = value.lower()
    if re.search(r"(list|page|query|search)", low):
        score += 25
        reasons.append("列表/分页/查询")
    if re.search(r"(detail|info|get)", low):
        score += 18
        reasons.append("详情/信息")
    if re.search(r"(user|member|student|openid|unionid|phone|mobile|idcard|identity)", low):
        score += 30
        reasons.append("用户/身份字段")
    if re.search(r"(order|pay|fee|balance|card|water|operation|record)", low):
        score += 28
        reasons.append("业务/交易/用水记录")
    if re.search(r"(admin|role|sys|permission)", low):
        score += 22
        reasons.append("后台/权限")
    if re.search(r"(upload|download|export|file)", low):
        score += 20
        reasons.append("文件/导出")
    if re.search(r"(login|register|sms|phoneNumber|code2Session)", low):
        score += 18
        reasons.append("登录/注册/手机号授权")
    if WRITE_RE.search(value):
        reasons.append("写入型仅人工判断")
    return score, reasons


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def origin_of(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def site_key(host: str) -> str:
    parts = [part for part in host.lower().split(".") if part]
    if len(parts) <= 2:
        return host.lower()
    tail2 = ".".join(parts[-2:])
    if tail2 in {"com.cn", "edu.cn", "gov.cn", "net.cn", "org.cn"} and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail2


def same_site(a: str, b: str) -> bool:
    return bool(a and b and site_key(a) == site_key(b))


def redact_url_values(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.query:
        return url
    query = urlencode([(key, "<value>") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))


def load_scope_hosts(path: Path | None) -> set[str]:
    if not path or not path.exists():
        return set()
    hosts: set[str] = set()
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return hosts
        items = data.get("targets") if isinstance(data, dict) else data
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    host = str(item.get("host") or host_of(str(item.get("url") or ""))).lower()
                    if host:
                        hosts.add(host)
    else:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            host = host_of(line.strip().split("|", 1)[0])
            if host:
                hosts.add(host)
    return hosts


def scope_state(host: str, scope_hosts: set[str]) -> str:
    if not host:
        return "relative_endpoint_manual_mapping_required"
    if not scope_hosts:
        return "ownership_confirmation_required"
    if any(host == item or same_site(host, item) for item in scope_hosts):
        return "in_current_scope"
    return "ownership_confirmation_required"


def safe_candidate_url(url: str) -> bool:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return False
    if STATIC_PATH_RE.search(parsed.path):
        return False
    if WRITE_RE.search(parsed.path):
        return False
    sensitive_query_keys = {"token", "authorization", "secret", "appsecret", "password", "passwd", "pwd", "session_key", "openid", "unionid", "key"}
    if any(key.lower() in sensitive_query_keys for key, _ in parse_qsl(parsed.query, keep_blank_values=True)):
        return False
    return bool(SAFE_GET_RE.search(parsed.path) or API_FRAGMENT_RE.search(parsed.path.lstrip("/")))


def append_jsonl_dedup(path: Path, rows: list[dict], key: str = "url") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_lines: list[str] = []
    seen: set[str] = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            existing_lines.append(line)
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                seen.add(str(item.get(key) or item.get("endpoint") or ""))
    new_lines: list[str] = []
    for row in rows:
        marker = str(row.get(key) or row.get("endpoint") or "")
        if not marker or marker in seen:
            continue
        seen.add(marker)
        new_lines.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
    path.write_text("\n".join(existing_lines + new_lines) + ("\n" if existing_lines or new_lines else ""), encoding="utf-8")


def build_api_candidates(url_rows: list[dict], endpoint_rows: list[dict], scope_hosts: set[str]) -> list[dict]:
    candidates: list[dict] = []
    origins: list[str] = []
    for row in url_rows:
        value = str(row.get("value") or "")
        origin = origin_of(value)
        host = host_of(value)
        if origin and host and not PLATFORM_HOST_RE.search(host) and origin not in origins:
            origins.append(origin)
    origins = origins[:5]

    for row in url_rows:
        url = str(row.get("value") or "").rstrip(".,;")
        if not safe_candidate_url(url):
            continue
        score, reasons = score_endpoint(urlparse(url).path)
        host = host_of(url)
        candidates.append({
            "checked_at": now_iso(),
            "base_url": origin_of(url),
            "url": url,
            "redacted_url": redact_url_values(url),
            "method": "GET",
            "host": host,
            "scope_state": scope_state(host, scope_hosts),
            "source": "miniapp_source_offline",
            "source_detail": f"{row.get('file')}:{row.get('line')}",
            "priority_score": min(100, score + 10),
            "tags": ["miniapp_source", "api"],
            "reasons": reasons or ["源码绝对 URL"],
            "manual_next_step": "先确认小程序后端归属；登录态接口不要批量改 ID，优先在 Burp 里做当前账号只读复核。",
        })

    for row in endpoint_rows[:120]:
        endpoint = str(row.get("endpoint") or "")
        if not endpoint or STATIC_PATH_RE.search(endpoint) or WRITE_RE.search(endpoint):
            continue
        if not origins:
            candidates.append({
                "checked_at": now_iso(),
                "endpoint": endpoint,
                "url": "",
                "method": "GET",
                "scope_state": "relative_endpoint_manual_mapping_required",
                "source": "miniapp_source_offline",
                "priority_score": int(row.get("score") or 0),
                "tags": ["miniapp_source", "relative_api"],
                "reasons": row.get("reasons") or [],
                "manual_next_step": "需要先从 Burp 或源码配置确认 base URL，再进入主流程。",
            })
            continue
        for origin in origins:
            url = urljoin(origin + "/", endpoint.lstrip("/"))
            if not safe_candidate_url(url):
                continue
            host = host_of(url)
            candidates.append({
                "checked_at": now_iso(),
                "base_url": origin,
                "url": url,
                "redacted_url": redact_url_values(url),
                "method": "GET",
                "host": host,
                "scope_state": scope_state(host, scope_hosts),
                "source": "miniapp_source_offline",
                "source_detail": "relative_endpoint_plus_source_origin",
                "priority_score": int(row.get("score") or 0),
                "tags": ["miniapp_source", "api"],
                "reasons": row.get("reasons") or [],
                "manual_next_step": "先确认该 origin 确属目标单位；登录态接口不要批量改 ID，优先在 Burp 里做当前账号只读复核。",
            })
    by_url: dict[str, dict] = {}
    for row in candidates:
        marker = str(row.get("url") or row.get("endpoint") or "")
        old = by_url.get(marker)
        if not old or int(row.get("priority_score") or 0) > int(old.get("priority_score") or 0):
            by_url[marker] = row
    return sorted(by_url.values(), key=lambda item: (-int(item.get("priority_score") or 0), item.get("url") or item.get("endpoint") or ""))


def add_endpoint(endpoints: dict[str, dict], value: str, rel: str, text: str) -> None:
    clean = value.strip()
    if not clean or len(clean) > 220:
        return
    if STATIC_PATH_RE.search(clean):
        return
    normalized = clean if clean.startswith("/") else "/" + clean
    score, reasons = score_endpoint(normalized)
    row = endpoints.setdefault(normalized, {
        "endpoint": normalized,
        "score": score,
        "reasons": reasons,
        "files": [],
        "write_or_auth_related": bool(WRITE_RE.search(normalized)),
    })
    if len(row["files"]) < 8:
        row["files"].append({"file": rel, "line": line_no(text, value), "context": context_line(text, value)})
    row["score"] = max(row["score"], score)
    row["reasons"] = sorted(set(row["reasons"]) | set(reasons))


def main() -> int:
    setup()
    parser = argparse.ArgumentParser(description="Offline WeChat mini-program source endpoint extractor")
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--scope-targets", type=Path, default=None)
    parser.add_argument("--api-candidates-out", type=Path, default=None)
    parser.add_argument("--in-scope-api-candidates-out", type=Path, default=None)
    parser.add_argument("--pending-assets-out", type=Path, default=None)
    parser.add_argument("--append-api-candidates", action="store_true")
    args = parser.parse_args()
    root = args.source_dir
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    print(f"source_dir={root}")
    if not root.exists():
        print("missing_source_dir=true")
        return 2

    files = [p for p in root.rglob("*") if p.is_file()]
    ext_counts = Counter(p.suffix.lower() or "<none>" for p in files)
    text_files = [p for p in files if p.suffix.lower() in TEXT_SUFFIXES or p.name in {"app-config.json", "app-service.js"}]

    urls: dict[str, dict] = {}
    domains = Counter()
    appids = Counter()
    endpoints: dict[str, dict] = {}
    interesting: list[dict] = []
    sign_hits: list[dict] = []
    auth_hits: list[dict] = []
    tree_preview: list[str] = []

    for path in sorted(files, key=lambda p: str(p).lower()):
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        if len(tree_preview) < 200:
            tree_preview.append(rel)

    for path in text_files:
        text = read_text(path)
        if not text:
            continue
        rel = str(path.relative_to(root))

        for match in URL_RE.finditer(text):
            value = match.group(0).rstrip(".,;")
            host = urlparse(value).netloc.lower()
            if host:
                domains[host] += 1
            urls.setdefault(value, {
                "value": value,
                "host": host,
                "file": rel,
                "line": line_no(text, value),
                "context": context_line(text, value),
            })

        for match in DOMAIN_RE.finditer(text):
            host = match.group(0).lower()
            domains[host] += 1

        for match in APPID_RE.finditer(text):
            value = match.group(0)
            appids[value] += 1

        for match in ENDPOINT_RE.finditer(text):
            value = match.group("path")
            add_endpoint(endpoints, value, rel, text)

        for match in QUOTED_VALUE_RE.finditer(text):
            value = match.group(2).strip()
            if API_FRAGMENT_RE.search(value):
                add_endpoint(endpoints, value, rel, text)

        for match in DIRECT_API_FRAGMENT_RE.finditer(text):
            add_endpoint(endpoints, match.group(1), rel, text)

        for idx, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if len(stripped) > 1000:
                continue
            if HIGH_VALUE_RE.search(stripped):
                if len(interesting) < 500:
                    interesting.append({"file": rel, "line": idx, "kind": "high_value_keyword", "text": redact(stripped)[:500]})
            if SIGN_RE.search(stripped) or "createSign" in stripped:
                if len(sign_hits) < 200:
                    sign_hits.append({"file": rel, "line": idx, "text": redact(stripped)[:500]})
            if AUTH_RE.search(stripped):
                if len(auth_hits) < 200:
                    auth_hits.append({"file": rel, "line": idx, "text": redact(stripped)[:500]})

    endpoint_rows = sorted(endpoints.values(), key=lambda r: (-int(r["score"]), r["endpoint"]))[:300]
    url_rows = sorted(urls.values(), key=lambda r: (r["host"], r["value"]))[:300]
    domain_rows = [{"domain": d, "count": c} for d, c in domains.most_common(200)]
    appid_rows = [{"appid": a, "count": c} for a, c in appids.most_common(50)]
    scope_hosts = load_scope_hosts(args.scope_targets)
    api_candidate_rows = build_api_candidates(url_rows, endpoint_rows, scope_hosts)
    in_scope_rows = [row for row in api_candidate_rows if row.get("scope_state") == "in_current_scope" and row.get("url")]
    pending_hosts = sorted({
        str(row.get("host") or "")
        for row in api_candidate_rows
        if row.get("scope_state") == "ownership_confirmation_required" and row.get("host")
    })

    summary = {
        "source_dir": str(root),
        "file_count": len(files),
        "text_file_count": len(text_files),
        "extension_counts": dict(ext_counts),
        "appid_candidates": appid_rows,
        "domain_count": len(domains),
        "url_count": len(urls),
        "endpoint_count": len(endpoints),
        "high_value_endpoint_count": sum(1 for r in endpoints.values() if int(r["score"]) >= 50),
        "sign_hit_count": len(sign_hits),
        "auth_hit_count": len(auth_hits),
        "api_candidate_count": len(api_candidate_rows),
        "in_scope_api_candidate_count": len(in_scope_rows),
        "pending_asset_count": len(pending_hosts),
    }

    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "domains.json").write_text(json.dumps(domain_rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "urls.redacted.json").write_text(json.dumps(url_rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "endpoints.redacted.json").write_text(json.dumps(endpoint_rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "miniapp_api_candidates.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in api_candidate_rows),
        encoding="utf-8",
    )
    (out / "sign_hits.redacted.json").write_text(json.dumps(sign_hits, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "auth_hits.redacted.json").write_text(json.dumps(auth_hits, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "miniapp_new_assets_pending.txt").write_text("\n".join(pending_hosts) + ("\n" if pending_hosts else ""), encoding="utf-8")
    if args.api_candidates_out:
        append_jsonl_dedup(args.api_candidates_out, api_candidate_rows)
    if args.in_scope_api_candidates_out:
        append_jsonl_dedup(args.in_scope_api_candidates_out, in_scope_rows)
    if args.pending_assets_out:
        existing = args.pending_assets_out.read_text(encoding="utf-8", errors="replace").splitlines() if args.pending_assets_out.exists() else []
        merged = sorted(set([line.strip() for line in existing if line.strip()] + pending_hosts))
        args.pending_assets_out.write_text("\n".join(merged) + ("\n" if merged else ""), encoding="utf-8")

    md: list[str] = []
    md.append("# 微信小程序源码离线分析")
    md.append("")
    md.append(f"- 源目录：`{root}`")
    md.append(f"- 文件数：{len(files)}，文本文件：{len(text_files)}")
    md.append(f"- 域名数：{len(domains)}，URL 数：{len(urls)}，接口候选数：{len(endpoints)}")
    md.append(f"- 高价值接口候选：{summary['high_value_endpoint_count']}")
    md.append(f"- 主流程 API 候选：{len(api_candidate_rows)}，当前范围内：{len(in_scope_rows)}，待归属确认域名：{len(pending_hosts)}")
    md.append("")
    md.append("## AppID")
    md.append("")
    md.extend([f"- `{row['appid']}`：{row['count']} 次" for row in appid_rows[:20]] or ["_未发现_"])
    md.append("")
    md.append("## 域名 TOP")
    md.append("")
    md.extend([f"- `{row['domain']}`：{row['count']} 次" for row in domain_rows[:40]] or ["_未发现_"])
    md.append("")
    md.append("## 高价值接口候选")
    md.append("")
    for row in endpoint_rows[:80]:
        if int(row["score"]) < 20:
            continue
        first = row["files"][0] if row["files"] else {}
        md.append(f"- score={row['score']} `{row['endpoint']}`")
        md.append(f"  - 原因：{'；'.join(row['reasons']) or '接口候选'}")
        if first:
            md.append(f"  - 位置：`{first.get('file')}:{first.get('line')}`")
    md.append("")
    md.append("## 可接入主流程的 API 候选")
    md.append("")
    for row in api_candidate_rows[:80]:
        shown = row.get("redacted_url") or row.get("endpoint") or row.get("url")
        md.append(f"- score={row.get('priority_score')} scope={row.get('scope_state')} `{shown}`")
        md.append(f"  - 原因：{'；'.join(row.get('reasons') or []) or '源码接口候选'}")
    md.append("")
    md.append("## Sign / 加密 / 鉴权线索")
    md.append("")
    for row in sign_hits[:60]:
        md.append(f"- `{row['file']}:{row['line']}` {row['text']}")
    md.append("")
    md.append("## 登录 / Token / OpenID 线索")
    md.append("")
    for row in auth_hits[:60]:
        md.append(f"- `{row['file']}:{row['line']}` {row['text']}")
    md.append("")
    md.append("## 文件树预览")
    md.append("")
    md.extend([f"- `{item}`" for item in tree_preview[:120]])
    md.append("")
    md.append("## 边界")
    md.append("")
    md.append("本分析只做离线源码与接口地图提取。未访问后端接口，未保存响应正文，疑似凭据值已脱敏。")
    (out / "微信小程序源码离线分析.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"report={out / '微信小程序源码离线分析.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
