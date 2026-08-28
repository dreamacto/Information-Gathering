from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import argparse
import base64
import csv
import hashlib
import html
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, quote_plus, urlencode, urlparse, urlunparse
from xml.etree import ElementTree


URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
REQUEST_LINE_RE = re.compile(r"(?im)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/\d(?:\.\d)?")
HOST_RE = re.compile(r"(?im)^Host:\s*([^\s\r\n]+)")
TABLE_ROW_RE = re.compile(
    r"(?i)(?:^\s*\d+\s+)?(?P<host>https?://[^\s\t]+|[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?)\s+"
    r"(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?P<url>https?://[^\s\t]+|/[^\s\t]+)"
)
API_PATH_RE = re.compile(
    r"(?i)(/api/|/apis/|/gateway/|/prod-api/|/mini|/wx|/wechat|/weixin|/app/|/user|/member|/student|"
    r"/order|/pay|/card|/repair|/consume|/list|/page|/query|/detail|/info|/login|/register)"
)
SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(realname|real_name|name|姓名|mobile|phone|tel|手机号|电话|idcard|id_card|identity|身份证|"
    r"student|学号|user.?id|open.?id|union.?id|address|地址|room|宿舍|dorm|balance|余额|amount|金额|"
    r"pay|payment|缴费|order|订单|consume|repair|visitor|parent|email|mail)"
)
OBJECT_ID_HINT_RE = re.compile(
    r"(?i)(^|[._-])(id|user.?id|student.?id|stu.?id|order.?id|repair.?id|record.?id|card.?no|card.?id|"
    r"open.?id|union.?id|phone|mobile|sfz|idcard|identity|member.?id)([._-]|$)"
)
UNSAFE_PATH_RE = re.compile(r"(?i)(/delete|/remove|/update|/save|/create|/add|/submit|/pay|/refund|/upload|/import|/logout)")
STATIC_RE = re.compile(r"(?i)\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map)(?:[?#].*)?$")


@dataclass(frozen=True)
class TargetSeed:
    url: str
    name: str
    host: str


def setup_console() -> None:
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def normalize_url(value: str) -> str:
    value = value.strip().lstrip("\ufeff")
    if not value:
        return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
        value = "https://" + value
    return value


def site_key(host: str) -> str:
    parts = [p for p in host.lower().split(".") if p]
    if len(parts) <= 2:
        return host.lower()
    tail2 = ".".join(parts[-2:])
    if tail2 in {"com.cn", "edu.cn", "gov.cn", "net.cn", "org.cn"} and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail2


def same_site(a: str, b: str) -> bool:
    return bool(a and b and site_key(a) == site_key(b))


def redacted_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.query:
        return url
    query = urlencode([(key, "<value>") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))


def load_targets(path: Path) -> list[TargetSeed]:
    rows: list[TargetSeed] = []
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            for row in csv.DictReader(handle):
                url = normalize_url(str(row.get("url") or ""))
                host = str(row.get("host") or host_of(url)).lower()
                if url and host:
                    rows.append(TargetSeed(url=url, name=str(row.get("name") or ""), host=host))
        return rows
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [part.strip() for part in line.split("|")]
            url = normalize_url(parts[0])
            host = host_of(url)
            if url and host:
                rows.append(TargetSeed(url=url, name=parts[1] if len(parts) > 1 else "", host=host))
    return rows


def compact_name(name: str) -> str:
    name = re.sub(r"\s+", "", name or "")
    name = re.sub(r"(有限责任公司|有限公司|股份有限公司|学校|学院|医院|中心|委员会|管理局|人民政府)$", "", name)
    return name


def seed_keywords(targets: list[TargetSeed]) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for target in targets:
        host_root = site_key(target.host)
        host_token = host_root.split(".", 1)[0]
        seeds = [target.name, compact_name(target.name), host_root, host_token]
        for seed in [item for item in seeds if item]:
            for keyword in [
                seed,
                f"{seed} 小程序",
                f"{seed} 微信小程序",
                f"{seed} 公众号",
                f"{seed} 掌上",
                f"{seed} 移动端",
                f"{seed} 缴费",
                f"{seed} 报修",
                f"{seed} site:mp.weixin.qq.com",
                f"{seed} site:wxaurl.cn",
            ]:
                key = (target.host, keyword)
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "target_host": target.host,
                    "target_name": target.name,
                    "keyword": keyword,
                    "wechat_search": keyword,
                    "bing": f"https://www.bing.com/search?q={quote_plus(keyword)}",
                    "baidu": f"https://www.baidu.com/s?wd={quote_plus(keyword)}",
                })
    return rows


def decode_burp_request(value: str, is_base64: bool) -> str:
    if not value:
        return ""
    if is_base64:
        try:
            return base64.b64decode(value).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return value


def extract_from_raw_http(text: str, source: Path) -> list[dict]:
    rows: list[dict] = []
    for match in REQUEST_LINE_RE.finditer(text):
        method, raw_target = match.group(1).upper(), match.group(2)
        if raw_target.startswith(("http://", "https://")):
            url = raw_target
        else:
            window = text[match.start(): match.start() + 4000]
            host_match = HOST_RE.search(window)
            if not host_match:
                continue
            url = f"https://{host_match.group(1).strip()}{raw_target if raw_target.startswith('/') else '/' + raw_target}"
        rows.append({"method": method, "url": url, "source": str(source), "source_kind": "raw_http"})
    return rows


def combine_host_and_path(host_value: str, url_value: str) -> str:
    host_value = host_value.strip()
    url_value = url_value.strip()
    if url_value.startswith(("http://", "https://")):
        return url_value
    if not url_value.startswith("/"):
        return ""
    if host_value.startswith(("http://", "https://")):
        return host_value.rstrip("/") + url_value
    return "https://" + host_value.rstrip("/") + url_value


def extract_from_copied_history_table(text: str, source: Path) -> list[dict]:
    rows: list[dict] = []
    for line in text.splitlines():
        if "..." in line or "…" in line:
            continue
        parts = [part.strip() for part in line.split("\t")]
        if len(parts) >= 3:
            host_index = next((idx for idx, part in enumerate(parts) if part.startswith(("http://", "https://")) or re.search(r"(?i)^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?$", part)), -1)
            method_index = next((idx for idx, part in enumerate(parts) if part.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}), -1)
            if host_index >= 0 and method_index >= 0:
                url_index = next(
                    (idx for idx in range(method_index + 1, len(parts)) if parts[idx].startswith(("/", "http://", "https://"))),
                    -1,
                )
                if url_index >= 0:
                    url = combine_host_and_path(parts[host_index], parts[url_index])
                    if url:
                        rows.append({
                            "method": parts[method_index].upper(),
                            "url": url,
                            "source": str(source),
                            "source_kind": "burp_copied_table",
                        })
                    continue
        match = TABLE_ROW_RE.search(line)
        if match:
            url = combine_host_and_path(match.group("host"), match.group("url"))
            if url:
                rows.append({
                    "method": match.group("method").upper(),
                    "url": url,
                    "source": str(source),
                    "source_kind": "burp_copied_table",
                })
    return rows


def extract_from_burp_xml(path: Path) -> list[dict]:
    rows: list[dict] = []
    try:
        root = ElementTree.fromstring(path.read_text(encoding="utf-8", errors="replace"))
    except ElementTree.ParseError:
        return rows
    for item in root.findall(".//item"):
        method = (item.findtext("method") or "GET").strip().upper()
        url = (item.findtext("url") or "").strip()
        if url.startswith(("http://", "https://")):
            rows.append({"method": method, "url": url, "source": str(path), "source_kind": "burp_xml"})
        req_el = item.find("request")
        if req_el is not None and req_el.text:
            decoded = decode_burp_request(req_el.text.strip(), (req_el.attrib.get("base64") or "").lower() == "true")
            rows.extend(extract_from_raw_http(decoded, path))
    return rows


def extract_burp_urls(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rows = extract_from_burp_xml(path) if path.suffix.lower() == ".xml" else []
    if path.suffix.lower() != ".xml":
        table_rows = extract_from_copied_history_table(text, path)
        if table_rows:
            rows.extend(table_rows)
        else:
            rows.extend({"method": "GET", "url": match.group(0).rstrip(".,;"), "source": str(path), "source_kind": "url_text"} for match in URL_RE.finditer(text))
            rows.extend(extract_from_raw_http(text, path))
    by_key: dict[tuple[str, str], dict] = {}
    for row in rows:
        url = row["url"].strip()
        if not url.startswith(("http://", "https://")):
            continue
        key = (row.get("method", "GET").upper(), url.split("#", 1)[0])
        by_key.setdefault(key, {**row, "method": key[0], "url": key[1]})
    return list(by_key.values())


def object_id_keys(url: str) -> list[str]:
    parsed = urlparse(url)
    keys = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if OBJECT_ID_HINT_RE.search(key)]
    tokens = [token for token in re.split(r"[/._-]+", parsed.path) if OBJECT_ID_HINT_RE.search(token)]
    return sorted(set(keys + tokens))


def score_url(method: str, url: str) -> tuple[int, list[str]]:
    parsed = urlparse(url)
    hay = f"{parsed.path} {parsed.query}"
    score = 0
    reasons: list[str] = []
    if method == "GET":
        score += 15
        reasons.append("GET 可只读复核")
    if API_PATH_RE.search(hay):
        score += 30
        reasons.append("小程序/API/业务路径")
    if SENSITIVE_FIELD_RE.search(hay):
        score += 25
        reasons.append("路径或参数含敏感业务语义")
    if object_id_keys(url):
        score += 20
        reasons.append("疑似对象 ID 参数")
    if UNSAFE_PATH_RE.search(parsed.path):
        reasons.append("写入/支付/上传类仅人工判断")
    return score, reasons


def is_safe_candidate(method: str, url: str) -> bool:
    parsed = urlparse(url)
    hay = f"{parsed.path} {parsed.query}"
    api_like = bool(API_PATH_RE.search(hay) or SENSITIVE_FIELD_RE.search(hay) or object_id_keys(url))
    return method == "GET" and api_like and not STATIC_RE.search(parsed.path) and not UNSAFE_PATH_RE.search(parsed.path)


def candidate_from_burp(row: dict, targets: list[TargetSeed]) -> dict:
    method = str(row.get("method") or "GET").upper()
    raw_url = str(row.get("url") or "")
    url = redacted_url(raw_url)
    host = host_of(raw_url)
    score, reasons = score_url(method, raw_url)
    in_scope = any(host == target.host or same_site(host, target.host) for target in targets)
    return {
        "checked_at": now_iso(),
        "base_url": f"{urlparse(raw_url).scheme}://{urlparse(raw_url).netloc}",
        "url": url,
        "redacted_url": url,
        "raw_url_sha256": hashlib.sha256(raw_url.encode("utf-8", "replace")).hexdigest(),
        "method": method,
        "host": host,
        "scope_state": "in_current_scope" if in_scope else "ownership_confirmation_required",
        "source": "burp_miniapp_import",
        "source_file": row.get("source"),
        "source_kind": row.get("source_kind"),
        "priority_score": score,
        "tags": ["miniapp", "burp", "api"] + (["object_id_candidate"] if object_id_keys(raw_url) else []),
        "object_id_keys": object_id_keys(raw_url),
        "reasons": reasons,
        "safe_auto_confirm": is_safe_candidate(method, raw_url) and in_scope,
        "manual_next_step": "先确认小程序后端归属；登录态接口不要批量改 ID，优先在 Burp 里做当前账号只读复核。",
    }


def append_jsonl_dedup(path: Path, rows: list[dict], key_fields: tuple[str, ...] = ("method", "url")) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    seen: set[tuple[str, ...]] = set()
    existing: list[str] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            existing.append(line)
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                seen.add(tuple(str(item.get(field) or "") for field in key_fields))
    new_lines = []
    for row in rows:
        key = tuple(str(row.get(field) or "") for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        new_lines.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
    path.write_text("\n".join(existing + new_lines) + ("\n" if existing or new_lines else ""), encoding="utf-8")


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def write_search_html(path: Path, rows: list[dict]) -> None:
    lines = [
        "<!doctype html><meta charset='utf-8'><title>Miniapp Search Pack</title>",
        "<h1>小程序人工搜索链接</h1>",
        "<p>这些链接只用于打开搜索页面；小程序归属和后端域名仍需人工确认。</p>",
        "<table border='1' cellpadding='6' cellspacing='0'>",
        "<tr><th>目标</th><th>关键词</th><th>Bing</th><th>Baidu</th><th>微信内搜索词</th></tr>",
    ]
    for row in rows:
        lines.append(
            "<tr>"
            f"<td>{html.escape(row.get('target_name') or row.get('target_host') or '')}</td>"
            f"<td>{html.escape(row.get('keyword') or '')}</td>"
            f"<td><a href='{html.escape(row.get('bing') or '')}'>Bing</a></td>"
            f"<td><a href='{html.escape(row.get('baidu') or '')}'>Baidu</a></td>"
            f"<td>{html.escape(row.get('wechat_search') or '')}</td>"
            "</tr>"
        )
    lines.append("</table>")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_report(out_dir: Path, keywords: list[dict], candidates: list[dict]) -> Path:
    in_scope = [row for row in candidates if row.get("scope_state") == "in_current_scope"]
    pending = [row for row in candidates if row.get("scope_state") != "in_current_scope"]
    lines = [
        "# 小程序人工搜索与 Burp 导入",
        "",
        f"- Generated: {now_iso()}",
        f"- 搜索关键词: {len(keywords)}",
        f"- Burp URL 候选: {len(candidates)}",
        f"- 当前范围内候选: {len(in_scope)}",
        f"- 需归属确认候选: {len(pending)}",
        "",
        "## 怎么用",
        "",
        "1. 用 `miniapp_search_urls.html` 或 `miniapp_search_keywords.csv` 找小程序名称和入口。",
        "2. 在微信里打开小程序，用 Burp 抓 HTTP history，再导出 XML/文本。",
        "3. 用 `--miniapp-burp-export <burp文件>` 导入，当前范围内的安全 GET 候选会进入主流程候选。",
        "4. 登录态接口不要批量改 ID；先看字段名、状态码、数量和页面归属，确认有把握再做最小化人工复核。",
        "",
        "## 当前范围内候选 TOP",
        "",
        "| # | 分数 | 方法 | URL | 理由 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for idx, row in enumerate(sorted(in_scope, key=lambda item: -int(item.get("priority_score") or 0))[:80], 1):
        lines.append(
            f"| {idx} | {row.get('priority_score')} | {row.get('method')} | `{html.escape(row.get('redacted_url') or '')}` | "
            f"{html.escape('；'.join(row.get('reasons') or []))} |"
        )
    if not in_scope:
        lines.append("| _无_ |  |  |  |  |")
    lines.extend(["", "## 需归属确认域名", ""])
    pending_hosts = sorted({row.get("host") for row in pending if row.get("host")})
    lines.extend([f"- `{host}`" for host in pending_hosts] or ["_无_"])
    path = out_dir / "小程序人工搜索与Burp导入.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def run_helper(
    targets_file: Path,
    out_dir: Path,
    search_pack: bool,
    burp_exports: list[Path],
    api_candidates_out: Path | None,
    in_scope_api_candidates_out: Path | None,
    main_api_candidates_out: Path | None,
    pending_assets_out: Path | None,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    targets = load_targets(targets_file)
    keywords = seed_keywords(targets) if search_pack else []
    if keywords:
        write_csv(out_dir / "miniapp_search_keywords.csv", keywords, ["target_host", "target_name", "keyword", "wechat_search", "bing", "baidu"])
        write_search_html(out_dir / "miniapp_search_urls.html", keywords)

    raw_rows: list[dict] = []
    for export in burp_exports:
        if export.exists():
            raw_rows.extend(extract_burp_urls(export))
    candidates = [candidate_from_burp(row, targets) for row in raw_rows]
    candidates = sorted(candidates, key=lambda item: (-int(item.get("priority_score") or 0), item.get("url") or ""))
    in_scope = [row for row in candidates if row.get("scope_state") == "in_current_scope"]
    safe_in_scope = [row for row in in_scope if row.get("safe_auto_confirm")]
    if api_candidates_out:
        append_jsonl_dedup(api_candidates_out, candidates)
    if in_scope_api_candidates_out:
        append_jsonl_dedup(in_scope_api_candidates_out, in_scope)
    if main_api_candidates_out:
        append_jsonl_dedup(main_api_candidates_out, safe_in_scope)
    if pending_assets_out:
        pending_hosts = sorted({row.get("host") for row in candidates if row.get("scope_state") != "in_current_scope" and row.get("host")})
        pending_assets_out.write_text("\n".join(pending_hosts) + ("\n" if pending_hosts else ""), encoding="utf-8")
    write_json = {
        "created_at": now_iso(),
        "targets": str(targets_file),
        "target_count": len(targets),
        "keyword_count": len(keywords),
        "burp_export_count": len(burp_exports),
        "burp_url_count": len(candidates),
        "in_scope_count": len(in_scope),
        "safe_in_scope_appended_count": len(safe_in_scope),
        "response_body_persisted": False,
        "cookie_or_token_persisted": False,
    }
    (out_dir / "manifest.json").write_text(json.dumps(write_json, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_report(out_dir, keywords, candidates)
    return write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manual mini-program search pack and Burp URL importer")
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=Path("runs") / f"{now_stamp()}_miniapp_manual_search")
    parser.add_argument("--search-pack", action="store_true")
    parser.add_argument("--burp-export", type=Path, action="append", default=[])
    parser.add_argument("--api-candidates-out", type=Path, default=None)
    parser.add_argument("--in-scope-api-candidates-out", type=Path, default=None)
    parser.add_argument("--main-api-candidates-out", type=Path, default=None)
    parser.add_argument("--pending-assets-out", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    setup_console()
    args = parse_args()
    manifest = run_helper(
        targets_file=args.targets,
        out_dir=args.out_dir,
        search_pack=args.search_pack,
        burp_exports=args.burp_export,
        api_candidates_out=args.api_candidates_out,
        in_scope_api_candidates_out=args.in_scope_api_candidates_out,
        main_api_candidates_out=args.main_api_candidates_out,
        pending_assets_out=args.pending_assets_out,
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
