import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+(?:gov\.cn|org\.cn|com\.cn|net\.cn|cn|com|net|org)(?![A-Za-z0-9_-])", re.I)
WX_APP_RE = re.compile(r"\bwx[a-f0-9]{16}\b", re.I)
GH_RE = re.compile(r"\bgh_[A-Za-z0-9_-]{6,}\b")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b")
PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(?:"
    r"api|admin|manage|manager|system|sys|login|logout|user|users|auth|oauth|sso|cas|"
    r"token|captcha|verify|password|pwd|role|dept|org|file|files|upload|download|export|"
    r"import|attachment|attach|img|image|common|portal|web|service|rest|restful|wx|weixin|"
    r"open|gateway|interface|query|search|list|detail|info|data|report|stat|notice|article"
    r")[A-Za-z0-9_\-./?=&:%{}[\],]{0,260}",
    re.I,
)
ROUTE_RE = re.compile(r"(?:path|url|redirect|component|name)\s*:\s*['\"]([^'\"]{1,180})['\"]", re.I)
API_ASSIGN_RE = re.compile(
    r"(?:baseURL|baseUrl|apiUrl|apiURL|serverUrl|serviceUrl|gateway|host|domain|uploadUrl|downloadUrl)\s*[:=]\s*['\"]([^'\"]{1,260})['\"]",
    re.I,
)
REQUEST_RE = re.compile(
    r"(?:axios|request|\$\.ajax|\$http|fetch|this\.\$http|this\.\$axios)\s*(?:\.([a-z]+))?\s*\((.{0,260}?)\)",
    re.I | re.S,
)
STRING_RE = re.compile(r"['\"]([^'\"]{3,240})['\"]")

KEYWORDS = {
    "auth_token": ["token", "authorization", "bearer", "jwt", "access_token", "refresh_token", "session"],
    "login_auth": ["login", "logout", "captcha", "password", "passwd", "pwd", "sso", "cas", "oauth"],
    "upload_file": ["upload", "multipart", "formdata", "fileupload", "attachment", "attach"],
    "download_export": ["download", "export", "excel", "word", "pdf", "zip", "template"],
    "admin_priv": ["admin", "manage", "manager", "role", "permission", "menu", "dept", "org", "user/list"],
    "debug_env": ["localhost", "127.0.0.1", "debug", "dev", "test", "uat", "staging", "mock"],
    "crypto_key": ["secret", "appsecret", "apikey", "api_key", "privatekey", "publickey", "encrypt", "decrypt"],
    "wechat": ["weixin", "wechat", "wx", "miniapp", "mp.weixin", "servicewechat", "appid"],
    "dangerous_client": ["eval(", "innerhtml", "dangerouslysetinnerhtml", "document.write", "localstorage", "sessionstorage"],
}


def read_text(path: Path) -> tuple[str, str, str]:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    for enc in ("utf-8", "utf-8-sig", "gb18030", "gbk"):
        try:
            return data.decode(enc), enc, sha
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "utf-8-replace", sha


def clean_match(value: str) -> str:
    value = value.strip().strip("`'\"")
    value = value.replace("\\/", "/")
    value = re.sub(r"\\u002[fF]", "/", value)
    value = re.sub(r"[),;]+$", "", value)
    return value


def unique_sorted(values):
    return sorted(set(v for v in values if v), key=lambda x: (len(x), x.lower()))


def keyword_hits(text: str):
    low = text.lower()
    rows = []
    for group, words in KEYWORDS.items():
        for word in words:
            count = low.count(word.lower())
            if count:
                rows.append({"group": group, "keyword": word, "count": count})
    return sorted(rows, key=lambda r: (-r["count"], r["group"], r["keyword"]))


def score_endpoint(endpoint: str) -> tuple[int, list[str]]:
    e = endpoint.lower()
    score = 0
    reasons = []
    buckets = [
        (["upload", "file", "attach", "multipart"], 5, "upload/file"),
        (["download", "export", "excel", "pdf", "template"], 4, "download/export"),
        (["admin", "manage", "system", "role", "permission", "user", "dept"], 4, "admin/authz"),
        (["login", "captcha", "token", "oauth", "sso", "cas", "password"], 4, "auth/session"),
        (["delete", "remove", "update", "save", "add", "edit"], 3, "state-changing"),
        (["debug", "test", "dev", "mock", "swagger", "druid", "actuator"], 5, "debug/exposed"),
        (["query", "list", "detail", "info", "data", "search"], 1, "data-query"),
        (["wx", "weixin", "wechat", "appid"], 2, "wechat"),
    ]
    for words, points, reason in buckets:
        if any(w in e for w in words):
            score += points
            reasons.append(reason)
    return score, sorted(set(reasons))


def nearby_snippet(text: str, needle: str, limit: int = 180) -> str:
    idx = text.find(needle)
    if idx < 0:
        return ""
    start = max(0, idx - limit // 2)
    end = min(len(text), idx + len(needle) + limit // 2)
    snippet = text[start:end]
    return re.sub(r"\s+", " ", snippet)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("js_file")
    parser.add_argument("--out-dir", default="runs/js_static_analysis")
    parser.add_argument("--top", type=int, default=300)
    args = parser.parse_args()

    path = Path(args.js_file)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    text, encoding, sha = read_text(path)
    urls = unique_sorted(clean_match(m.group(0)) for m in URL_RE.finditer(text))
    domains = unique_sorted(clean_match(m.group(0)) for m in DOMAIN_RE.finditer(text))
    ips = unique_sorted(clean_match(m.group(0)) for m in IP_RE.finditer(text))
    wx_appids = unique_sorted(m.group(0) for m in WX_APP_RE.finditer(text))
    gh_ids = unique_sorted(m.group(0) for m in GH_RE.finditer(text))
    paths = unique_sorted(clean_match(m.group(0)) for m in PATH_RE.finditer(text))
    routes = unique_sorted(clean_match(m.group(1)) for m in ROUTE_RE.finditer(text))
    api_assigns = unique_sorted(clean_match(m.group(1)) for m in API_ASSIGN_RE.finditer(text))

    request_rows = []
    for m in REQUEST_RE.finditer(text):
        call = re.sub(r"\s+", " ", m.group(0))[:320]
        request_rows.append({"method_hint": (m.group(1) or "").lower(), "call": call})

    string_values = [clean_match(m.group(1)) for m in STRING_RE.finditer(text)]
    high_strings = []
    for value in unique_sorted(string_values):
        low = value.lower()
        if any(word in low for words in KEYWORDS.values() for word in words):
            score, reasons = score_endpoint(value)
            high_strings.append({"value": value, "score": score, "reasons": "|".join(reasons), "snippet": nearby_snippet(text, value)})
    high_strings.sort(key=lambda r: (-r["score"], r["value"].lower()))

    endpoint_rows = []
    for endpoint in unique_sorted(paths + routes + api_assigns + urls):
        score, reasons = score_endpoint(endpoint)
        endpoint_rows.append({
            "endpoint": endpoint,
            "score": score,
            "reasons": "|".join(reasons),
            "snippet": nearby_snippet(text, endpoint),
        })
    endpoint_rows.sort(key=lambda r: (-r["score"], r["endpoint"].lower()))

    def write_lines(name, rows):
        (out_dir / name).write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")

    def write_csv(name, rows, fields):
        with (out_dir / name).open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({field: row.get(field, "") for field in fields})

    write_lines("urls.txt", urls)
    write_lines("domains.txt", domains)
    write_lines("ips.txt", ips)
    write_lines("wx_appids.txt", wx_appids)
    write_lines("gh_ids.txt", gh_ids)
    write_lines("paths.txt", paths)
    write_lines("routes.txt", routes)
    write_lines("api_assignments.txt", api_assigns)
    write_csv("keyword_hits.csv", keyword_hits(text), ["group", "keyword", "count"])
    write_csv("request_calls.csv", request_rows[: args.top], ["method_hint", "call"])
    write_csv("high_value_endpoints.csv", endpoint_rows[: args.top], ["score", "reasons", "endpoint", "snippet"])
    write_csv("sensitive_strings.csv", high_strings[: args.top], ["score", "reasons", "value", "snippet"])

    summary = {
        "file": str(path),
        "size": path.stat().st_size,
        "encoding": encoding,
        "sha256": sha,
        "counts": {
            "urls": len(urls),
            "domains": len(domains),
            "ips": len(ips),
            "wx_appids": len(wx_appids),
            "gh_ids": len(gh_ids),
            "paths": len(paths),
            "routes": len(routes),
            "api_assignments": len(api_assigns),
            "request_calls": len(request_rows),
            "high_value_endpoints": len(endpoint_rows),
            "sensitive_strings": len(high_strings),
        },
        "top_domains": domains[:50],
        "top_urls": urls[:50],
        "top_endpoints": endpoint_rows[:30],
        "keyword_top": keyword_hits(text)[:30],
        "libraries_hint": {
            "webpack": "!function(e){var t={}" in text[:2000],
            "react": "react" in text.lower() or "createelement" in text.lower(),
            "antd": "ant-" in text.lower() or "__ant_button" in text.lower(),
            "axios": "axios" in text.lower(),
        },
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
