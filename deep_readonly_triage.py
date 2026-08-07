import argparse
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


CONFIG_PATHS = [
    "/web.config",
    "/Web.config",
    "/web.Debug.config",
    "/web.Release.config",
    "/appsettings.json",
    "/appsettings.Production.json",
    "/.env",
    "/.env.production",
    "/config.php",
    "/config.inc.php",
    "/database.php",
    "/application.properties",
    "/bootstrap.properties",
    "/jdbc.properties",
    "/db.properties",
    "/application.yml",
    "/bootstrap.yml",
    "/WEB-INF/web.xml",
    "/WEB-INF/classes/application.properties",
    "/WEB-INF/classes/jdbc.properties",
]

GIT_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.git/logs/HEAD",
]

OPENAPI_PATHS = [
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-resources",
    "/swagger-ui.html",
    "/api/swagger-ui.html",
    "/doc.html",
]

ACTUATOR_PATHS = [
    "/actuator",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/metrics",
    "/actuator/heapdump",
]

DRUID_PATHS = [
    "/druid/index.html",
    "/druid/login.html",
    "/druid/basic.json",
    "/druid/datasource.json",
    "/druid/sql.json",
]

SENSITIVE_RE = re.compile(
    r"(password|passwd|pwd|secret|token|apikey|api_key|access_key|private|machinekey|"
    r"connectionstring|jdbc:|datasource|db_|mysql|oracle|sqlserver|redis|mongodb|username|user=)",
    re.I,
)

CONFIG_MARKER_RE = re.compile(
    r"(<configuration|<system\.webserver|connectionstrings|appsettings|spring\.datasource|"
    r"jdbc:|server:|datasource|<\?xml|DB_HOST|DB_PASSWORD|APP_KEY)",
    re.I,
)

NOISE_RE = re.compile(
    r"(<html|404|not found|forbidden|access denied|error\.htm|aspxerrorpath|访问禁止|找不到|登录|login)",
    re.I,
)


def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def title_of(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120]


def redacted_context(text: str, limit: int = 6) -> list[str]:
    lines = []
    for raw_line in text.splitlines():
        if SENSITIVE_RE.search(raw_line):
            line = raw_line.strip()[:260]
            line = re.sub(r"(?i)(password|passwd|pwd|secret|token|apikey|api_key|access_key|privatekey|machinekey)(\s*[:=]\s*)([^&\s\"']+)", r"\1\2<redacted>", line)
            line = re.sub(r"(?i)(connectionString\s*=\s*[\"'])([^\"']+)", r"\1<redacted>", line)
            lines.append(line)
        if len(lines) >= limit:
            break
    return lines


def fetch(url: str, timeout: float) -> dict:
    request = Request(
        url,
        headers={
            "User-Agent": "Authorized-ReadOnly-Deep-Triage/1.0",
            "Accept": "application/json,application/xml,text/plain,text/html,*/*",
        },
    )
    record = {"checked_at": now(), "url": url}
    try:
        with urlopen(request, timeout=timeout) as response:
            data = response.read(1024 * 512)
            content_type = response.headers.get("Content-Type", "")
            charset = response.headers.get_content_charset() or "utf-8"
            text = data.decode(charset, errors="ignore")
            record.update(
                {
                    "status": response.status,
                    "final_url": response.url,
                    "content_type": content_type,
                    "content_length": response.headers.get("Content-Length", ""),
                    "sample_bytes": len(data),
                    "sample_sha256": sha256_bytes(data[:65536]),
                    "title": title_of(text),
                    "text": text,
                }
            )
    except HTTPError as exc:
        data = exc.read(1024 * 128)
        content_type = exc.headers.get("Content-Type", "")
        charset = exc.headers.get_content_charset() or "utf-8"
        text = data.decode(charset, errors="ignore")
        record.update(
            {
                "status": exc.code,
                "final_url": exc.url,
                "content_type": content_type,
                "content_length": exc.headers.get("Content-Length", ""),
                "sample_bytes": len(data),
                "sample_sha256": sha256_bytes(data[:65536]),
                "title": title_of(text),
                "text": text,
            }
        )
    except URLError as exc:
        record.update({"error": str(exc.reason)[:300]})
    except Exception as exc:  # noqa: BLE001
        record.update({"error": str(exc)[:300]})
    return record


def classify_config(record: dict) -> dict:
    text = record.pop("text", "")
    lower_url = (record.get("final_url") or record.get("url") or "").lower()
    status = record.get("status")
    marker_hits = sorted(set(m.group(1).lower() for m in CONFIG_MARKER_RE.finditer(text[:65536])))
    sensitive_hits = sorted(set(m.group(1).lower() for m in SENSITIVE_RE.finditer(text[:65536])))
    noise = bool(NOISE_RE.search(text[:4096])) or "/404" in lower_url or "error" in lower_url
    category = "not_interesting"
    if status == 200 and marker_hits and sensitive_hits and not noise:
        category = "sensitive_config_exposed"
    elif status == 200 and marker_hits and not noise:
        category = "config_exposed_no_secret"
    elif status in (401, 403):
        category = "protected"
    elif noise:
        category = "likely_error_or_login"
    record.update(
        {
            "category": category,
            "marker_hits": marker_hits[:12],
            "sensitive_hits": sensitive_hits[:12],
            "redacted_context": redacted_context(text),
        }
    )
    return record


def classify_git(record: dict) -> dict:
    text = record.pop("text", "")
    status = record.get("status")
    path = record.get("path", "")
    category = "not_interesting"
    evidence = []
    if status == 200 and path.endswith("/.git/HEAD") and text.startswith("ref:"):
        category = "git_head_readable"
        evidence.append(text.strip()[:120])
    elif status == 200 and path.endswith("/.git/config") and "[remote" in text:
        category = "git_config_readable"
        evidence.extend(redacted_context(text, limit=4))
    elif status == 200 and path.endswith("/.git/index") and record.get("sample_bytes", 0) > 128:
        category = "git_index_readable"
        evidence.append("git index bytes readable")
    elif status in (401, 403):
        category = "protected"
    record.update({"category": category, "evidence": evidence})
    return record


def classify_openapi(record: dict) -> dict:
    text = record.pop("text", "")
    status = record.get("status")
    category = "not_interesting"
    path_count = 0
    sample_paths = []
    try:
        parsed = json.loads(text)
        paths = parsed.get("paths") if isinstance(parsed, dict) else None
        if isinstance(paths, dict):
            path_count = len(paths)
            sample_paths = list(paths.keys())[:15]
            category = "openapi_json_exposed" if path_count else "openapi_json_no_paths"
    except Exception:
        if status == 200 and re.search(r"swagger|openapi|swagger-ui", text, re.I) and not NOISE_RE.search(text[:4096]):
            category = "swagger_ui_candidate"
    if status in (401, 403):
        category = "protected"
    record.update({"category": category, "path_count": path_count, "sample_paths": sample_paths})
    return record


def classify_actuator(record: dict) -> dict:
    text = record.pop("text", "")
    status = record.get("status")
    category = "not_interesting"
    sensitive_hits = sorted(set(m.group(1).lower() for m in SENSITIVE_RE.finditer(text[:65536])))
    if status == 200 and ("propertySources" in text or "activeProfiles" in text or "systemProperties" in text):
        category = "actuator_env_exposed"
    elif status == 200 and record.get("path", "").endswith("/actuator/heapdump") and record.get("sample_bytes", 0) > 1024 * 64:
        category = "actuator_heapdump_accessible"
    elif status == 200 and re.search(r"jvm\.|process\.|http\.server\.requests|measurements", text):
        category = "actuator_metrics_exposed"
    elif status in (401, 403):
        category = "protected"
    elif NOISE_RE.search(text[:4096]):
        category = "likely_error_or_login"
    record.update(
        {
            "category": category,
            "sensitive_hits": sensitive_hits[:12],
            "redacted_context": redacted_context(text),
        }
    )
    return record


def classify_druid(record: dict) -> dict:
    text = record.pop("text", "")
    status = record.get("status")
    category = "not_interesting"
    if status == 200 and re.search(r"druid monitor|druid stat|web session stat|sql stat", text, re.I):
        category = "druid_panel_exposed"
    if status == 200 and record.get("content_type", "").lower().startswith("application/json"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict) and parsed:
                category = "druid_json_accessible"
        except Exception:
            pass
    if status in (401, 403):
        category = "protected"
    record.update({"category": category})
    return record


def probe_target(base_url: str, timeout: float, delay: float) -> list[dict]:
    base = base_url.rstrip("/") + "/"
    work = []
    for family, paths, classifier in [
        ("config", CONFIG_PATHS, classify_config),
        ("git", GIT_PATHS, classify_git),
        ("openapi", OPENAPI_PATHS, classify_openapi),
        ("actuator", ACTUATOR_PATHS, classify_actuator),
        ("druid", DRUID_PATHS, classify_druid),
    ]:
        for path in paths:
            url = urljoin(base, path.lstrip("/"))
            record = fetch(url, timeout)
            record.update({"base_url": base_url, "family": family, "path": path})
            work.append(classifier(record))
            time.sleep(delay)
    return work


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    targets = [line.strip() for line in args.targets.read_text(encoding="utf-8").splitlines() if line.strip()]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for target in targets:
            for record in probe_target(target, args.timeout, args.delay):
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                handle.flush()
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
