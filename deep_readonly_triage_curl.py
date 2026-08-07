import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin


PATH_GROUPS = {
    "config": [
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
    ],
    "git": ["/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD"],
    "openapi": [
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger-resources",
        "/swagger-ui.html",
        "/api/swagger-ui.html",
        "/doc.html",
    ],
    "actuator": ["/actuator", "/actuator/env", "/actuator/configprops", "/actuator/metrics", "/actuator/heapdump"],
    "druid": ["/druid/index.html", "/druid/login.html", "/druid/basic.json", "/druid/datasource.json", "/druid/sql.json"],
}

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
NOISE_RE = re.compile(r"(<html|404|not found|forbidden|access denied|error\.htm|aspxerrorpath|访问禁止|找不到|登录|login)", re.I)


def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_headers(raw: str) -> dict:
    blocks = [block for block in raw.replace("\r\n", "\n").split("\n\n") if block.strip()]
    block = blocks[-1] if blocks else ""
    headers = {}
    for line in block.splitlines()[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return headers


def title_of(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120]


def redacted_context(text: str, limit: int = 6) -> list[str]:
    hits = []
    for raw_line in text.splitlines():
        if SENSITIVE_RE.search(raw_line):
            line = raw_line.strip()[:260]
            line = re.sub(
                r"(?i)(password|passwd|pwd|secret|token|apikey|api_key|access_key|privatekey|machinekey)(\s*[:=]\s*)([^&\s\"']+)",
                r"\1\2<redacted>",
                line,
            )
            line = re.sub(r"(?i)(connectionString\s*=\s*[\"'])([^\"']+)", r"\1<redacted>", line)
            hits.append(line)
        if len(hits) >= limit:
            break
    return hits


def fetch_with_curl(url: str, timeout: int, connect_timeout: int, tmp_dir: Path) -> dict:
    tmp_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False) as body_file, tempfile.NamedTemporaryFile(
        dir=tmp_dir, delete=False
    ) as header_file:
        body_path = Path(body_file.name)
        header_path = Path(header_file.name)
    cmd = [
        "curl.exe",
        "-k",
        "-L",
        "--silent",
        "--show-error",
        "--max-time",
        str(timeout),
        "--connect-timeout",
        str(connect_timeout),
        "--range",
        "0-524287",
        "-A",
        "Authorized-ReadOnly-Deep-Triage/1.0",
        "-D",
        str(header_path),
        "-o",
        str(body_path),
        "-w",
        "%{http_code} %{url_effective} %{time_total}",
        url,
    ]
    record = {"checked_at": now(), "url": url}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3, check=False)
        stdout = proc.stdout.strip()
        parts = stdout.split(" ", 2)
        status = int(parts[0]) if parts and parts[0].isdigit() else 0
        final_url = parts[1] if len(parts) > 1 else url
        elapsed = float(parts[2]) if len(parts) > 2 else None
        body = body_path.read_bytes() if body_path.exists() else b""
        headers_raw = header_path.read_text(encoding="utf-8", errors="ignore") if header_path.exists() else ""
        headers = parse_headers(headers_raw)
        charset = "utf-8"
        ctype = headers.get("content-type", "")
        charset_match = re.search(r"charset=([^;\s]+)", ctype, re.I)
        if charset_match:
            charset = charset_match.group(1)
        text = body.decode(charset, errors="ignore")
        record.update(
            {
                "status": status,
                "final_url": final_url,
                "elapsed_seconds": elapsed,
                "content_type": ctype,
                "content_length": headers.get("content-length", ""),
                "sample_bytes": len(body),
                "sample_sha256": sha256_bytes(body[:65536]),
                "title": title_of(text),
                "_text": text,
                "curl_returncode": proc.returncode,
                "curl_stderr": proc.stderr.strip()[:300],
            }
        )
    except Exception as exc:  # noqa: BLE001
        record.update({"error": str(exc)[:300]})
    finally:
        for path in (body_path, header_path):
            try:
                path.unlink()
            except OSError:
                pass
    return record


def classify(record: dict) -> dict:
    text = record.pop("_text", "")
    family = record.get("family")
    path = record.get("path", "")
    final_url = (record.get("final_url") or "").lower()
    status = record.get("status")
    category = "not_interesting"
    detail = {}

    if family == "config":
        markers = sorted(set(m.group(1).lower() for m in CONFIG_MARKER_RE.finditer(text[:65536])))
        sensitive = sorted(set(m.group(1).lower() for m in SENSITIVE_RE.finditer(text[:65536])))
        noise = bool(NOISE_RE.search(text[:4096])) or "/404" in final_url or "error" in final_url
        if status == 200 and markers and sensitive and not noise:
            category = "sensitive_config_exposed"
        elif status == 200 and markers and not noise:
            category = "config_exposed_no_secret"
        elif status in (401, 403):
            category = "protected"
        elif noise:
            category = "likely_error_or_login"
        detail = {"marker_hits": markers[:12], "sensitive_hits": sensitive[:12], "redacted_context": redacted_context(text)}
    elif family == "git":
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
        detail = {"evidence": evidence}
    elif family == "openapi":
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
        detail = {"path_count": path_count, "sample_paths": sample_paths}
    elif family == "actuator":
        sensitive = sorted(set(m.group(1).lower() for m in SENSITIVE_RE.finditer(text[:65536])))
        if status == 200 and ("propertySources" in text or "activeProfiles" in text or "systemProperties" in text):
            category = "actuator_env_exposed"
        elif status == 200 and path.endswith("/actuator/heapdump") and record.get("sample_bytes", 0) > 65536:
            category = "actuator_heapdump_accessible"
        elif status == 200 and re.search(r"jvm\.|process\.|http\.server\.requests|measurements", text):
            category = "actuator_metrics_exposed"
        elif status in (401, 403):
            category = "protected"
        elif NOISE_RE.search(text[:4096]):
            category = "likely_error_or_login"
        detail = {"sensitive_hits": sensitive[:12], "redacted_context": redacted_context(text)}
    elif family == "druid":
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

    record.update({"category": category, **detail})
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--connect-timeout", type=int, default=4)
    args = parser.parse_args()

    targets = [line.strip() for line in args.targets.read_text(encoding="utf-8").splitlines() if line.strip()]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp_dir = args.out.parent / ".triage_tmp"
    with args.out.open("w", encoding="utf-8") as handle:
        for target in targets:
            base = target.rstrip("/") + "/"
            for family, paths in PATH_GROUPS.items():
                for path in paths:
                    url = urljoin(base, path.lstrip("/"))
                    record = fetch_with_curl(url, args.timeout, args.connect_timeout, tmp_dir)
                    record.update({"base_url": target, "family": family, "path": path})
                    handle.write(json.dumps(classify(record), ensure_ascii=False) + "\n")
                    handle.flush()
                    time.sleep(args.delay)
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
