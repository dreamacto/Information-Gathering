import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urljoin


PATHS = [
    "/web.config",
    "/Web.config",
    "/web.Debug.config",
    "/web.Release.config",
    "/appsettings.json",
    "/appsettings.Production.json",
    "/config.json",
    "/settings.json",
    "/database.config",
    "/connectionStrings.config",
    "/.env",
    "/.env.production",
    "/application.properties",
    "/bootstrap.properties",
    "/config.properties",
    "/database.properties",
    "/jdbc.properties",
    "/db.properties",
    "/application.yml",
    "/bootstrap.yml",
    "/config.yml",
    "/WEB-INF/web.xml",
    "/WEB-INF/classes/application.properties",
    "/WEB-INF/classes/jdbc.properties",
    "/WEB-INF/classes/db.properties",
    "/WEB-INF/classes/config.properties",
]

SENSITIVE_KEYWORDS = [
    "password",
    "passwd",
    "pwd",
    "connectionstring",
    "connectionstrings",
    "datasource",
    "jdbc:",
    "username",
    "user=",
    "secret",
    "apikey",
    "api_key",
    "token",
    "machinekey",
    "privatekey",
    "db_",
    "mysql",
    "oracle",
    "sqlserver",
    "redis",
    "mongodb",
]

CONFIG_MARKERS = [
    "<configuration",
    "<system.webserver",
    "appsettings",
    "spring.datasource",
    "server:",
    "datasource",
    "jdbc:",
    "connectionstrings",
    "<?xml",
]

NOISE_MARKERS = [
    "<html",
    "404",
    "not found",
    "找不到",
    "error.htm",
    "login",
]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def classify(text: str, status: int, content_type: str) -> tuple[str, list[str]]:
    lower = text[:8192].lower()
    hits = [kw for kw in SENSITIVE_KEYWORDS if kw in lower]
    config_hits = [kw for kw in CONFIG_MARKERS if kw in lower]
    noise_hits = [kw for kw in NOISE_MARKERS if kw in lower]
    if status == 200 and hits and config_hits:
        return "high_sensitive_config_candidate", hits[:8]
    if status == 200 and config_hits and not noise_hits:
        return "config_file_exposed", config_hits[:8]
    if status == 200 and "octet-stream" in content_type.lower() and config_hits:
        return "downloadable_config_candidate", config_hits[:8]
    if status in (401, 403):
        return "protected_or_forbidden", []
    if status == 200 and noise_hits:
        return "likely_error_page", noise_hits[:5]
    return "not_interesting", []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/") + "/"
    args.out.parent.mkdir(parents=True, exist_ok=True)

    with args.out.open("w", encoding="utf-8") as handle:
        for idx, path in enumerate(PATHS):
            url = urljoin(base_url, path.lstrip("/"))
            record = {
                "checked_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
                "url": url,
                "path": path,
            }
            try:
                request = Request(
                    url,
                    headers={
                        "User-Agent": "Authorized-ReadOnly-Config-Check/1.0",
                        "Accept": "text/html,application/json,application/xml,text/plain,*/*",
                    },
                )
                with urlopen(request, timeout=args.timeout) as response:
                    raw = response.read(1024 * 256)
                    content_type = response.headers.get("Content-Type", "")
                    encoding = response.headers.get_content_charset() or "utf-8"
                    text = raw.decode(encoding, errors="ignore")
                    status = response.status
                    final_url = response.url
                    content_length = response.headers.get("Content-Length", "")
                category, keyword_hits = classify(text, status, content_type)
                sample = text[:4096]
                record.update(
                    {
                        "status": status,
                        "final_url": final_url,
                        "content_type": content_type,
                        "content_length": content_length,
                        "sample_length": len(sample),
                        "sample_sha256": sha256_text(sample),
                        "category": category,
                        "keyword_hits": keyword_hits,
                    }
                )
            except HTTPError as exc:
                raw = exc.read(1024 * 64)
                content_type = exc.headers.get("Content-Type", "")
                encoding = exc.headers.get_content_charset() or "utf-8"
                text = raw.decode(encoding, errors="ignore")
                category, keyword_hits = classify(text, exc.code, content_type)
                record.update(
                    {
                        "status": exc.code,
                        "final_url": exc.url,
                        "content_type": content_type,
                        "content_length": exc.headers.get("Content-Length", ""),
                        "sample_length": len(text[:4096]),
                        "sample_sha256": sha256_text(text[:4096]),
                        "category": category,
                        "keyword_hits": keyword_hits,
                    }
                )
            except URLError as exc:
                record.update({"category": "request_error", "error": str(exc.reason)[:300]})
            except Exception as exc:  # noqa: BLE001 - record network errors for review.
                record.update({"category": "request_error", "error": str(exc)[:300]})
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            if idx != len(PATHS) - 1:
                time.sleep(args.delay)
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
