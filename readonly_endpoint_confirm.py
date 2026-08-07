import argparse
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


KEYWORDS = {
    "swagger": ["swagger", "swagger-ui", "openapi", "api-docs", "swaggerresources"],
    "druid": ["druid monitor", "druid stat", "web session stat", "sql stat"],
    "actuator": ["propertysources", "activeprofiles", "heapdump", "heap"],
    "config": ["<configuration", "connectionstrings", "system.webserver"],
    "error": ["404", "not found", "error", "找不到", "login", "登录", "aspxerrorpath"],
}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def title_of(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120]


def classify(text: str) -> dict[str, list[str]]:
    lower = text[:65536].lower()
    return {
        name: [kw for kw in words if kw in lower]
        for name, words in KEYWORDS.items()
        if any(kw in lower for kw in words)
    }


def fetch(url: str, timeout: float) -> dict[str, object]:
    record: dict[str, object] = {
        "checked_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "url": url,
    }
    request = Request(
        url,
        headers={
            "User-Agent": "Authorized-ReadOnly-Endpoint-Confirm/1.0",
            "Accept": "text/html,application/json,application/xml,text/plain,*/*",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(1024 * 256)
            content_type = response.headers.get("Content-Type", "")
            encoding = response.headers.get_content_charset() or "utf-8"
            text = raw.decode(encoding, errors="ignore")
            record.update(
                {
                    "status": response.status,
                    "final_url": response.url,
                    "content_type": content_type,
                    "content_length": response.headers.get("Content-Length", ""),
                    "sample_length": len(text[:4096]),
                    "sample_sha256": sha256_text(text[:4096]),
                    "title": title_of(text),
                    "keyword_groups": classify(text),
                }
            )
    except HTTPError as exc:
        raw = exc.read(1024 * 64)
        content_type = exc.headers.get("Content-Type", "")
        encoding = exc.headers.get_content_charset() or "utf-8"
        text = raw.decode(encoding, errors="ignore")
        record.update(
            {
                "status": exc.code,
                "final_url": exc.url,
                "content_type": content_type,
                "content_length": exc.headers.get("Content-Length", ""),
                "sample_length": len(text[:4096]),
                "sample_sha256": sha256_text(text[:4096]),
                "title": title_of(text),
                "keyword_groups": classify(text),
            }
        )
    except URLError as exc:
        record.update({"error": str(exc.reason)[:300]})
    except Exception as exc:  # noqa: BLE001 - summary probe should record errors.
        record.update({"error": str(exc)[:300]})
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--urls", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    urls = [line.strip() for line in args.urls.read_text(encoding="utf-8").splitlines() if line.strip()]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for idx, url in enumerate(urls):
            handle.write(json.dumps(fetch(url, args.timeout), ensure_ascii=False) + "\n")
            handle.flush()
            if idx != len(urls) - 1:
                time.sleep(args.delay)
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
