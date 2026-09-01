from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import argparse
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import uuid

try:
    from authorized_assessment.triage.response_baseline import (
        assess_response_record,
        build_baseline_profile,
        load_baseline_profiles,
        origin_of,
        summarize_body,
    )
except ImportError:  # 直接以文件方式执行时把 src/ 加入 sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from authorized_assessment.triage.response_baseline import (
        assess_response_record,
        build_baseline_profile,
        load_baseline_profiles,
        origin_of,
        summarize_body,
    )


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


def attach_fixed_path_assessment(
    record: dict, *, text: str, baselines: list | None = None
) -> dict:
    """为已抓取记录附加 fixed_path_assessment（纯函数，fetch 与测试共用）。

    无基线时 fail-closed：baseline_available=False、promotion_status=not_promoted。
    """
    record["fixed_path_assessment"] = assess_response_record(
        record, list(baselines or []), body_lines=summarize_body(text)
    )
    return record


def fetch(url: str, timeout: float, baselines: list | None = None) -> dict[str, object]:
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
            attach_fixed_path_assessment(record, text=text, baselines=baselines)
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
        attach_fixed_path_assessment(record, text=text, baselines=baselines)
    except URLError as exc:
        record.update({"error": str(exc.reason)[:300]})
    except Exception as exc:  # noqa: BLE001 - summary probe should record errors.
        record.update({"error": str(exc)[:300]})
    return record


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--urls", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--baseline-file",
        type=Path,
        default=None,
        help="离线基线记录 JSONL（build_baseline_profile 产物；零新增请求）",
    )
    parser.add_argument(
        "--with-baseline",
        action="store_true",
        help="显式 opt-in：为每个 origin 抓取首页与随机不存在路径作为基线（每 origin 新增 2 个 GET）；"
        "默认关闭，默认网络行为不变",
    )
    return parser


def capture_baselines(url: str, timeout: float) -> list[dict]:
    """显式 opt-in 的基线抓取（仅在 --with-baseline 时调用）。

    每个 origin 新增 2 个 GET：首页（target_baseline）与随机不存在路径
    （generic_error_page）。登录页/CDN/WAF 页无需预抓取——比较时由
    response_baseline.detect_known_false_positive_pattern 按已知模式识别。
    """
    origin = origin_of(url)
    profiles = []
    for kind, probe_url in (
        ("target_baseline", origin + "/"),
        ("generic_error_page", origin + "/" + uuid.uuid4().hex + ".json"),
    ):
        record = fetch(probe_url, timeout)
        record.setdefault("origin", origin)
        profiles.append(build_baseline_profile(record, kind=kind))
    return profiles


def main() -> int:
    args = build_parser().parse_args()

    file_baselines = load_baseline_profiles(args.baseline_file) if args.baseline_file else []
    baseline_cache: dict[str, list[dict]] = {}
    captured_origins: set[str] = set()

    def baselines_for(url: str) -> list[dict]:
        origin = origin_of(url)
        if origin not in baseline_cache:
            matching = [row for row in file_baselines if str(row.get("origin") or "") == origin]
            if args.with_baseline and origin not in captured_origins:
                matching.extend(capture_baselines(url, args.timeout))
                captured_origins.add(origin)
            baseline_cache[origin] = matching
        return baseline_cache[origin]

    urls = [line.strip() for line in args.urls.read_text(encoding="utf-8").splitlines() if line.strip()]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for idx, url in enumerate(urls):
            handle.write(json.dumps(fetch(url, args.timeout, baselines=baselines_for(url)), ensure_ascii=False) + "\n")
            handle.flush()
            if idx != len(urls) - 1:
                time.sleep(args.delay)
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
