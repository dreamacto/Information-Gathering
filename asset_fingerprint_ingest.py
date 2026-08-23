#!/usr/bin/env python3
"""Cross-run cumulative asset fingerprint library.

Imports fingerprint evidence from a run directory (product_fingerprints.jsonl,
tool_fingerprints.jsonl, and optionally the app-specific triage candidates such
as shiro_candidates.jsonl) into a single accumulating library
``asset_fingerprint_lib.jsonl`` keyed by ``host + base_path + product``, then
regenerates per-product views under ``asset_fingerprint_views/``.

Rules
-----
* Dedup key is ``(host, base_path, product)`` so http/https or www variants of
  the same site collapse into one row while different apps on one host stay
  separate.
* Re-scanning the same target updates ``last_seen`` / ``seen_count``, keeps the
  earliest ``first_seen``, adopts a newer non-null version, and merges evidence
  sources.  Nothing is deleted: a target that stops appearing simply keeps a
  stale ``last_seen``.
* Importing the same run directory twice is idempotent.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

BASE_DIR = Path(__file__).resolve().parent

LIB_PATH = BASE_DIR / "asset_fingerprint_lib.jsonl"
VIEW_DIR = BASE_DIR / "asset_fingerprint_views"


def now_iso() -> str:
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def read_jsonl(path: Path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def canonical_url(url: str) -> str:
    """Lower-case host, drop default ports, strip trailing slash on paths."""
    if not url:
        return ""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    port = parts.port
    if port in (80, 443):
        port = None
    scheme = (parts.scheme or "http").lower()
    path = parts.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    netloc = host if not port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, path or "/", "", ""))


def base_path_of(url: str) -> str:
    """Directory-level base of a URL: /a/b/login.html -> /a/b/."""
    path = (urlsplit(url).path or "/")
    if path.endswith("/") or path == "":
        return path or "/"
    last = path.rsplit("/", 1)[-1]
    if "." in last:
        path = path.rsplit("/", 1)[0] + "/" if "/" in path else "/"
    else:
        path = path + "/"
    return path if path else "/"


def _tech_name_version(tech: str) -> tuple[str, str | None]:
    """Parse 'jQuery:3.3.1' -> ('jQuery', '3.3.1'); 'Nginx' -> ('Nginx', None)."""
    name = tech.strip()
    if not name:
        return "", None
    if ":" in name:
        left, _, right = name.rpartition(":")
        left = left.strip()
        if left and re.match(r"^\d+(\.\d+)*$", right.strip()):
            return left, right.strip()
    return name, None


# 入库卫生门（2026-08-23）：占位域不入库；纯 JS 关键词指纹（product_triage 打了
# needs-corroboration 标记的）不入库——今晨根库被灌 10 条误报指纹的事故防线。
PLACEHOLDER_HOST_RE = re.compile(
    r"(^|\.)(example|invalid|test|localhost|local|placeholder|replace[-_]me)(\.|$)",
    re.I,
)


def _row_allowed(row: dict, host: str) -> bool:
    if PLACEHOLDER_HOST_RE.search((host or "").lower()):
        return False
    notes = str(row.get("notes") or "")
    if "JS-keyword-only" in notes:
        return False
    return True


PRODUCT_PRIORITY = {
    "product_fingerprints": 3,
    "shiro_candidates": 2,
    "tool_fingerprints": 1,
}


def extract_rows(run_dir: Path) -> list[dict]:
    """Normalize all fingerprint sources of a run into library rows."""
    rows: list[dict] = []
    now = now_iso()

    for row in read_jsonl(run_dir / "product_fingerprints.jsonl"):
        url = str(row.get("base_url") or row.get("url") or "").rstrip("/")
        if not url:
            continue
        product = str(row.get("product_id") or row.get("product") or "").strip()
        if not product:
            continue
        if not _row_allowed(row, str(row.get("host") or "")):
            continue
        rows.append({
            "url": url,
            "host": row.get("host") or (urlsplit(url).hostname or ""),
            "product": product,
            "family": row.get("family") or "",
            "version": None,
            "version_source": None,
            "source": "product_fingerprints",
            "confidence": str(row.get("confidence") or "unknown"),
            "checked_at": row.get("checked_at") or now,
        })

    for row in read_jsonl(run_dir / "tool_fingerprints.jsonl"):
        url = str(row.get("url") or row.get("input_url") or "").rstrip("/")
        if not url:
            continue
        host = row.get("host") or (urlsplit(url).hostname or "")
        if not _row_allowed(row, str(host)):
            continue
        for tech in row.get("technologies") or []:
            name, version = _tech_name_version(str(tech))
            if not name:
                continue
            rows.append({
                "url": url,
                "host": host,
                "product": name,
                "family": "",
                "version": version,
                "version_source": "wappalyzer" if version else None,
                "source": "tool_fingerprints",
                "confidence": "medium",
                "checked_at": row.get("checked_at") or now,
            })

    for row in read_jsonl(run_dir / "shiro_candidates.jsonl"):
        url = str(row.get("url") or "").rstrip("/")
        if not url:
            continue
        if str(row.get("confidence") or "") != "high":
            continue
        if not _row_allowed(row, str(row.get("host") or urlsplit(url).hostname or "")):
            continue
        rows.append({
            "url": url,
            "host": row.get("host") or (urlsplit(url).hostname or ""),
            "product": "shiro",
            "family": "framework",
            "version": None,
            "version_source": None,
            "source": "shiro_candidates",
            "confidence": "high",
            "checked_at": row.get("checked_at") or now,
        })

    return rows


def merge_rows(library: dict, incoming: list[dict], now: str) -> None:
    for row in incoming:
        url = canonical_url(row["url"])
        if not url:
            continue
        host = (row.get("host") or (urlsplit(url).hostname or "")).lower()
        key = (host, base_path_of(url), str(row.get("product") or "").strip().lower())
        if not key[2]:
            continue
        src = str(row.get("source") or "unknown")
        priority = PRODUCT_PRIORITY.get(src, 0)
        entry = library.get(key)
        if entry is None:
            library[key] = {
                "url": url,
                "host": host,
                "base_path": key[1],
                "product": str(row.get("product") or "").strip(),
                "family": row.get("family") or "",
                "version": row.get("version"),
                "version_source": row.get("version_source"),
                "source": [src],
                "confidence": row.get("confidence") or "unknown",
                "first_seen": row.get("checked_at") or now,
                "last_seen": row.get("checked_at") or now,
                "seen_count": 1,
            }
            continue
        entry["last_seen"] = now
        entry["seen_count"] = int(entry.get("seen_count") or 0) + 1
        if src not in entry["source"]:
            entry["source"].append(src)
        if entry.get("confidence") in (None, "unknown", "low") and row.get("confidence") not in (None, "unknown", "low"):
            entry["confidence"] = row.get("confidence")
        if not entry.get("version") and row.get("version"):
            entry["version"] = row.get("version")
            entry["version_source"] = row.get("version_source")
        if not entry.get("family") and row.get("family"):
            entry["family"] = row.get("family")


def write_library(library: dict) -> None:
    LIB_PATH.write_text("", encoding="utf-8")
    for key in sorted(library):
        row = dict(library[key])
        row["key"] = "|".join(key)
        append_jsonl(LIB_PATH, row)


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def generate_views(library: dict) -> list[str]:
    by_product: dict[str, list[dict]] = {}
    for entry in library.values():
        by_product.setdefault(entry.get("product") or "other", []).append(entry)

    VIEW_DIR.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []
    for product, entries in sorted(by_product.items()):
        safe = "".join(c if (c.isalnum() or c in "-_") else "_" for c in product)
        lines = [f"# {product} ({len(entries)} assets)", ""]
        for entry in sorted(entries, key=lambda e: e["url"]):
            version = entry.get("version") or "(版本未知)"
            lines.append(f"{entry['url']} | {version} | 最近确认 {entry.get('last_seen') or '?'} | 源: {','.join(entry.get('source') or [])}")
        view = VIEW_DIR / f"{safe}.txt"
        view.write_text("\n".join(lines) + "\n", encoding="utf-8")
        generated.append(view.name)
    (VIEW_DIR / "README.md").write_text(
        "自动生成的按产品指纹视图。每次运行 asset_fingerprint_ingest.py 后重建，勿手工编辑。\n",
        encoding="utf-8",
    )
    return generated


def load_library() -> dict:
    library: dict = {}
    for row in read_jsonl(LIB_PATH):
        key = tuple(str(row.get("key") or "").split("|"))
        if len(key) == 3 and key[2]:
            library[key] = row
    return library


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import a run's fingerprints into the cumulative library.")
    parser.add_argument("--run-dir", type=Path, required=True, help="Run directory to import.")
    parser.add_argument("--views-only", action="store_true", help="Only rebuild views from existing library.")
    args = parser.parse_args(argv)

    run_dir: Path = args.run_dir
    if not run_dir.is_dir():
        print(f"run-dir not found: {run_dir}", file=sys.stderr)
        return 2

    now = now_iso()
    library = load_library()
    if not args.views_only:
        incoming = extract_rows(run_dir)
        merge_rows(library, incoming, now)
        write_library(library)
        print(f"imported {len(incoming)} raw rows -> {len(library)} unique assets in {LIB_PATH.name}")

    views = generate_views(library)
    print(f"generated {len(views)} views in {VIEW_DIR.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
