#!/usr/bin/env python3
"""Convert Butian detail-URL export CSV into gov_exercise_runner targets."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from exercise_runtime import now_iso

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def normalize_url(value: str) -> str:
    value = (value or "").strip().strip("\"'“”‘’")
    if not value:
        return ""
    if value.startswith("www."):
        value = "https://" + value
    try:
        parsed = urlparse(value)
    except Exception:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", "", ""))


def split_urls(value: str) -> list[str]:
    urls: list[str] = []
    for part in (value or "").replace("\n", ";").replace(",", ";").split(";"):
        url = normalize_url(part)
        if url and url not in urls:
            urls.append(url)
    return urls


def convert(csv_path: Path, run_dir: Path) -> dict:
    out_path = run_dir / "butian_confirmed_targets_from_detail.txt"
    review_path = run_dir / "butian_detail_url_review.csv"
    rows_out: list[dict] = []
    target_lines: list[str] = []
    seen: set[str] = set()
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            name = (row.get("name") or "").strip()
            urls = split_urls(row.get("main_urls") or "") + split_urls(row.get("scope_urls") or "")
            if not urls:
                urls = split_urls(row.get("all_detail_urls") or "")
            for url in urls:
                key = (url, name)
                if url in seen:
                    continue
                seen.add(url)
                target_lines.append(f"{url}|{name}")
                rows_out.append({
                    "name": name,
                    "url": url,
                    "source_csv": str(csv_path),
                    "detail_href": row.get("detail_href", ""),
                    "detail_status": row.get("detail_status", ""),
                    "operator_scope_check": "verify Butian detail page scope before live testing if unsure",
                })
    out_path.write_text(
        "# Targets extracted from Butian vendor detail pages.\n"
        "# Format: URL|organization name\n"
        + "\n".join(target_lines)
        + ("\n" if target_lines else ""),
        encoding="utf-8",
    )
    fields = ["name", "url", "source_csv", "detail_href", "detail_status", "operator_scope_check"]
    with review_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows_out)
    summary = {
        "generated_at": now_iso(),
        "source_csv": str(csv_path),
        "run_dir": str(run_dir),
        "target_count": len(target_lines),
        "target_file": str(out_path),
        "review_csv": str(review_path),
    }
    (run_dir / "butian_detail_url_import_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Butian detail URL CSV to targets txt")
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(convert(args.csv, args.run_dir), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
