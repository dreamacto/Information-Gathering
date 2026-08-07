#!/usr/bin/env python3
"""Convert Butian submit-domain export into gov_exercise_runner targets."""

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


def normalize_target(value: str) -> str:
    raw = (value or "").strip().strip("\"'“”‘’")
    if not raw:
        return ""
    if raw.startswith("www."):
        raw = "https://" + raw
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
    except Exception:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", "", ""))


def convert(csv_path: Path, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    targets_path = output_dir / "butian_confirmed_targets_from_submit_domains.txt"
    review_path = output_dir / "butian_submit_domains_review.csv"
    rows_out = []
    seen = set()
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            name = (row.get("name") or "").strip()
            target = normalize_target(row.get("normalized_target_url") or row.get("domain_or_ip") or "")
            cid = (row.get("company_id") or "").strip()
            status = (row.get("status") or "").strip()
            if not name or not target or target in seen:
                continue
            seen.add(target)
            rows_out.append(
                {
                    "target": target,
                    "name": name,
                    "company_id": cid,
                    "status": status,
                    "source_submit_url": (row.get("submit_url") or "").strip(),
                }
            )
    targets_path.write_text(
        "# Targets extracted from Butian submit pages' 域名或ip field.\n"
        "# Format: URL|organization name\n"
        + "\n".join(f"{row['target']}|{row['name']}" for row in rows_out)
        + ("\n" if rows_out else ""),
        encoding="utf-8",
    )
    with review_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["target", "name", "company_id", "status", "source_submit_url"])
        writer.writeheader()
        writer.writerows(rows_out)
    summary = {
        "generated_at": now_iso(),
        "source_csv": str(csv_path),
        "target_count": len(rows_out),
        "targets_path": str(targets_path),
        "review_path": str(review_path),
    }
    (output_dir / "butian_submit_domains_to_targets_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Butian submit-domain CSV to runner targets")
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("runs") / "butian_submit_domains")
    args = parser.parse_args()
    print(json.dumps(convert(args.csv, args.output_dir), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
