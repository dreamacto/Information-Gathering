#!/usr/bin/env python3
"""Convert Butian company_id export to submit URLs."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

from exercise_runtime import now_iso

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def convert(csv_path: Path, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    submit_csv = output_dir / "butian_submit_urls.csv"
    submit_txt = output_dir / "butian_submit_urls.txt"
    rows = []
    seen = set()
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            cid = (row.get("company_id") or row.get("cid") or "").strip()
            name = (row.get("name") or row.get("company_name") or "").strip()
            if not cid or not name or cid in seen:
                continue
            seen.add(cid)
            rows.append({
                "name": name,
                "company_id": cid,
                "submit_url": f"https://www.butian.net/Loo/submit?cid={cid}",
            })
    with submit_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["name", "company_id", "submit_url"])
        writer.writeheader()
        writer.writerows(rows)
    submit_txt.write_text(
        "\n".join(f"{row['submit_url']}|{row['name']}" for row in rows) + ("\n" if rows else ""),
        encoding="utf-8",
    )
    summary = {
        "generated_at": now_iso(),
        "source_csv": str(csv_path),
        "rows": len(rows),
        "submit_csv": str(submit_csv),
        "submit_txt": str(submit_txt),
        "note": "submit_url pages are platform pages used to read Butian-listed main/scope domains; they are not target scan URLs.",
    }
    (output_dir / "butian_company_ids_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Butian company_id CSV to submit URL list")
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("runs") / "butian_company_ids")
    args = parser.parse_args()
    print(json.dumps(convert(args.csv, args.output_dir), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
