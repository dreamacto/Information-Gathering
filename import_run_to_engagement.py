#!/usr/bin/env python3
"""Import explicitly selected run endpoints as isolated WZ historical leads (offline only).

The importer never writes the current WZ endpoint inventory. It requires an explicit
historical-lead acknowledgement and preserves source lineage in an isolated copy.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse, parse_qsl

CST = timezone(timedelta(hours=8))
ROOT = Path(__file__).resolve().parent
FIELDS = ["endpoint_id", "host", "method", "path", "parameters", "content_type",
          "auth_required", "roles", "state_changing", "source", "test_status", "notes"]
# historical_lead 导入只写入隔离目录，不进入当前 WZ 主端点清单。
IMPORT_FIELDS = FIELDS + [
    "source_class", "source_run_id", "source_artifact", "source_item_id",
    "imported_at", "operator_ack", "current_validation_status",
]


def now_iso() -> str:
    return datetime.now(CST).isoformat(timespec="seconds")


def read_jsonl(p: Path) -> list[dict]:
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def endpoint_row(url: str, origin: str, status) -> dict | None:
    try:
        u = urlparse(str(url))
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.netloc:
        return None
    params = ",".join(sorted({name for name, _v in parse_qsl(u.query, keep_blank_values=True)}))
    eid = hashlib.sha256(f"{u.netloc.lower()}#GET#{u.path}".encode()).hexdigest()[:12]
    return {
        "endpoint_id": eid,
        "host": u.netloc.lower(),
        "method": "GET",
        "path": u.path or "/",
        "parameters": params,
        "content_type": "",
        "auth_required": "unknown",
        "roles": "",
        "state_changing": "no",
        "source": f"run_import:{origin}",
        "test_status": "untested",
        "notes": f"imported {now_iso()} observed_status={status}",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="run → WZ historical lead 隔离导入（零网络）")
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--engagement", type=Path, required=True)
    ap.add_argument("--source-kind", choices=("historical_lead",), required=True)
    ap.add_argument("--operator-ack", choices=("YES",), required=True)
    a = ap.parse_args()
    run_dir = a.run_dir if a.run_dir.is_absolute() else ROOT / a.run_dir
    eng = a.engagement if a.engagement.is_absolute() else ROOT / a.engagement
    if not eng.is_dir():
        print(f"[!] engagement 目录不存在: {eng}")
        return 2
    engagement_meta = {}
    meta_path = eng / "engagement.json"
    if meta_path.is_file():
        try:
            engagement_meta = json.loads(meta_path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError:
            print(f"[!] engagement.json 无法解析: {meta_path}")
            return 3
    if engagement_meta.get("workspace_type") not in (None, "wz_engagement"):
        print("[!] 目标不是 WZ engagement，拒绝导入")
        return 3
    scope_hosts = set()
    scope_path = eng / "scope.csv"
    if scope_path.is_file():
        with scope_path.open(encoding="utf-8-sig", newline="") as f:
            scope_hosts = {(r.get("asset") or "").strip().lower().lstrip("*.") for r in csv.DictReader(f)}
    run_id = run_dir.name
    if not run_id.strip():
        print("[!] source run 标识为空")
        return 3

    sources = [
        ("api_confirmed.jsonl", "confirmed"),
        ("api_interesting.jsonl", "interesting"),
        ("api_candidates.jsonl", "candidate"),
    ]
    rows: dict[str, dict] = {}
    for fname, origin in sources:
        for r in read_jsonl(run_dir / fname):
            url = r.get("url") or r.get("base_url")
            if not url:
                continue
            row = endpoint_row(url, origin, r.get("status"))
            if row and row["endpoint_id"] not in rows:
                # confirmed 优先级最高（先处理），同端点保留首个来源
                rows[row["endpoint_id"]] = row

    for row in rows.values():
        if scope_hosts and row["host"].split(":", 1)[0].lower().lstrip("*.") not in scope_hosts:
            continue
        row.update({
            "source_class": "historical_lead",
            "source_run_id": run_id,
            "source_artifact": row["source"].split(":", 1)[-1] + ".jsonl",
            "source_item_id": row["endpoint_id"],
            "imported_at": now_iso(),
            "operator_ack": "YES",
            "current_validation_status": "unverified",
        })

    inv = eng / "artifacts" / "imports" / "historical_leads" / run_id / "endpoint-inventory.csv"
    inv.parent.mkdir(parents=True, exist_ok=True)
    existing: set[str] = set()
    if inv.is_file():
        with inv.open(encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                existing.add((r.get("host") or "").lower() + "#" + (r.get("method") or "GET") + "#" + (r.get("path") or ""))
    fresh = []
    for row in rows.values():
        key = row["host"] + "#" + row["method"] + "#" + row["path"]
        if key in existing:
            continue
        existing.add(key)
        fresh.append(row)

    new_file = not inv.is_file()
    with inv.open("a", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=IMPORT_FIELDS, extrasaction="ignore")
        if new_file:
            w.writeheader()
        w.writerows(fresh)

    print(f"[+] 导入 {len(fresh)} 个 historical_lead 端点（来源 run={run_dir.name}；仅隔离副本）")
    print(f"[+] → {inv}（不修改 WZ 主 endpoint-inventory.csv）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
