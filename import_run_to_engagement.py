#!/usr/bin/env python3
"""import_run_to_engagement.py —— 把一键流程 run 产物导入 engagement 端点清单（20260822 复盘 P1）。

打通 L0 广度 → L1 深度：run 里结构化的 api_confirmed/api_candidates 直接变成
engagement 工作区的端点清单种子行，替代手工从 jsonl 抄端点。

用法：
  python import_run_to_engagement.py --run-dir runs/<ts> --engagement engagements/<名-日期>

规则：
  - 来源仅只读 GET 类：api_confirmed.jsonl / api_interesting.jsonl / api_candidates.jsonl
  - 写 <engagement>/artifacts/endpoint-inventory.csv（无则建表头，有则按 host+method+path 去重追加）
  - 全部标记 test_status=untested、source=run_import；query 参数名进 parameters 列
  - 零网络请求
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
    ap = argparse.ArgumentParser(description="run → engagement 端点清单导入（零网络）")
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--engagement", type=Path, required=True)
    a = ap.parse_args()
    run_dir = a.run_dir if a.run_dir.is_absolute() else ROOT / a.run_dir
    eng = a.engagement if a.engagement.is_absolute() else ROOT / a.engagement
    if not run_dir.is_dir():
        print(f"[!] run 目录不存在: {run_dir}")
        return 2

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

    inv = eng / "artifacts" / "endpoint-inventory.csv"
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
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        if new_file:
            w.writeheader()
        w.writerows(fresh)

    print(f"[+] 导入 {len(fresh)} 个端点（来源 run={run_dir.name}；confirmed/interesting/candidate 优先级去重）")
    print(f"[+] → {inv}（文件 {'新建' if new_file else '追加'}，host#method#path 全局去重后）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
