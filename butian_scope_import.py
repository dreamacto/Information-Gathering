#!/usr/bin/env python3
"""Import Butian vendor-name exports into an offline scope-confirmation run.

The Butian reward-plan list usually contains organization names, not direct
asset URLs. This importer deliberately does not probe the internet. It creates
operator queues for confirming official domains and platform scope before the
normal gov_exercise_runner workflow is allowed to run.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

from exercise_runtime import create_run_dir, now_iso

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify_name(name: str) -> str:
    if "医院" in name:
        return "hospital_or_medical_school"
    if "科学院" in name or "研究院" in name:
        return "research_institute"
    if "职业技术学院" in name or "职业学院" in name or "技师学院" in name:
        return "vocational_college"
    if "大学" in name:
        return "university"
    if "学院" in name:
        return "college"
    return "organization"


def read_butian_csv(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for raw in reader:
            name = str(raw.get("name") or "").strip()
            if not name:
                continue
            rows.append({
                "page": str(raw.get("page") or "").strip(),
                "name": name,
                "href": str(raw.get("href") or "").strip(),
                "source": str(raw.get("source") or "").strip(),
            })
    return rows


def normalize_rows(rows: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for row in rows:
        name = row["name"]
        item = grouped.setdefault(name, {
            "name": name,
            "type_hint": classify_name(name),
            "source_pages": set(),
            "source_urls": set(),
            "hrefs": set(),
        })
        if row.get("page"):
            item["source_pages"].add(str(row["page"]))
        if row.get("source"):
            item["source_urls"].add(str(row["source"]))
        if row.get("href"):
            item["hrefs"].add(str(row["href"]))

    output: list[dict] = []
    for index, item in enumerate(sorted(grouped.values(), key=lambda value: value["name"]), 1):
        output.append({
            "rank": index,
            "name": item["name"],
            "type_hint": item["type_hint"],
            "source_pages": ";".join(sorted(item["source_pages"], key=lambda value: (len(value), value))),
            "source_urls": ";".join(sorted(item["source_urls"])),
            "hrefs": ";".join(sorted(item["hrefs"])),
            "operator_action": "确认补天项目详情页/官方域名/授权范围；确认后把 URL 写入 butian_confirmed_targets.todo.txt",
            "scan_state": "not_scannable_name_only",
        })
    return output


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def dorks_for(name: str) -> list[str]:
    quoted = f'"{name}"'
    return [
        f'{quoted} 官网',
        f'{quoted} 官方网站',
        f'{quoted} ICP备案',
        f'site:.edu.cn {quoted}',
        f'site:.edu.cn {quoted} 信息中心',
        f'site:.edu.cn {quoted} 网络安全',
    ]


def build_dork_lines(rows: list[dict]) -> list[str]:
    lines = [
        "# Butian vendor-name dorks",
        "# Use these only to confirm official domains/scope; do not scan newly found assets until ownership is confirmed.",
        "",
    ]
    for row in rows:
        lines.append(f"## {row['name']}")
        lines.extend(dorks_for(row["name"]))
        lines.append("")
    return lines


def write_readme(run_dir: Path, source: Path, rows: list[dict]) -> None:
    type_counts = defaultdict(int)
    for row in rows:
        type_counts[row["type_hint"]] += 1
    lines = [
        "# 补天学院厂商名导入结果",
        "",
        f"- Created: {now_iso()}",
        f"- Source CSV: `{source}`",
        f"- Unique names: {len(rows)}",
        "",
        "## 结论",
        "",
        "这个 CSV 只有厂商/学院名称，没有域名或 URL，因此不能直接进入 `gov_exercise_runner.py --probe`。",
        "当前 run 已完成离线导入、去重、分类和人工确认队列生成；真正扫描前必须先确认补天项目详情页、官方域名和授权范围。",
        "",
        "## 分类数量",
        "",
    ]
    for key, count in sorted(type_counts.items()):
        lines.append(f"- {key}: {count}")
    lines.extend([
        "",
        "## 先看这些文件",
        "",
        "- `butian_vendor_names.csv`: 去重后的厂商/学院名称清单。",
        "- `butian_scope_manual_queue.csv`: 需要你逐项确认官方域名和补天授权范围的队列。",
        "- `butian_vendor_dorks.txt`: 辅助搜索官方域名/备案/信息中心的 dork。",
        "- `butian_confirmed_targets.todo.txt`: 把确认后的 URL 按 `https://example.edu.cn|机构名` 格式填进去。",
        "",
        "## 确认域名后再跑完整流程",
        "",
        "```powershell",
        "<python.exe> .\\gov_exercise_runner.py --targets \"" + str(run_dir / "butian_confirmed_targets.todo.txt") + "\" --label butian_academy --probe --fingerprint --high-value-paths --api-discovery --api-confirm --sqli-triage --shiro-triage --wechat-miniapp --healthcare-profile --delay 3",
        "```",
        "",
        "如果只想先建 run/合规材料，不发网络请求：",
        "",
        "```powershell",
        "<python.exe> .\\gov_exercise_runner.py --targets \"" + str(run_dir / "butian_confirmed_targets.todo.txt") + "\" --label butian_academy",
        "```",
        "",
        "## 边界",
        "",
        "- 不把机构名当作域名扫描。",
        "- 不对未确认归属/未确认补天范围的域名发起探测。",
        "- 新确认出来的域名仍然需要按项目规则保留证据、限速和停止条件。",
    ])
    (run_dir / "README_先看这里.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_todo(path: Path, rows: list[dict]) -> None:
    lines = [
        "# Fill confirmed Butian in-scope URLs here before running gov_exercise_runner.",
        "# Format: https://official.example.edu.cn|机构名",
        "# Keep only assets whose ownership and Butian program scope have been confirmed.",
        "",
    ]
    for row in rows:
        lines.append(f"# {row['name']}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Butian vendor-name CSV into an offline scope-confirmation run")
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--label", default="butian_academy_scope")
    args = parser.parse_args()

    rows_raw = read_butian_csv(args.csv)
    rows = normalize_rows(rows_raw)
    run_dir = create_run_dir(args.label)

    write_csv(
        run_dir / "butian_vendor_names.csv",
        rows,
        ["rank", "name", "type_hint", "source_pages", "source_urls", "hrefs", "operator_action", "scan_state"],
    )
    write_csv(
        run_dir / "butian_scope_manual_queue.csv",
        rows,
        ["rank", "name", "type_hint", "operator_action", "scan_state", "source_pages", "source_urls"],
    )
    (run_dir / "butian_vendor_names.txt").write_text(
        "\n".join(row["name"] for row in rows) + "\n",
        encoding="utf-8",
    )
    (run_dir / "butian_vendor_dorks.txt").write_text(
        "\n".join(build_dork_lines(rows)) + "\n",
        encoding="utf-8",
    )
    write_todo(run_dir / "butian_confirmed_targets.todo.txt", rows)
    write_readme(run_dir, args.csv, rows)

    manifest = {
        "created_at": now_iso(),
        "run_dir": str(run_dir),
        "source_csv": str(args.csv),
        "source_sha256": file_sha256(args.csv),
        "raw_rows": len(rows_raw),
        "unique_names": len(rows),
        "network_requests_sent": False,
        "live_scan_started": False,
        "reason_live_scan_not_started": "source CSV contains organization names only; no confirmed URLs/domains",
        "next_file_to_fill": str(run_dir / "butian_confirmed_targets.todo.txt"),
    }
    (run_dir / "butian_scope_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
