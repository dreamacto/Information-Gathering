#!/usr/bin/env python3
"""Build a screenshot work queue for report/evidence generation.

The queue is intentionally conservative.  Public pages can be captured by the
optional Playwright helper, while authenticated or sensitive findings stay as
manual screenshot tasks so cookies, tokens, response bodies, and personal data
are not silently stored in the run directory.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from exercise_runtime import BASE_DIR, now_iso, read_json, write_json


SCREENSHOT_FIELDS = [
    "id",
    "priority",
    "source",
    "title",
    "url",
    "host",
    "capture_policy",
    "output_file",
    "reason",
    "notes",
]

PUBLIC_POLICY = "public_metadata_only"
MANUAL_REDACTION_POLICY = "manual_redaction_required"
MANUAL_AUTH_POLICY = "manual_auth_required"

SENSITIVE_HINTS = re.compile(
    r"(token|cookie|password|passwd|secret|credential|session|jwt|authorization|heapdump|\.env|"
    r"export|download|delete|remove|upload|file|patient|student|idcard|身份证|手机号|密码|"
    r"个人|隐私|病人|患者|学生|导出|下载|删除|上传)",
    re.I,
)

PUBLIC_PAGE_HINTS = re.compile(
    r"(/$|login|signin|sso|cas|portal|index|home|swagger-ui|doc\.html|druid/login|"
    r"nacos|actuator/?$|actuator/health|actuator/info)",
    re.I,
)


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def safe_text(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text


def normalize_url(raw: object) -> str:
    value = safe_text(raw)
    if not value:
        return ""
    if value.startswith("//"):
        value = "https:" + value
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return value


def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def join_base_path(base_url: object, path: object) -> str:
    base = normalize_url(base_url)
    rel = safe_text(path)
    if not base:
        return normalize_url(rel)
    if not rel:
        return base
    if rel.startswith("http://") or rel.startswith("https://"):
        return normalize_url(rel)
    if not rel.startswith("/"):
        rel = "/" + rel
    return base.rstrip("/") + rel


def slugify(value: str, fallback: str) -> str:
    text = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", value)
    text = re.sub(r"[\\/:*?\"<>|#%&={}]+", "_", text)
    text = re.sub(r"\s+", "_", text).strip("._ ")
    text = text[:90].strip("._ ")
    return text or fallback


def policy_for_url(url: str, *, source: str, row: dict) -> str:
    joined = " ".join(
        safe_text(value)
        for value in [
            url,
            source,
            row.get("kind"),
            row.get("candidate_type"),
            row.get("title"),
            row.get("description"),
            row.get("reason"),
            row.get("notes"),
        ]
    )
    if source in {"authenticated_impact_candidates", "authenticated_api_results", "api_interesting"}:
        return MANUAL_AUTH_POLICY
    if SENSITIVE_HINTS.search(joined):
        return MANUAL_REDACTION_POLICY
    if PUBLIC_PAGE_HINTS.search(url):
        return PUBLIC_POLICY
    if source in {"probe_results", "priority_targets", "product_vuln_candidates", "manual_auth_queue", "shiro_candidates"}:
        return PUBLIC_POLICY
    return MANUAL_REDACTION_POLICY


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SCREENSHOT_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in SCREENSHOT_FIELDS})


def add_row(rows: list[dict], seen: set[str], *, source: str, title: str, url: str, priority: str, reason: str, notes: str, row: dict) -> None:
    normalized = normalize_url(url)
    if not normalized:
        return
    key = normalized.rstrip("/").lower()
    if key in seen:
        return
    seen.add(key)
    item_id = f"S{len(rows) + 1:03d}"
    out_name = f"{item_id}_{slugify(normalized, 'screenshot')}.png"
    rows.append({
        "id": item_id,
        "priority": priority,
        "source": source,
        "title": title,
        "url": normalized,
        "host": host_of(normalized),
        "capture_policy": policy_for_url(normalized, source=source, row=row),
        "output_file": f"evidence/screenshots/{out_name}",
        "reason": reason,
        "notes": notes,
    })


def build_rows(run_dir: Path) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()

    manual_auth = read_json(run_dir / "manual_auth_queue.json")
    for item in manual_auth.get("items", [])[:30] if isinstance(manual_auth.get("items"), list) else []:
        evidence_urls = item.get("evidence_urls") if isinstance(item.get("evidence_urls"), list) else []
        url = evidence_urls[0] if evidence_urls else item.get("base_url")
        add_row(
            rows,
            seen,
            source="manual_auth_queue",
            title="登录页/认证入口截图",
            url=safe_text(url),
            priority="high",
            reason="报告中常需要展示目标入口、登录边界或需要认证态复核的位置",
            notes="默认只截登录页或公开入口，不携带 Cookie。",
            row=item,
        )

    priority = read_json(run_dir / "priority_targets.json")
    for item in priority.get("items", [])[:40] if isinstance(priority.get("items"), list) else []:
        add_row(
            rows,
            seen,
            source="priority_targets",
            title="可报告候选页面截图",
            url=safe_text(item.get("url") or item.get("base_url")),
            priority="high" if int(item.get("score") or 0) >= 10 else "medium",
            reason="Top 候选需要最小截图证据，先证明页面/系统存在",
            notes="若页面含敏感数据，请手动打码后再放入报告。",
            row=item,
        )

    for item in read_jsonl(run_dir / "verified_exposures.jsonl")[:40]:
        url = safe_text(item.get("url")) or join_base_path(item.get("base_url"), item.get("path"))
        add_row(
            rows,
            seen,
            source="verified_exposures",
            title="已验证暴露候选截图",
            url=url,
            priority="high",
            reason="真伪校验通过的暴露候选，适合放入报告证据链",
            notes="敏感路径默认进入人工打码队列，自动脚本会跳过。",
            row=item,
        )

    for item in read_jsonl(run_dir / "product_vuln_candidates.jsonl")[:40]:
        add_row(
            rows,
            seen,
            source="product_vuln_candidates",
            title=f"产品候选截图：{safe_text(item.get('product') or item.get('candidate_type'))}",
            url=safe_text(item.get("base_url") or item.get("url")),
            priority=safe_text(item.get("confidence")) or "medium",
            reason=safe_text(item.get("safe_review") or "产品/框架候选需要先截图证明指纹和入口"),
            notes="只作为候选证据，不代表漏洞成立；不运行利用。",
            row=item,
        )

    for item in read_jsonl(run_dir / "shiro_candidates.jsonl")[:25]:
        add_row(
            rows,
            seen,
            source="shiro_candidates",
            title="Shiro 候选入口截图",
            url=safe_text(item.get("base_url") or item.get("url")),
            priority=safe_text(item.get("confidence")) or "medium",
            reason="Shiro 候选需要保留登录页、Cookie 行为或产品上下文截图",
            notes="只截公开入口；key 爆破/反序列化验证另行审批。",
            row=item,
        )

    for source_name in ("api_interesting", "authenticated_impact_candidates", "authenticated_api_results"):
        for item in read_jsonl(run_dir / f"{source_name}.jsonl")[:35]:
            add_row(
                rows,
                seen,
                source=source_name,
                title="接口/越权复核证据截图",
                url=safe_text(item.get("url") or item.get("endpoint") or item.get("base_url")),
                priority="high",
                reason="接口泄露/越权类报告通常需要浏览器或 Burp 证据截图",
                notes="认证态和敏感接口只生成清单，建议人工截图并打码。",
                row=item,
            )

    for item in read_jsonl(run_dir / "sqli_high_probability.jsonl")[:25]:
        add_row(
            rows,
            seen,
            source="sqli_high_probability",
            title="SQL 注入高概率线索截图",
            url=safe_text(item.get("url") or item.get("endpoint") or item.get("base_url")),
            priority="high",
            reason="SQLi 线索报告需要参数、响应差异和时间窗口说明",
            notes="默认人工截图；不要自动跑 SQLMap 或导出数据。",
            row=item,
        )

    for item in read_jsonl(run_dir / "probe_results.jsonl")[:50]:
        if not item.get("ok"):
            continue
        add_row(
            rows,
            seen,
            source="probe_results",
            title="存活页面截图",
            url=safe_text(item.get("url") or item.get("final_url")),
            priority="low",
            reason="补充报告中的资产存活和系统入口证据",
            notes="低优先级，只截公开页面。",
            row=item,
        )

    priority_rank = {"high": 0, "medium": 1, "low": 2}
    rows.sort(key=lambda item: (priority_rank.get(item["priority"], 1), item["capture_policy"], item["host"], item["url"]))
    for idx, row in enumerate(rows, 1):
        row["id"] = f"S{idx:03d}"
        row["output_file"] = f"evidence/screenshots/{row['id']}_{slugify(row['url'], 'screenshot')}.png"
    return rows


def write_markdown(path: Path, rows: list[dict]) -> None:
    public_count = sum(row["capture_policy"] == PUBLIC_POLICY for row in rows)
    manual_count = len(rows) - public_count
    lines = [
        "# 截图队列",
        "",
        f"- Generated: {now_iso()}",
        f"- Total: {len(rows)}",
        f"- 可自动截图: {public_count}",
        f"- 需要人工截图/打码: {manual_count}",
        "",
        "## 使用方式",
        "",
        "1. 先看 `capture_policy`。只有 `public_metadata_only` 会被一键截图脚本默认采集。",
        "2. `manual_auth_required` 代表需要你登录后手动截图，截图前打码 Cookie、Token、身份证、手机号、姓名等敏感值。",
        "3. `manual_redaction_required` 代表页面可能含敏感内容，建议手动打开、最小化展示、打码后放到 `evidence/screenshots/`。",
        "4. 自动截图脚本只做浏览器 GET 截图，不携带 Cookie，不保存响应正文。",
        "",
        "## 一键采集公开页面",
        "",
        "运行 `evidence/screenshots/截图队列_一键采集.bat`。",
        "",
        "| ID | Priority | Policy | Source | Host | URL | Reason |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows[:120]:
        reason = row["reason"].replace("|", "\\|")
        lines.append(
            f"| {row['id']} | {row['priority']} | `{row['capture_policy']}` | {row['source']} | "
            f"`{row['host']}` | `{row['url']}` | {reason} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_screenshot_readme(path: Path, rows: list[dict]) -> None:
    lines = [
        "# 截图目录说明",
        "",
        "这里存放报告用截图。自动脚本只会采集 `reports/screenshot_queue.csv` 中 `public_metadata_only` 的 URL。",
        "",
        "人工截图建议：",
        "",
        "- 截图里保留系统时间、目标 URL、权限身份或登录状态边界。",
        "- 接口泄露/越权截图只展示字段名、数量、状态码、权限差异，不展示完整敏感值。",
        "- Cookie、Token、Authorization、身份证、手机号、姓名、银行卡、病历、学生信息等必须打码。",
        "- 上传、SQLi、RCE、反序列化、弱口令等高风险证明需要按演练规则拿到明确许可。",
        "",
        f"当前队列总数：{len(rows)}。",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_capture_bat(run_dir: Path) -> Path:
    screenshot_dir = run_dir / "evidence" / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    node_path = Path.home() / ".cache" / "codex-runtimes" / "codex-primary-runtime" / "dependencies" / "node" / "bin" / "node.exe"
    node_modules = Path.home() / ".cache" / "codex-runtimes" / "codex-primary-runtime" / "dependencies" / "node" / "node_modules"
    script_path = BASE_DIR / "tools" / "report_screenshot_capture.mjs"
    bat = screenshot_dir / "截图队列_一键采集.bat"
    content = "\n".join([
        "@echo off",
        "chcp 65001 >nul",
        "setlocal",
        f"set \"RUN_DIR={run_dir}\"",
        f"set \"NODE={node_path}\"",
        "if not exist \"%NODE%\" set \"NODE=node\"",
        f"set \"NODE_PATH={node_modules};%NODE_PATH%\"",
        "\"%NODE%\" " + f"\"{script_path}\" --run-dir \"%RUN_DIR%\" --queue \"%RUN_DIR%\\reports\\screenshot_queue.csv\" --delay 3 --limit 60",
        "pause",
        "",
    ])
    bat.write_text(content, encoding="utf-8")
    return bat


def build_screenshot_queue(run_dir: Path) -> dict:
    run_dir = run_dir.resolve()
    rows = build_rows(run_dir)
    reports = run_dir / "reports"
    screenshot_dir = run_dir / "evidence" / "screenshots"
    csv_path = reports / "screenshot_queue.csv"
    md_path = reports / "screenshot_queue.md"
    readme_path = screenshot_dir / "README_截图说明.md"
    bat_path = write_capture_bat(run_dir)
    write_csv(csv_path, rows)
    write_markdown(md_path, rows)
    write_screenshot_readme(readme_path, rows)
    manifest = {
        "generated_at": now_iso(),
        "queue_csv": str(csv_path),
        "queue_md": str(md_path),
        "screenshot_dir": str(screenshot_dir),
        "capture_bat": str(bat_path),
        "total": len(rows),
        "public_metadata_only": sum(row["capture_policy"] == PUBLIC_POLICY for row in rows),
        "manual_auth_required": sum(row["capture_policy"] == MANUAL_AUTH_POLICY for row in rows),
        "manual_redaction_required": sum(row["capture_policy"] == MANUAL_REDACTION_POLICY for row in rows),
    }
    write_json(reports / "screenshot_queue_manifest.json", manifest)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build report screenshot queue from a run directory")
    parser.add_argument("--run-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    print(json.dumps(build_screenshot_queue(args.run_dir), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
