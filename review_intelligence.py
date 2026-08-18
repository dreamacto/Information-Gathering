#!/usr/bin/env python3
"""Offline candidate ranking and per-target dossier builder.

This module is deliberately offline. It reads the artifacts produced by the
runner, merges repeated leads, assigns P0-P3 review priority, and writes a
per-host dossier so the operator can manually review richer context without
digging through every raw scan file first.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict:
    if not path.exists() or not path.read_text(encoding="utf-8", errors="ignore").strip():
        return {}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def csv_join(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(item) for item in value if item not in (None, ""))
    return str(value)


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_join(row.get(key, "")) for key in fieldnames})


def host_of(value: str) -> str:
    try:
        parsed = urlparse(str(value or ""))
    except Exception:
        return ""
    return (parsed.hostname or parsed.netloc or str(value or "")).lower()


def origin_of(value: str) -> str:
    try:
        parsed = urlparse(str(value or ""))
    except Exception:
        return str(value or "").rstrip("/")
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return str(value or "").rstrip("/")


def safe_filename(value: str) -> str:
    raw = re.sub(r"[^A-Za-z0-9_.\-\u4e00-\u9fff]+", "_", value or "target").strip("._-")
    return raw[:120] or "target"


def md_safe(value: object, limit: int = 180) -> str:
    return csv_join(value).replace("|", "/").replace("\n", " ")[:limit]


def priority_tier(score: int) -> str:
    if score >= 85:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    return "P3"


def stable_key(family: str, host: str, target: str, param: str = "") -> str:
    raw = f"{family}|{host}|{target}|{param}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def normalize_score(value, default: int = 0) -> int:
    try:
        return max(0, min(100, int(float(value))))
    except (TypeError, ValueError):
        return default


def score_from_confidence(confidence: str, high_probability: bool = False) -> int:
    if high_probability:
        return 88
    return {
        "critical": 88,
        "high": 82,
        "medium": 64,
        "low": 45,
        "manual_only": 42,
        "review": 55,
    }.get(str(confidence or "").lower(), 35)


def add_candidate(
    items: dict[str, dict],
    *,
    family: str,
    target: str,
    host: str = "",
    base_url: str = "",
    param: str = "",
    score: int = 0,
    confidence: str = "",
    reasons=None,
    evidence=None,
    source: str = "",
    manual_next_step: str = "",
) -> None:
    target = str(target or base_url or host or "")
    if not target:
        return
    host = host or host_of(target) or host_of(base_url)
    key = stable_key(family, host, target, param)
    row = items.setdefault(key, {
        "candidate_id": key[:16],
        "priority": priority_tier(score),
        "score": score,
        "family": family,
        "confidence": confidence,
        "host": host,
        "base_url": base_url or origin_of(target),
        "target": target,
        "param": param,
        "reasons": [],
        "evidence": [],
        "sources": [],
        "manual_next_step": manual_next_step,
        "claim_boundary": "Candidate only. Manually verify before reporting; do not treat automated leads as confirmed vulnerabilities.",
    })
    if score > int(row.get("score") or 0):
        row["score"] = score
        row["priority"] = priority_tier(score)
    if confidence and not row.get("confidence"):
        row["confidence"] = confidence
    if manual_next_step and not row.get("manual_next_step"):
        row["manual_next_step"] = manual_next_step
    for field, values in (("reasons", reasons), ("evidence", evidence), ("sources", [source] if source else [])):
        if values is None:
            continue
        if not isinstance(values, (list, tuple, set)):
            values = [values]
        row[field].extend(str(value) for value in values if value not in (None, ""))


def build_candidates(run_dir: Path) -> list[dict]:
    items: dict[str, dict] = {}

    for row in read_jsonl(run_dir / "second_pass_confirmed.jsonl"):
        family = str(row.get("family") or "second_pass")
        score = normalize_score(row.get("score"), 78)
        if row.get("stable"):
            score = max(score, 82)
        target = row.get("url") or row.get("probe_url") or row.get("host") or ""
        add_candidate(
            items,
            family=family,
            target=str(target),
            host=str(row.get("host") or ""),
            param=str(row.get("param") or ""),
            score=score,
            confidence=str(row.get("priority") or ""),
            reasons=row.get("reasons") or row.get("signals") or row.get("second_signals") or [],
            evidence="second_pass_stable",
            source="second_pass_confirmed.jsonl",
            manual_next_step="优先单条复核二次复测稳定的候选，截图保留差异/字段/上下文，不扩大验证范围。",
        )

    for row in read_jsonl(run_dir / "second_pass_results.jsonl"):
        if row.get("stable"):
            continue
        family = str(row.get("family") or "second_pass")
        score = normalize_score(row.get("score"), 45)
        target = row.get("url") or row.get("probe_url") or row.get("host") or ""
        add_candidate(
            items,
            family=family,
            target=str(target),
            host=str(row.get("host") or ""),
            param=str(row.get("param") or ""),
            score=score,
            confidence=str(row.get("priority") or ""),
            reasons=row.get("reasons") or row.get("signals") or row.get("second_signals") or [],
            evidence="second_pass_unstable_or_low_signal",
            source="second_pass_results.jsonl",
            manual_next_step="作为备用线索复核；如果不能复现或只是统一错误页，直接降级/丢弃。",
        )

    for filename, source_boost in (("sqli_high_probability.jsonl", 86), ("sqli_candidates.jsonl", 0)):
        for row in read_jsonl(run_dir / filename):
            signals = row.get("signals") or []
            score = normalize_score(row.get("candidate_score"), 0)
            score = max(score, source_boost or score_from_confidence(str(row.get("confidence") or ""), bool(row.get("high_probability"))))
            if any(str(signal).startswith("db_error_signature") for signal in signals):
                score = max(score, 86)
            add_candidate(
                items,
                family="sqli",
                target=str(row.get("url") or ""),
                host=str(row.get("host") or ""),
                base_url=str(row.get("base_url") or ""),
                param=str(row.get("param") or ""),
                score=score,
                confidence=str(row.get("confidence") or ""),
                reasons=signals,
                evidence=[row.get("notes") or "", f"baseline_stability={row.get('baseline_stability', '')}"],
                source=filename,
                manual_next_step="用单 URL、单参数在 Repeater 里复核差异；不跑批量 SQLMap、不导库、不做延时/写入验证。",
            )

    for row in read_jsonl(run_dir / "header_reflection_candidates.jsonl"):
        header = str(row.get("header") or "")
        cookie_key = str(row.get("cookie_key") or "")
        add_candidate(
            items,
            family="sql_injection",
            target=str(row.get("url") or ""),
            host=str(row.get("host") or ""),
            base_url=str(row.get("url") or "").split("?")[0],
            param=f"{header}{('.' + cookie_key) if cookie_key else ''}",
            score=86,
            confidence="header_reflection",
            reasons=[f"header_reflected_count={row.get('reflection_count', '')}",
                     f"context={str(row.get('context_snippet') or '')[:120]}"],
            evidence=str(row.get("suggest_command") or ""),
            source="header_reflection_candidates.jsonl",
            manual_next_step="只读探测确认该 Header 值被服务端读取回显；用建议命令在 Repeater 中复核注入差异，"
                             "不跑批量 SQLMap、不导库、不做延时/写入验证。",
        )

    for row in read_jsonl(run_dir / "xss_reflection_checks.jsonl"):
        if not row.get("marker_reflected"):
            continue
        confidence = str(row.get("confidence") or "low")
        score = normalize_score(row.get("candidate_score"), 0)
        score = max(score, 78 if confidence == "medium" else 62)
        add_candidate(
            items,
            family="xss",
            target=str(row.get("probe_url") or row.get("url") or ""),
            host=str(row.get("host") or ""),
            base_url=str(row.get("base_url") or ""),
            param=str(row.get("param") or ""),
            score=score,
            confidence=confidence,
            reasons=row.get("signals") or [row.get("reflection_context") or "marker_reflected"],
            evidence=f"context={row.get('reflection_context', '')}",
            source="xss_reflection_checks.jsonl",
            manual_next_step="只复核该参数的输出上下文和编码；随机标记反射不等于 XSS 成立。",
        )

    for row in read_jsonl(run_dir / "xss_candidates.jsonl"):
        if row.get("default_action") != "manual_only":
            continue
        score = min(55, normalize_score(row.get("score"), 35))
        add_candidate(
            items,
            family="xss",
            target=str(row.get("url") or ""),
            host=str(row.get("host") or ""),
            base_url=str(row.get("base_url") or ""),
            param=str(row.get("param") or ""),
            score=score,
            confidence="manual_only",
            reasons=row.get("reasons") or row.get("skip_reason") or [],
            evidence="possible_write_or_stored_context",
            source="xss_candidates.jsonl",
            manual_next_step="仅在自有记录且规则允许时人工确认；不要自动提交评论/公告/工单/昵称等写入位置。",
        )

    for filename, base_score in (
        ("authenticated_impact_candidates.jsonl", 86),
        ("api_interesting.jsonl", 72),
        ("impact_candidates.jsonl", 68),
        ("api_confirmed.jsonl", 55),
        ("api_candidates.jsonl", 45),
    ):
        for row in read_jsonl(run_dir / filename):
            target = str(row.get("url") or row.get("base_url") or "")
            if not target:
                continue
            score = base_score
            score += min(16, normalize_score(row.get("business_value_score"), 0) * 2)
            score += min(10, normalize_score(row.get("priority_score") or row.get("source_priority_score"), 0))
            if row.get("is_json") and not row.get("json_parse_error"):
                score += 8
            add_candidate(
                items,
                family="api",
                target=target,
                host=host_of(target) or host_of(str(row.get("base_url") or "")),
                base_url=str(row.get("base_url") or ""),
                score=min(95, score),
                confidence=str(row.get("priority") or row.get("finding") or ""),
                reasons=row.get("business_value_reasons") or row.get("tags") or row.get("source_tags") or row.get("finding") or [],
                evidence=[
                    f"status={row.get('status', '')}",
                    f"json={row.get('is_json', '')}",
                    f"keys={csv_join(row.get('top_level_keys') or row.get('first_item_keys') or [])}",
                ],
                source=filename,
                manual_next_step="只做只读字段/数量/权限边界复核；不调用导出、下载、删除、审批、短信、支付、改密接口。",
            )

    for row in read_jsonl(run_dir / "product_vuln_candidates.jsonl"):
        score = normalize_score(row.get("score"), 58)
        confidence = str(row.get("confidence") or row.get("priority") or "review")
        if confidence.lower() == "high":
            score = max(score, 76)
        add_candidate(
            items,
            family="product",
            target=str(row.get("url") or row.get("base_url") or ""),
            host=str(row.get("host") or ""),
            base_url=str(row.get("base_url") or ""),
            score=score,
            confidence=confidence,
            reasons=[row.get("product") or row.get("product_id") or "", row.get("candidate_type") or ""],
            evidence=row.get("evidence_to_collect") or row.get("safe_review") or "",
            source="product_vuln_candidates.jsonl",
            manual_next_step="先确认产品/版本/入口存在；RCE、反序列化、绕过、批量验证都需要单目标审批。",
        )

    for row in read_jsonl(run_dir / "fingerprint_deepening_plan.jsonl"):
        score = normalize_score(row.get("score"), 50)
        if str(row.get("priority") or "") in {"P0", "P1"}:
            score = max(score, 70)
        add_candidate(
            items,
            family="fingerprint_deepening",
            target=str(row.get("base_url") or ""),
            host=str(row.get("host") or ""),
            base_url=str(row.get("base_url") or ""),
            score=score,
            confidence=str(row.get("confidence") or row.get("priority") or "review"),
            reasons=[row.get("product") or row.get("product_id") or "", row.get("runner_followup") or ""],
            evidence=[
                f"tools={csv_join(row.get('tool_preference') or [])}",
                f"templates={csv_join(row.get('review_templates') or [])}",
            ],
            source="fingerprint_deepening_plan.jsonl",
            manual_next_step="按指纹后深入分支逐项复核：先做只读/离线确认；命令预览和审批队列不自动执行。",
        )

    for row in read_jsonl(run_dir / "shiro_candidates.jsonl"):
        confidence = str(row.get("confidence") or "review")
        score = max(normalize_score(row.get("score"), 0), score_from_confidence(confidence, False))
        add_candidate(
            items,
            family="shiro",
            target=str(row.get("url") or row.get("base_url") or ""),
            host=str(row.get("host") or ""),
            base_url=str(row.get("base_url") or ""),
            score=score,
            confidence=confidence,
            reasons=row.get("signals") or row.get("reasons") or [],
            evidence="rememberMe/login/java_candidate",
            source="shiro_candidates.jsonl",
            manual_next_step="先复核 rememberMe 行为和产品背景；不爆破 key，不发序列化/RCE payload。",
        )

    for row in read_jsonl(run_dir / "weak_credential_successes.jsonl"):
        add_candidate(
            items,
            family="weak_credential",
            target=str(row.get("base_url") or row.get("login_url") or ""),
            host=host_of(str(row.get("base_url") or row.get("login_url") or "")),
            score=90,
            confidence="success_candidate",
            reasons=[row.get("evidence") or "", row.get("preset_id") or ""],
            evidence=[f"username={row.get('username', '')}", f"password_profile={row.get('password_profile', '')}"],
            source="weak_credential_successes.jsonl",
            manual_next_step="人工打开确认最小影响面并截图；不要导出数据，不保存 Cookie/Token。",
        )

    auth_queue = read_json(run_dir / "manual_auth_queue.json")
    for item in auth_queue.get("items", []) if isinstance(auth_queue.get("items"), list) else []:
        add_candidate(
            items,
            family="auth_surface",
            target=str(item.get("base_url") or ""),
            host=str(item.get("host") or ""),
            score=58 if item.get("scope_state") == "in_current_scope" else 48,
            confidence=str(item.get("scope_state") or ""),
            reasons=item.get("reasons") or [],
            evidence=item.get("evidence_urls") or [],
            source="manual_auth_queue.json",
            manual_next_step="手动登录/注册拿 Cookie；只对授权范围内站点继续认证态只读复核。",
        )

    for filename, score, family in (
        ("verified_exposures.jsonl", 82, "exposure"),
        ("candidate_exposures.jsonl", 62, "exposure"),
    ):
        for row in read_jsonl(run_dir / filename):
            target = str(row.get("url") or row.get("final_url") or row.get("base_url") or "")
            add_candidate(
                items,
                family=family,
                target=target,
                host=host_of(target),
                score=score,
                confidence=str(row.get("finding") or row.get("family") or ""),
                reasons=row.get("body_keyword_hits") or row.get("reasons") or row.get("finding") or [],
                evidence=[f"status={row.get('status', '')}", f"title={row.get('title', '')}"],
                source=filename,
                manual_next_step="先排除统一错误页/随机 404；截图只保留必要证据并打码敏感值。",
            )

    output: list[dict] = []
    for row in items.values():
        row["reasons"] = sorted(set(row.get("reasons") or []))[:12]
        row["evidence"] = sorted(set(row.get("evidence") or []))[:10]
        row["sources"] = sorted(set(row.get("sources") or []))
        output.append(row)
    output.sort(key=lambda item: (item.get("priority", "P3"), -int(item.get("score") or 0), item.get("host", ""), item.get("family", "")))
    return output


def rows_for_host(rows: list[dict], host: str, limit: int = 80) -> list[dict]:
    return [row for row in rows if row.get("host") == host][:limit]


def raw_rows_for_host(run_dir: Path, filename: str, host: str, limit: int = 20) -> list[dict]:
    output: list[dict] = []
    for row in read_jsonl(run_dir / filename):
        text = " ".join(str(row.get(key) or "") for key in ("host", "url", "base_url", "final_url", "probe_url"))
        if host and host in text.lower():
            output.append(row)
            if len(output) >= limit:
                break
    return output


def target_rows(run_dir: Path) -> list[dict]:
    path = run_dir / "targets.csv"
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        return list(csv.DictReader(handle))


def write_candidate_markdown(run_dir: Path, rows: list[dict]) -> Path:
    lines = [
        "# P0-P3 Candidate Confidence",
        "",
        f"- Generated: {now_iso()}",
        f"- Candidates: {len(rows)}",
        "- P0/P1/P2/P3 are review priorities, not vulnerability conclusions.",
        "",
    ]
    counts = defaultdict(int)
    for row in rows:
        counts[str(row.get("priority") or "P3")] += 1
    lines.extend([
        "## Counts",
        "",
        f"- P0: {counts['P0']}",
        f"- P1: {counts['P1']}",
        f"- P2: {counts['P2']}",
        f"- P3: {counts['P3']}",
        "",
        "## Review Queue",
        "",
        "| Priority | Score | Family | Host | Target | Param | Reasons | Sources |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for row in rows[:300]:
        lines.append(
            f"| {row.get('priority')} | {row.get('score')} | {row.get('family')} | `{md_safe(row.get('host'), 80)}` | "
            f"`{md_safe(row.get('target'), 220)}` | `{md_safe(row.get('param'), 60)}` | "
            f"{md_safe(row.get('reasons'), 220)} | {md_safe(row.get('sources'), 160)} |"
        )
    lines.extend([
        "",
        "## Boundary",
        "",
        "- 自动线索只用于减少人工翻文件的工作量；提交前必须人工复核。",
        "- 不从 P0/P1 直接写成漏洞结论，先确认作用域、可复现性、影响面和截图证据。",
    ])
    out = run_dir / "reports" / "candidate_confidence.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def write_dossiers(run_dir: Path, rows: list[dict]) -> dict:
    dossier_dir = run_dir / "target_dossiers"
    dossier_dir.mkdir(parents=True, exist_ok=True)
    hosts = sorted({str(row.get("host") or "") for row in rows if row.get("host")})
    target_by_host: dict[str, list[dict]] = defaultdict(list)
    for target in target_rows(run_dir):
        host = host_of(str(target.get("url") or ""))
        if host:
            target_by_host[host].append(target)

    items = []
    index_lines = [
        "# Target Dossiers",
        "",
        f"- Generated: {now_iso()}",
        f"- Hosts: {len(hosts)}",
        "",
        "| Host | P0 | P1 | P2 | P3 | File |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for host in hosts:
        host_rows = rows_for_host(rows, host)
        counts = defaultdict(int)
        for row in host_rows:
            counts[str(row.get("priority") or "P3")] += 1
        filename = safe_filename(host) + ".md"
        path = dossier_dir / filename
        items.append({
            "host": host,
            "file": str(path),
            "candidate_count": len(host_rows),
            "p0": counts["P0"],
            "p1": counts["P1"],
            "p2": counts["P2"],
            "p3": counts["P3"],
        })
        index_lines.append(f"| `{host}` | {counts['P0']} | {counts['P1']} | {counts['P2']} | {counts['P3']} | `{filename}` |")

        fingerprints = raw_rows_for_host(run_dir, "fingerprints.jsonl", host, 5)
        tool_fps = raw_rows_for_host(run_dir, "tool_fingerprints.jsonl", host, 5)
        api_rows = raw_rows_for_host(run_dir, "api_candidates.jsonl", host, 20)
        confirmed_api = raw_rows_for_host(run_dir, "api_interesting.jsonl", host, 12)
        second_pass = raw_rows_for_host(run_dir, "second_pass_results.jsonl", host, 12)
        deepening = raw_rows_for_host(run_dir, "fingerprint_deepening_plan.jsonl", host, 12)
        weak_success = raw_rows_for_host(run_dir, "weak_credential_successes.jsonl", host, 5)

        lines = [
            f"# Target Dossier: {host}",
            "",
            f"- Generated: {now_iso()}",
            f"- Candidate count: {len(host_rows)}",
            f"- Priority mix: P0={counts['P0']} / P1={counts['P1']} / P2={counts['P2']} / P3={counts['P3']}",
            "",
            "## Target",
            "",
        ]
        for target in target_by_host.get(host, [])[:8]:
            lines.append(f"- `{md_safe(target.get('url'), 220)}` {md_safe(target.get('name'), 120)}")
        if not target_by_host.get(host):
            lines.append("- No direct targets.csv row matched this host; it may come from discovered API/subdomain artifacts.")

        lines.extend([
            "",
            "## Top Candidates",
            "",
            "| Priority | Score | Family | Target | Param | Reasons |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for row in host_rows[:30]:
            lines.append(
                f"| {row.get('priority')} | {row.get('score')} | {row.get('family')} | "
                f"`{md_safe(row.get('target'), 220)}` | `{md_safe(row.get('param'), 60)}` | {md_safe(row.get('reasons'), 220)} |"
            )

        lines.extend(["", "## Fingerprint Notes", ""])
        for row in fingerprints:
            lines.append(f"- probe: status={row.get('status')} categories={csv_join(row.get('categories'))} title={md_safe(row.get('title'), 140)}")
        for row in tool_fps:
            lines.append(f"- tool: technologies={csv_join(row.get('technologies') or row.get('tech'))} title={md_safe(row.get('title'), 140)}")
        if not fingerprints and not tool_fps:
            lines.append("- No fingerprint rows matched this host.")

        lines.extend(["", "## API Context", ""])
        for row in confirmed_api[:8]:
            lines.append(f"- confirmed JSON: `{md_safe(row.get('url'), 220)}` keys={md_safe(row.get('top_level_keys') or row.get('first_item_keys'), 160)}")
        for row in api_rows[:12]:
            lines.append(f"- candidate: score={row.get('priority_score')} `{md_safe(row.get('url'), 220)}` tags={md_safe(row.get('tags'), 120)}")
        if not api_rows and not confirmed_api:
            lines.append("- No API rows matched this host.")

        lines.extend(["", "## Second-Pass Notes", ""])
        for row in second_pass:
            lines.append(f"- {row.get('family')} stable={row.get('stable')} priority={row.get('priority')} score={row.get('score')} target=`{md_safe(row.get('url') or row.get('probe_url'), 220)}`")
        if not second_pass:
            lines.append("- No second-pass rows matched this host.")

        lines.extend(["", "## Fingerprint Deepening", ""])
        for row in deepening:
            lines.append(
                f"- {md_safe(row.get('product'), 80)} priority={row.get('priority')} "
                f"followup={md_safe(row.get('runner_followup'), 80)} tools={md_safe(row.get('tool_preference'), 160)}"
            )
        if not deepening:
            lines.append("- No fingerprint-deepening rows matched this host.")

        lines.extend(["", "## Weak Credential Notes", ""])
        for row in weak_success:
            lines.append(f"- success candidate: username={md_safe(row.get('username'), 80)} password_profile={md_safe(row.get('password_profile'), 80)} evidence={md_safe(row.get('evidence'), 120)}")
        if not weak_success:
            lines.append("- No weak-credential success candidate matched this host.")

        lines.extend([
            "",
            "## Manual Review Guardrails",
            "",
            "- 先确认目标仍在授权范围内，再做单条复核。",
            "- 只保存最小证据：状态、字段名、数量、hash、截图；敏感值打码。",
            "- 自动候选不等于漏洞结论；不能复现、统一错误页、登录页伪 200 都应降级。",
        ])
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    index_path = dossier_dir / "index.md"
    index_path.write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    manifest = {
        "created_at": now_iso(),
        "directory": str(dossier_dir),
        "index": str(index_path),
        "host_count": len(hosts),
        "items": items,
    }
    write_json(run_dir / "target_dossier_manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build offline P0-P3 candidate confidence and target dossiers")
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()

    rows = build_candidates(args.run_dir)
    write_jsonl(args.run_dir / "candidate_confidence.jsonl", rows)
    fields = [
        "priority",
        "score",
        "family",
        "confidence",
        "host",
        "base_url",
        "target",
        "param",
        "reasons",
        "evidence",
        "sources",
        "manual_next_step",
        "candidate_id",
    ]
    write_csv(args.run_dir / "candidate_confidence.csv", rows, fields)
    confidence_md = write_candidate_markdown(args.run_dir, rows)
    dossier_manifest = write_dossiers(args.run_dir, rows)
    summary = {
        "created_at": now_iso(),
        "candidate_count": len(rows),
        "p0": sum(1 for row in rows if row.get("priority") == "P0"),
        "p1": sum(1 for row in rows if row.get("priority") == "P1"),
        "p2": sum(1 for row in rows if row.get("priority") == "P2"),
        "p3": sum(1 for row in rows if row.get("priority") == "P3"),
        "candidate_confidence_md": str(confidence_md),
        "candidate_confidence_csv": str(args.run_dir / "candidate_confidence.csv"),
        "target_dossiers": dossier_manifest,
    }
    write_json(args.run_dir / "review_intelligence_manifest.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
