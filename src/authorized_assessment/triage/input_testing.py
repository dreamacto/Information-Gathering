"""input_testing 编排器（实施规格 5.4 input_testing 子阶段；orchestration_only）。

职责边界（操作员决定④⑥）：只负责编排与产物治理——初始化产物骨架、调用已接入的
筛选域（injection_candidate_screening / parser_deserialization_screening /
ssrf_candidate_screening / file_path_candidate_screening / browser_boundary_review
的既有模块）、把候选与类别汇总落盘、审计产物完整性。不重复执行任何子阶段探测动作
（不发请求、不发 payload、不签发 OOB token、不读本地文件）。

产物路径：规格 5.4 明示 artifacts/ssrf/ 三件与 artifacts/browser-boundary/
cors-csrf-cache.jsonl、reports/browser-boundary.md；injection/parser/file-path 三域
路径为规格未明示部分的实现定义（artifacts/input-testing/、artifacts/file-path/），
登记于 INPUT_TESTING_ARTIFACTS 单一事实源。全部离线、只读输入、幂等初始化。
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from authorized_assessment.triage import browser_boundary as bb
from authorized_assessment.triage import file_path_candidate_screening as fp
from authorized_assessment.triage import injection_candidates as ic
from authorized_assessment.triage import parser_deserialization as pdeser
from authorized_assessment.triage import ssrf_candidate_screening as ssrf

# 产物路径登记（相对 workspace 根；spec 5.4 明示 ssrf 三件与 browser-boundary 两件，
# 其余为实现定义）。
INPUT_TESTING_ARTIFACTS: dict[str, str] = {
    "injection_summary_csv": "artifacts/input-testing/injection-category-summary.csv",
    "injection_candidates_jsonl": "artifacts/input-testing/injection-candidates.jsonl",
    "parser_summary_csv": "artifacts/input-testing/parser-deserialization-category-summary.csv",
    "parser_candidates_jsonl": "artifacts/input-testing/parser-deserialization-candidates.jsonl",
    "ssrf_candidates_jsonl": "artifacts/ssrf/ssrf_candidates.jsonl",
    "ssrf_review_queue_csv": "artifacts/ssrf/ssrf_review_queue.csv",
    "oob_token_manifest": "artifacts/ssrf/oob_token_manifest.json",
    "browser_boundary_jsonl": "artifacts/browser-boundary/cors-csrf-cache.jsonl",
    "browser_boundary_report_md": "reports/browser-boundary.md",
    "file_path_summary_csv": "artifacts/file-path/file-path-category-summary.csv",
    "file_path_candidates_jsonl": "artifacts/file-path/file-path-candidates.jsonl",
}

SSRF_REVIEW_QUEUE_FIELDS = (
    "candidate_id",
    "status",
    "parameter_name",
    "source",
    "evidence_ref",
    "reason",
    "precondition",
)


def artifact_path(workspace: Path, key: str) -> Path:
    return Path(workspace) / INPUT_TESTING_ARTIFACTS[key]


def init_input_testing_artifacts(workspace: Path) -> list[str]:
    """初始化产物骨架（幂等：已存在的文件不覆盖，返回本次新建的相对路径列表）。"""
    workspace = Path(workspace)
    created: list[str] = []
    for key, rel in INPUT_TESTING_ARTIFACTS.items():
        path = workspace / rel
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if key.endswith("_csv"):
            if key.endswith("summary_csv"):
                _write_summary_csv(path, [])
            else:
                _write_queue_csv(path, [])
        elif key.endswith("_jsonl"):
            path.write_text("", encoding="utf-8")
        elif key == "oob_token_manifest":
            path.write_text(
                json.dumps({"schema_version": "1.0", "tokens": []}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        elif key == "browser_boundary_report_md":
            path.write_text(bb.build_browser_boundary_report([], []), encoding="utf-8")
        created.append(rel)
    return created


def _write_summary_csv(path: Path, summaries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(list(ic.CATEGORY_SUMMARY_FIELDS))
        for row in summaries:
            writer.writerow(
                [
                    row.get("category", ""),
                    row.get("category_status", ""),
                    json.dumps(row.get("applicability_counts", {}), ensure_ascii=False, sort_keys=True),
                    json.dumps(row.get("status_counts", {}), ensure_ascii=False, sort_keys=True),
                    row.get("tested_count", 0),
                    row.get("reason", ""),
                    row.get("source", ""),
                    row.get("precondition", ""),
                ]
            )


def _write_queue_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(SSRF_REVIEW_QUEUE_FIELDS))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in SSRF_REVIEW_QUEUE_FIELDS})


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def run_input_testing_screening(
    workspace: Path,
    *,
    injection_observations: list[dict] | None = None,
    parser_observations: list[dict] | None = None,
    ssrf_observations: list[dict] | None = None,
    browser_boundary_observations: list[dict] | None = None,
    file_path_observations: list[dict] | None = None,
    write: bool = True,
) -> dict:
    """已接入筛选域的筛选 + 落盘（离线端到端）。返回报告 dict；违例非空不视为失败——
    产物如实落盘，由 audit 与复核会话处置（筛选层不吞违例也不替人判定）。
    """
    workspace = Path(workspace)
    inj_rows, inj_summaries, inj_violations = ic.screen_observations(injection_observations or [])
    parser_rows, parser_summaries, parser_violations = pdeser.screen_parser_observations(
        parser_observations or []
    )
    ssrf_rows, ssrf_summary, ssrf_violations = ssrf.screen_ssrf_observations(ssrf_observations or [])
    bb_rows, bb_summaries, bb_violations = bb.screen_browser_boundary_observations(
        browser_boundary_observations or []
    )
    fp_rows, fp_summaries, fp_violations = fp.screen_file_path_observations(
        file_path_observations or []
    )
    report = {
        "domains": {
            "injection_candidate_screening": {
                "candidates": len(inj_rows),
                "summaries": len(inj_summaries),
                "violations": inj_violations,
            },
            "parser_deserialization_screening": {
                "candidates": len(parser_rows),
                "summaries": len(parser_summaries),
                "violations": parser_violations,
            },
            "ssrf_candidate_screening": {
                "candidates": len(ssrf_rows),
                "summary": ssrf_summary,
                "violations": ssrf_violations,
            },
            "browser_boundary_review": {
                "candidates": len(bb_rows),
                "summaries": len(bb_summaries),
                "violations": bb_violations,
            },
            "file_path_candidate_screening": {
                "candidates": len(fp_rows),
                "summaries": len(fp_summaries),
                "violations": fp_violations,
            },
        },
        "violations": inj_violations + parser_violations + ssrf_violations + bb_violations
        + fp_violations,
    }
    if write:
        init_input_testing_artifacts(workspace)
        _write_summary_csv(artifact_path(workspace, "injection_summary_csv"), inj_summaries)
        _write_jsonl(artifact_path(workspace, "injection_candidates_jsonl"), inj_rows)
        _write_summary_csv(artifact_path(workspace, "parser_summary_csv"), parser_summaries)
        _write_jsonl(artifact_path(workspace, "parser_candidates_jsonl"), parser_rows)
        _write_jsonl(artifact_path(workspace, "ssrf_candidates_jsonl"), ssrf_rows)
        _write_queue_csv(artifact_path(workspace, "ssrf_review_queue_csv"), ssrf_rows)
        _write_jsonl(artifact_path(workspace, "browser_boundary_jsonl"), bb_rows)
        report_md = artifact_path(workspace, "browser_boundary_report_md")
        report_md.parent.mkdir(parents=True, exist_ok=True)
        report_md.write_text(bb.build_browser_boundary_report(bb_summaries, bb_violations), encoding="utf-8")
        _write_summary_csv(artifact_path(workspace, "file_path_summary_csv"), fp_summaries)
        _write_jsonl(artifact_path(workspace, "file_path_candidates_jsonl"), fp_rows)
    return report


def _read_summary_csv(path: Path) -> tuple[list[dict], list[str]]:
    violations: list[str] = []
    summaries: list[dict] = []
    if not path.is_file():
        return [], [f"missing artifact: {path.name}"]
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header != list(ic.CATEGORY_SUMMARY_FIELDS):
            return [], [f"{path.name}: 表头与契约字段不符: {header}"]
        for line_no, raw in enumerate(reader, start=2):
            if not raw:
                continue
            try:
                summaries.append(
                    {
                        "category": raw[0],
                        "category_status": raw[1],
                        "applicability_counts": json.loads(raw[2]),
                        "status_counts": json.loads(raw[3]),
                        "tested_count": int(raw[4]),
                        "reason": raw[5],
                        "source": raw[6],
                        "precondition": raw[7],
                    }
                )
            except (IndexError, ValueError, json.JSONDecodeError) as exc:
                violations.append(f"{path.name}:L{line_no}: 解析失败 {exc}")
    return summaries, violations


def _read_jsonl(path: Path) -> tuple[list[dict], list[str]]:
    violations: list[str] = []
    rows: list[dict] = []
    if not path.is_file():
        return [], [f"missing artifact: {path.name}"]
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            violations.append(f"{path.name}:L{line_no}: 解析失败 {exc}")
    return rows, violations


def _consistency_violations(
    summaries: list[dict], candidate_rows: list[dict], label: str, category_key: str = "category"
) -> list[str]:
    """summary.status_counts / tested_count 必须与候选行归组重算一致（端到端闭环）。"""
    violations: list[str] = []
    grouped: dict[str, list[dict]] = {}
    for row in candidate_rows:
        grouped.setdefault(str(row.get(category_key) or ""), []).append(row)
    for summary in summaries:
        category = str(summary.get(category_key) or "")
        cat_rows = grouped.get(category, [])
        counts = {s: 0 for s in ic.CANDIDATE_STATUS_VALUES}
        for row in cat_rows:
            status = str(row.get("status") or "")
            if status in counts:
                counts[status] += 1
        for status, count in counts.items():
            recorded = int((summary.get("status_counts") or {}).get(status, 0))
            if recorded != count:
                violations.append(
                    f"{label}[{category}].status_counts.{status}={recorded} 与候选行重算 {count} 不一致"
                )
        recorded_tested = int(summary.get("tested_count") or 0)
        recomputed = sum(counts[s] for s in ic.DEFINITIVE_RESULT_STATUSES)
        if recorded_tested != recomputed:
            violations.append(
                f"{label}[{category}].tested_count={recorded_tested} 与候选行重算 {recomputed} 不一致"
            )
    orphan = sorted(set(grouped) - {str(s.get(category_key) or "") for s in summaries})
    if orphan:
        violations.append(f"{label}: 候选行存在汇总未覆盖的类别 {orphan}")
    return violations


def audit_input_testing(workspace: Path) -> tuple[bool, list[str]]:
    """审计 input_testing 产物：存在性 + 行契约 + summary↔候选一致性 + OOB manifest 红线。

    返回 (ok, violations)。产物从未生成（全部缺骨架）时同样报违例——审计不做静默通过。
    """
    workspace = Path(workspace)
    violations: list[str] = []
    missing = [rel for rel in INPUT_TESTING_ARTIFACTS.values() if not (workspace / rel).is_file()]
    if missing:
        violations.append(f"input_testing: 缺少产物文件 {missing}")
        return False, violations

    inj_summaries, v = _read_summary_csv(artifact_path(workspace, "injection_summary_csv"))
    violations += v
    inj_rows, v = _read_jsonl(artifact_path(workspace, "injection_candidates_jsonl"))
    violations += v
    for index, row in enumerate(inj_rows, start=1):
        violations += [
            f"injection-candidates.jsonl:L{index}: {msg}"
            for msg in ic.validate_injection_candidate(row, label=f"candidate[{row.get('candidate_id')}]")
        ]
    for summary in inj_summaries:
        violations += ic.validate_category_summary(summary, label="injection-category-summary")
    violations += _consistency_violations(inj_summaries, inj_rows, "injection-category-summary")

    parser_summaries, v = _read_summary_csv(artifact_path(workspace, "parser_summary_csv"))
    violations += v
    parser_rows, v = _read_jsonl(artifact_path(workspace, "parser_candidates_jsonl"))
    violations += v
    for index, row in enumerate(parser_rows, start=1):
        violations += [
            f"parser-candidates.jsonl:L{index}: {msg}"
            for msg in ic.validate_injection_candidate(row, label=f"candidate[{row.get('candidate_id')}]")
        ]
    for summary in parser_summaries:
        violations += ic.validate_category_summary(summary, label="parser-category-summary")
    violations += _consistency_violations(parser_summaries, parser_rows, "parser-category-summary")

    ssrf_rows, v = _read_jsonl(artifact_path(workspace, "ssrf_candidates_jsonl"))
    violations += v
    for index, row in enumerate(ssrf_rows, start=1):
        violations += [
            f"ssrf_candidates.jsonl:L{index}: {msg}"
            for msg in ssrf.validate_ssrf_candidate(row, label=f"candidate[{row.get('candidate_id')}]")
        ]
    queue_path = artifact_path(workspace, "ssrf_review_queue_csv")
    with queue_path.open("r", encoding="utf-8", newline="") as f:
        queue_rows = list(csv.DictReader(f))
    if len(queue_rows) != len(ssrf_rows):
        violations.append(
            f"ssrf_review_queue.csv 行数 {len(queue_rows)} 与 ssrf_candidates.jsonl {len(ssrf_rows)} 不一致"
        )

    manifest, err = None, None
    try:
        manifest = json.loads(artifact_path(workspace, "oob_token_manifest").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        err = str(exc)
    if err or not isinstance(manifest, dict):
        violations.append(f"oob_token_manifest.json 不可解析: {err}")
    else:
        violations += ssrf.validate_oob_token_manifest(manifest)

    bb_rows, v = _read_jsonl(artifact_path(workspace, "browser_boundary_jsonl"))
    violations += v
    for index, row in enumerate(bb_rows, start=1):
        violations += [
            f"cors-csrf-cache.jsonl:L{index}: {msg}"
            for msg in bb.validate_browser_boundary_candidate(
                row, label=f"candidate[{row.get('candidate_id')}]"
            )
        ]
    report_payload, report_err = bb.extract_report_summary(
        artifact_path(workspace, "browser_boundary_report_md").read_text(encoding="utf-8")
    )
    if report_err or report_payload is None:
        violations.append(f"browser-boundary.md: {report_err}")
    else:
        if str(report_payload.get("domain") or "") != "browser_boundary":
            violations.append("browser-boundary.md: domain 字段缺失或不符")
        if str(report_payload.get("schema_version") or "") != bb.REPORT_SCHEMA_VERSION:
            violations.append(
                f"browser-boundary.md: schema_version 与当前 {bb.REPORT_SCHEMA_VERSION!r} 不符"
            )
        bb_summaries = report_payload.get("category_summaries")
        if not isinstance(bb_summaries, list):
            violations.append("browser-boundary.md: category_summaries 必须为列表")
            bb_summaries = []
        for summary in bb_summaries:
            violations += ic.validate_category_summary(
                summary,
                label="browser-boundary-report",
                categories=bb.BROWSER_BOUNDARY_CATEGORIES,
            )
        violations += _consistency_violations(
            bb_summaries, bb_rows, "browser-boundary-report"
        )

    fp_summaries, v = _read_summary_csv(artifact_path(workspace, "file_path_summary_csv"))
    violations += v
    fp_rows, v = _read_jsonl(artifact_path(workspace, "file_path_candidates_jsonl"))
    violations += v
    for index, row in enumerate(fp_rows, start=1):
        violations += [
            f"file-path-candidates.jsonl:L{index}: {msg}"
            for msg in fp.validate_file_path_candidate(
                row, label=f"candidate[{row.get('candidate_id')}]"
            )
        ]
    for summary in fp_summaries:
        violations += ic.validate_category_summary(
            summary, label="file-path-category-summary", categories=fp.FILE_PATH_CATEGORIES
        )
    violations += _consistency_violations(fp_summaries, fp_rows, "file-path-category-summary")

    return not violations, violations
