"""run_lifecycle 修复测试（实施规格 668-682 行；batch1_1）。

覆盖：Path 导入修复、review_aggregated 七项验证的正例与逐项负例、
既有状态推导不回归、blocked/needs_login/approval_required 显式计数。
"""
from __future__ import annotations

import csv
import json

import run_lifecycle
from authorized_assessment.quality import evaluate_run_quality

QUEUE_COLS = [
    "target_id", "review_order", "priority", "value_score", "host", "base_url",
    "representative_url", "run_dirs", "categories", "signals", "source_files",
    "safe_readonly_plan", "approval_gates", "rate_limit", "status", "disposition",
    "evidence_paths", "notes",
]
LEDGER_COLS = [
    "item_id", "order", "priority", "category", "run_dir", "source_file",
    "item_count", "safe_default", "approval_gate", "recommended_action", "status", "notes",
]


def _row(**overrides) -> dict:
    row = {col: "" for col in QUEUE_COLS}
    row.update(
        target_id="T-001",
        review_order="1",
        host="example-target",
        source_files="src/js_api.txt",
    )
    row.update(overrides)
    return row


def _ledger_row(source_file: str, status: str = "reviewed") -> dict:
    return {col: "" for col in LEDGER_COLS} | {
        "item_id": f"I-{source_file}",
        "source_file": source_file,
        "status": status,
    }


def _valid_quality_report() -> dict:
    targets = ["t0", "t1"]
    rows = [{"target": t, "ok": True, "error_class": None} for t in targets]
    return evaluate_run_quality(targets, rows)


def _make_run(
    tmp_path,
    queue_rows: list[dict] | None = None,
    ledger_rows: list[dict] | None = None,
    verdicts: dict[str, dict] | None = None,
    quality_report: dict | None = None,
    write_run_summary: bool = False,
):
    run_dir = tmp_path / "run"
    ws = run_dir / "postrun_review"
    (ws / "verdicts").mkdir(parents=True)
    if queue_rows is not None:
        with (ws / "target_review_queue.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=QUEUE_COLS)
            writer.writeheader()
            writer.writerows(queue_rows)
    if ledger_rows is not None:
        with (ws / "review_ledger.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=LEDGER_COLS)
            writer.writeheader()
            writer.writerows(ledger_rows)
    for name, data in (verdicts or {}).items():
        (ws / "verdicts" / f"{name}.json").write_text(
            json.dumps(data, ensure_ascii=False), encoding="utf-8"
        )
    if quality_report is not None:
        (run_dir / "run_quality.json").write_text(
            json.dumps(quality_report, ensure_ascii=False), encoding="utf-8"
        )
    if write_run_summary:
        (run_dir / "run_summary.json").write_text("{}", encoding="utf-8")
    return run_dir


def _verdict(order: str, disposition: str = "confirmed") -> dict:
    return {
        "review_order": int(order),
        "host": "example-target",
        "disposition": disposition,
        "confidence": 0.8,
        "basis": "dossier.md:10",
    }


# ---------------------------------------------------------------- Path 导入修复


def test_module_imports_cleanly():
    # 修复前第 30 行 ROOT = Path(...) 在导入期即 NameError
    assert run_lifecycle.ROOT == run_lifecycle.Path(run_lifecycle.__file__).resolve().parent


def test_review_aggregation_gate_exists():
    assert callable(run_lifecycle.evaluate_review_aggregation)


# ---------------------------------------------------------------- review_aggregated 正例


def test_review_aggregated_happy_path(tmp_path):
    queue = [
        _row(disposition="confirmed", evidence_paths="evidence/x.json"),
        _row(
            target_id="T-002", review_order="2", disposition="needs_login",
            notes="needs manual login", source_files="src/login.txt",
        ),
    ]
    ledger = [_ledger_row("src/js_api.txt"), _ledger_row("src/login.txt")]
    run_dir = _make_run(tmp_path, queue, ledger, quality_report=_valid_quality_report())
    info = run_lifecycle.derive(run_dir)
    assert "review_aggregated" in info["states"]
    agg = info["derived_from"]["review_aggregation"]
    assert agg["allowed"] is True
    assert all(agg["checks"].values())
    assert agg["counts"]["needs_login"] == 1


def test_review_aggregated_via_verdicts_for_pending_rows(tmp_path):
    # pending 行带合法非 pending verdict → 批次 verdict 已聚合（回填前的形态仍不放行，
    # 见 test_pending_queue_rows_block_aggregation：条件四要求队列无 pending）
    queue = [
        _row(disposition="confirmed", evidence_paths="evidence/x.json"),
        _row(target_id="T-002", review_order="2", source_files="src/login.txt"),
    ]
    ledger = [_ledger_row("src/js_api.txt"), _ledger_row("src/login.txt")]
    run_dir = _make_run(
        tmp_path, queue, ledger,
        verdicts={"2": _verdict("2", "needs_login")},
        quality_report=_valid_quality_report(),
    )
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["checks"]["batch_verdicts_aggregated"] is True
    assert agg["checks"]["no_pending_left"] is False
    assert agg["allowed"] is False


# ---------------------------------------------------------------- 七项验证逐项负例


def test_pending_row_without_verdict_denies(tmp_path):
    queue = [_row(disposition="confirmed", evidence_paths="evidence/x.json"),
             _row(target_id="T-002", review_order="2")]
    run_dir = _make_run(tmp_path, queue, [], quality_report=_valid_quality_report())
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["checks"]["batch_verdicts_aggregated"] is False
    assert any("batch_verdicts_missing_or_pending" in r for r in agg["reasons"])


def test_invalid_verdict_denies(tmp_path):
    queue = [_row()]
    verdict = _verdict("1")
    del verdict["basis"]
    run_dir = _make_run(tmp_path, queue, [], verdicts={"1": verdict},
                        quality_report=_valid_quality_report())
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["checks"]["batch_verdicts_aggregated"] is False
    assert any("verdicts_invalid" in r for r in agg["reasons"])


def test_bad_verdict_disposition_denies(tmp_path):
    queue = [_row()]
    run_dir = _make_run(tmp_path, queue, [], verdicts={"1": _verdict("1", "looks-fine")},
                        quality_report=_valid_quality_report())
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert any("bad_disposition" in r for r in agg["reasons"])


def test_unmapped_source_denies(tmp_path):
    queue = [_row(disposition="confirmed", evidence_paths="evidence/x.json",
                  source_files="src/unknown.txt")]
    ledger = [_ledger_row("src/js_api.txt")]
    run_dir = _make_run(tmp_path, queue, ledger, quality_report=_valid_quality_report())
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["checks"]["candidate_sources_mapped"] is False
    assert any("sources_not_in_ledger" in r for r in agg["reasons"])


def test_nonterminal_ledger_status_denies(tmp_path):
    queue = [_row(disposition="confirmed", evidence_paths="evidence/x.json")]
    ledger = [_ledger_row("src/js_api.txt", status="")]
    run_dir = _make_run(tmp_path, queue, ledger, quality_report=_valid_quality_report())
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["checks"]["ledger_queue_counts_consistent"] is False


def test_duplicate_ledger_rows_denies(tmp_path):
    queue = [_row(disposition="confirmed", evidence_paths="evidence/x.json")]
    ledger = [_ledger_row("src/js_api.txt"), _ledger_row("src/js_api.txt")]
    run_dir = _make_run(tmp_path, queue, ledger, quality_report=_valid_quality_report())
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["checks"]["ledger_queue_counts_consistent"] is False


def test_blocked_row_without_reason_denies(tmp_path):
    queue = [_row(disposition="confirmed", evidence_paths="evidence/x.json"),
             _row(target_id="T-002", review_order="2", disposition="blocked")]
    ledger = [_ledger_row("src/js_api.txt")]
    run_dir = _make_run(tmp_path, queue, ledger, quality_report=_valid_quality_report())
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["checks"]["blocking_dispositions_counted"] is False
    assert any("blocking_rows_without_reason" in r for r in agg["reasons"])
    assert agg["counts"]["blocked"] == 1


def test_confirmed_without_evidence_denies(tmp_path):
    queue = [_row(disposition="confirmed")]
    run_dir = _make_run(tmp_path, queue, [], quality_report=_valid_quality_report())
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["checks"]["confirmed_evidence_valid"] is False
    assert any("evidenced_rows_without_evidence" in r for r in agg["reasons"])


def test_missing_run_quality_report_denies(tmp_path):
    queue = [_row(disposition="confirmed", evidence_paths="evidence/x.json")]
    run_dir = _make_run(tmp_path, queue, [])
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["checks"]["run_quality_gate_allows_conclusions"] is False
    assert any("run_quality_report_missing" in r for r in agg["reasons"])


def test_inconclusive_quality_report_denies(tmp_path):
    targets = ["t0", "t1"]
    rows = [{"target": "t0", "ok": True, "error_class": None}]
    report = evaluate_run_quality(targets, rows)  # coverage 0.5 < 0.9 → INCONCLUSIVE
    assert report["quality_status"] == "INCONCLUSIVE"
    queue = [_row(disposition="confirmed", evidence_paths="evidence/x.json")]
    run_dir = _make_run(tmp_path, queue, [], quality_report=report)
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["checks"]["run_quality_gate_allows_conclusions"] is False
    assert any("run_quality_status_blocks_conclusions" in r for r in agg["reasons"])


def test_unparseable_quality_report_denies(tmp_path):
    queue = [_row(disposition="confirmed", evidence_paths="evidence/x.json")]
    run_dir = _make_run(tmp_path, queue, [])
    (run_dir / "run_quality.json").write_text("{broken", encoding="utf-8")
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert any("run_quality_report_unparseable" in r for r in agg["reasons"])


# ---------------------------------------------------------------- 既有行为不回归


def test_scan_done_only_for_bare_run(tmp_path):
    run_dir = _make_run(tmp_path, write_run_summary=True)
    info = run_lifecycle.derive(run_dir)
    assert "scan_done" in info["states"]
    assert "review_aggregated" not in info["states"]
    assert info["derived_from"]["review_aggregation"] is None


def test_review_in_progress_preserved(tmp_path):
    queue = [_row(), _row(target_id="T-002", review_order="2", disposition="confirmed",
                          evidence_paths="evidence/x.json")]
    run_dir = _make_run(tmp_path, queue, [], verdicts={"1": _verdict("1", "rejected")},
                        quality_report=_valid_quality_report())
    info = run_lifecycle.derive(run_dir)
    assert "review_in_progress" in info["states"]
    assert "review_aggregated" not in info["states"]


def test_counts_cover_all_blocking_dispositions(tmp_path):
    queue = [
        _row(target_id="T-001", review_order="1", disposition="blocked", notes="oob attempt"),
        _row(target_id="T-002", review_order="2", disposition="needs_login", notes="login"),
        _row(target_id="T-003", review_order="3", disposition="approval_required", notes="write"),
    ]
    ledger = [_ledger_row("src/js_api.txt")]
    run_dir = _make_run(tmp_path, queue, ledger, quality_report=_valid_quality_report())
    agg = run_lifecycle.evaluate_review_aggregation(run_dir, queue)
    assert agg["counts"] == {
        "queue_total": 3, "blocked": 1, "needs_login": 1, "approval_required": 1,
    }
