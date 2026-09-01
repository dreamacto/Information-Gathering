"""Acceptance matrix for context governance (implementation spec 3.11).

Each test maps to one numbered acceptance criterion in spec section 3.11.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from authorized_assessment.runtime import context_loader as cl
from authorized_assessment.runtime import context_snapshot as cs


@pytest.fixture()
def bundle_snapshot() -> dict:
    bundle = cl.load_context(task_type="offline_implementation", workflow="wz")
    return cs.build_snapshot_from_bundle(bundle)


@pytest.fixture()
def miniapp_run_dir(tmp_path: Path) -> Path:
    """A run dir stuffed with historical material that must never load as current fact."""
    run_dir = tmp_path / "runs" / "20260828_090000"
    (run_dir / "reports").mkdir(parents=True)
    (run_dir / "auth_sessions.local.json").write_text("COOKIE_VALUE_XYZ", encoding="utf-8")
    (run_dir / "sessions.jsonl").write_text("SESSION_RAW", encoding="utf-8")
    (run_dir / "reports" / "draft_findings.html").write_text("RAW RESPONSE BODY", encoding="utf-8")
    (run_dir / "candidates_full_history.json").write_text("[]", encoding="utf-8")
    index = run_dir / cl.HISTORY_INDEX_NAME
    index.write_text(
        json.dumps(
            [
                {"path": "runs/20260828_090000/candidates_full_history.json",
                 "classification": "historical_fact"},
            ]
        ),
        encoding="utf-8",
    )
    return run_dir


def test_acceptance_01_web_phase_never_loads_miniapp_rules():
    bundle = cl.load_context(task_type="offline_implementation", workflow="wz", phase="injection")
    loaded = [s.path for s in bundle.loaded_sources]
    assert not any(".agents/skills/xcx/" in p for p in loaded)
    assert not any(".agents/skills/fh/" in p for p in loaded)
    reasons = {(e.reason) for e in bundle.excluded_sources}
    assert "other_workflow" in reasons


def test_acceptance_02_miniapp_phase_never_loads_full_history(miniapp_run_dir: Path):
    bundle = cl.load_context(
        task_type="offline_implementation",
        workflow="xcx",
        phase="miniapp_auth",
        run_dir=miniapp_run_dir,
    )
    loaded = [s.path for s in bundle.loaded_sources]
    assert any(p.endswith("package-analysis.md") for p in loaded)
    # 历史目录内容一个都不进 loaded（历史索引也只在 include_history 时可用）
    assert not any("candidates_full_history" in p for p in loaded)
    excluded_paths = {e.path for e in bundle.excluded_sources}
    assert any("auth_sessions.local.json" in p for p in excluded_paths)


def test_acceptance_03_include_history_false_never_reads_history_content(miniapp_run_dir: Path):
    marker = "HISTORICAL_CANDIDATE_TEXT_MARKER"
    (miniapp_run_dir / "candidates_full_history.json").write_text(marker, encoding="utf-8")
    bundle = cl.load_context(
        task_type="offline_implementation", run_dir=miniapp_run_dir, include_history=False
    )
    assert bundle.historical_inputs == []
    for source in bundle.loaded_sources:
        assert source.content is None or marker not in source.content


def test_acceptance_04_credentials_and_raw_responses_excluded_by_default(miniapp_run_dir: Path):
    bundle = cl.load_context(
        task_type="offline_implementation", run_dir=miniapp_run_dir
    )
    reasons = {(e.path, e.reason) for e in bundle.excluded_sources}
    assert any(r == "credential_file" for _, r in reasons)
    assert any(r == "raw_response" for _, r in reasons)
    for source in bundle.loaded_sources:
        assert source.content is None or "COOKIE_VALUE_XYZ" not in source.content


def test_acceptance_05_missing_l0_fails_closed(tmp_path: Path):
    copied = tmp_path / "map.yaml"
    text = cl.MAP_PATH.read_text(encoding="utf-8").replace("path: ROE.md", "path: missing/ROE_MISSING.md")
    copied.write_text(text, encoding="utf-8")
    bundle = cl.load_context(task_type="offline_implementation", workflow="fh", map_path=copied)
    assert bundle.fail_closed
    assert any("ROE_MISSING" in p for p in bundle.missing_required)


def test_acceptance_06_rule_conflicts_detected_and_recorded():
    bundle = cl.load_context(task_type="offline_implementation")
    # 当前快照 authorization_status=unknown：scope 不明确 → 冲突已登记且主动动作被封
    assert any(c.startswith("scope_not_confirmed") for c in bundle.context_conflicts)
    assert bundle.active_actions_blocked is True


def test_acceptance_07_source_hash_change_triggers_reread_signal(bundle_snapshot: dict):
    assert cs.verify_source_hashes(bundle_snapshot) == []
    tampered = json.loads(json.dumps(bundle_snapshot))
    victim = sorted(tampered["source_hashes"])[0]
    tampered["source_hashes"][victim] = "a" * 64
    problems = cs.verify_source_hashes(tampered)
    assert f"hash_drift:{victim}" in problems  # 显式信号：必须重读


def test_acceptance_08_snapshot_restores_workflow_phase_and_facts(tmp_path: Path):
    bundle = cl.load_context(task_type="review", workflow="fh", phase=None)
    snapshot = cs.build_snapshot_from_bundle(bundle)
    written = cs.write_context_snapshot(snapshot, tmp_path / "context_snapshot.json")
    restored = cs.restore_from_snapshot(cs.load_context_snapshot(written))
    assert restored["task_type"] == "review"
    assert restored["workflow"] == "fh"
    assert restored["phase"] is None
    assert restored["current_facts"]
    assert restored["policy_digest"].get("blocked_actions")


def test_acceptance_09_current_facts_and_history_are_separate_columns(
    bundle_snapshot: dict, miniapp_run_dir: Path
):
    bundle = cl.load_context(
        task_type="review", run_dir=miniapp_run_dir, include_history=True
    )
    snapshot = bundle.to_snapshot_dict()
    fact_texts = " ".join(snapshot["current_facts"])
    for item in snapshot["historical_inputs"]:
        assert item["path"] not in fact_texts
        assert item["classification"] in ("historical_fact", "derived_pattern", "stale_reference")


def test_acceptance_10_counts_and_bytes_reported(bundle_snapshot: dict):
    bundle = cl.load_context(task_type="offline_implementation", workflow="wz")
    assert bundle.total_files == len(bundle.loaded_sources)
    assert bundle.total_bytes == sum(s.size_bytes for s in bundle.loaded_sources)
    report = cl.summarize(bundle)
    for key in ("loaded_files=", "loaded_bytes=", "excluded="):
        assert key in report


def test_acceptance_11_missing_required_phase_file_fails_explicitly(tmp_path: Path):
    copied = tmp_path / "map.yaml"
    # Batch 10 落地后 miniapp_auth_schema.json 已存在——改注入一个不存在的必需
    # 路径，保持被测语义（必需文件缺失 → missing_required + fail_closed）不变。
    text = cl.MAP_PATH.read_text(encoding="utf-8").replace(
        """    - path: contracts/miniapp_auth_schema.json
      purpose: 小程序认证态契约（已落地 Batch 10：三 phase/分支/产物路径/形状/红线）
      required: false""",
        """    - path: contracts/does_not_exist_acceptance11.json
      purpose: 验收11注入：必需缺失文件负例
      required: true""",
    )
    assert "does_not_exist_acceptance11.json" in text, "map mutation failed"
    copied.write_text(text, encoding="utf-8")
    bundle = cl.load_context(task_type="offline_implementation", phase="miniapp_auth", map_path=copied)
    assert any("does_not_exist_acceptance11.json" in p for p in bundle.missing_required)
    assert bundle.fail_closed
