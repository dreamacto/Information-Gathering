"""Behavior tests for src/authorized_assessment/runtime/context_loader.py.

Covers implementation spec 3.6 items 1-10. Acceptance matrix 3.11 lives in
tests/test_context_loading_acceptance.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from authorized_assessment.runtime import context_loader as cl

REPO_MAP = cl.MAP_PATH


@pytest.fixture()
def engagement_dir(tmp_path: Path) -> Path:
    d = tmp_path / "engagements" / "example.test-20260829"
    d.mkdir(parents=True)
    (d / "engagement.json").write_text(json.dumps({"target": "example.test"}), encoding="utf-8")
    (d / "scope.csv").write_text("host,in_scope\nexample.test,yes\n", encoding="utf-8")
    (d / "phase_status.json").write_text(json.dumps({"phase": "alive_probe"}), encoding="utf-8")
    return d


@pytest.fixture()
def run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "runs" / "20260829_120000"
    d.mkdir(parents=True)
    return d


def test_l0_only_minimal_load():
    bundle = cl.load_context(task_type="offline_implementation")
    paths = [s.path for s in bundle.loaded_sources]
    assert paths == ["AGENTS.md", "ROE.md", "runtime/policy_snapshot.json"]
    assert all(s.layer == "L0" for s in bundle.loaded_sources)
    assert all(s.sha256 and s.content for s in bundle.loaded_sources)
    assert bundle.total_files == 3
    assert bundle.total_bytes > 0


def test_workflow_load_isolates_other_workflows():
    bundle = cl.load_context(task_type="offline_implementation", workflow="wz")
    loaded = [s.path for s in bundle.loaded_sources]
    assert ".agents/skills/wz/SKILL.md" in loaded
    assert all(".agents/skills/xcx/" not in p for p in loaded)
    assert all(".agents/skills/fh/" not in p for p in loaded)
    excluded_other = [e for e in bundle.excluded_sources if e.reason == "other_workflow"]
    excluded_paths = [e.path for e in excluded_other]
    assert any(p.endswith("fh/SKILL.md") for p in excluded_paths)
    assert any(p.endswith("xcx/SKILL.md") for p in excluded_paths)


def test_phase_whitelist_and_optional_missing():
    bundle = cl.load_context(task_type="offline_implementation", phase="miniapp_auth")
    loaded = [s.path for s in bundle.loaded_sources]
    assert ".agents/skills/xcx/references/package-analysis.md" in loaded
    # Batch 10 落地后契约文件已存在：registered + loaded（不再是 missing → unavailable）
    schema_source = next(
        s for s in bundle.loaded_sources if s.path.endswith("miniapp_auth_schema.json")
    )
    assert schema_source.exists is True
    assert "contracts/miniapp_auth_schema.json" not in bundle.unavailable
    assert bundle.missing_required == []
    # batch10_4 扩充的三模块与测试条目（required: false，全部存在）
    assert "src/authorized_assessment/miniapp/platform_login_exchange.py" in loaded
    assert "src/authorized_assessment/miniapp/session_token_lifecycle.py" in loaded
    assert "src/authorized_assessment/miniapp/signature_replay_review.py" in loaded
    assert "tests/test_miniapp_auth_lifecycle.py" in loaded


def test_phase_whitelist_storage_package_section():
    """batch11_4：miniapp_storage_package 段（契约+三模块+两测试文件，required:false）。"""
    bundle = cl.load_context(task_type="offline_implementation", phase="miniapp_storage_package")
    loaded = [s.path for s in bundle.loaded_sources]
    assert "contracts/miniapp_storage_package_schema.json" in loaded
    assert "src/authorized_assessment/miniapp/package_integrity_update.py" in loaded
    assert "src/authorized_assessment/miniapp/local_data_exposure.py" in loaded
    assert "src/authorized_assessment/miniapp/crypto_secret_review.py" in loaded
    assert "tests/test_package_integrity_update.py" in loaded
    assert "tests/test_miniapp_storage_crypto.py" in loaded
    assert "contracts/miniapp_storage_package_schema.json" not in bundle.unavailable
    assert bundle.missing_required == []
    # 上一 phase 的条目不加载（phase 白名单隔离）
    assert not any(p.endswith("miniapp_auth_schema.json") for p in loaded)


def test_phase_whitelist_reconciliation_section():
    """batch12_5：miniapp_reconciliation 段（契约+对账模块+测试文件，required:false）。"""
    bundle = cl.load_context(task_type="offline_implementation", phase="miniapp_reconciliation")
    loaded = [s.path for s in bundle.loaded_sources]
    assert "contracts/miniapp_reconciliation_schema.json" in loaded
    assert "src/authorized_assessment/miniapp/static_dynamic_reconciliation.py" in loaded
    assert "tests/test_static_dynamic_reconciliation.py" in loaded
    assert "contracts/miniapp_reconciliation_schema.json" not in bundle.unavailable
    assert bundle.missing_required == []
    # 其他 miniapp 段的条目不加载（phase 白名单隔离）
    assert not any(p.endswith("miniapp_cloud_schema.json") for p in loaded)
    assert not any(p.endswith("miniapp_storage_package_schema.json") for p in loaded)


def test_phase_whitelist_cloud_section():
    """batch12_5：miniapp_cloud 段（契约+三模块+共享测试文件，required:false）。"""
    bundle = cl.load_context(task_type="offline_implementation", phase="miniapp_cloud")
    loaded = [s.path for s in bundle.loaded_sources]
    assert "contracts/miniapp_cloud_schema.json" in loaded
    assert "src/authorized_assessment/miniapp/cloud_function_review.py" in loaded
    assert "src/authorized_assessment/miniapp/cloud_storage_review.py" in loaded
    assert "src/authorized_assessment/miniapp/third_party_boundary_review.py" in loaded
    assert "tests/test_miniapp_cloud_review.py" in loaded
    assert "contracts/miniapp_cloud_schema.json" not in bundle.unavailable
    assert bundle.missing_required == []
    # 对账段条目不加载（phase 白名单隔离）
    assert not any(p.endswith("miniapp_reconciliation_schema.json") for p in loaded)


def test_phase_whitelist_webview_section():
    """batch13_4：miniapp_webview 段（契约+测试文件，required:false；webview 域无
    src 模块——规格 6.8 既有 phase 增固定产物，batch13_0 D4）。"""
    bundle = cl.load_context(task_type="offline_implementation", phase="miniapp_webview")
    loaded = [s.path for s in bundle.loaded_sources]
    assert "contracts/miniapp_webview_schema.json" in loaded
    assert "tests/test_xcx_webview_artifacts.py" in loaded
    assert "contracts/miniapp_webview_schema.json" not in bundle.unavailable
    assert bundle.missing_required == []
    # 其他 miniapp 段的条目不加载（phase 白名单隔离）
    assert not any(p.endswith("miniapp_cloud_schema.json") for p in loaded)
    assert not any(p.endswith("miniapp_reconciliation_schema.json") for p in loaded)


def test_phase_section_pointer_missing_section_unavailable():
    bundle = cl.load_context(task_type="offline_implementation", phase="graphql")
    # tool_strategy.json 存在但没有 graphql 键（Batch 6 才落地）→ unavailable，不 fail-closed。
    assert "tool_strategy.json#graphql" in bundle.unavailable
    assert not bundle.fail_closed


def test_unknown_workflow_or_phase_fail_loudly():
    with pytest.raises(cl.ContextLoadError, match="workflow not in loading map"):
        cl.load_context(task_type="offline_implementation", workflow="nope")
    with pytest.raises(cl.ContextLoadError, match="phase not in loading map"):
        cl.load_context(task_type="offline_implementation", phase="nope")


def test_engagement_l0_required_fail_closed(tmp_path: Path):
    empty = tmp_path / "engagements" / "empty"
    empty.mkdir(parents=True)
    bundle = cl.load_context(task_type="offline_implementation", engagement_dir=empty)
    assert "empty" in str(bundle.missing_required) or any(
        "engagement.json" in p for p in bundle.missing_required
    )
    assert any("scope.csv" in p for p in bundle.missing_required)
    assert bundle.fail_closed
    # L0 缺失时不加载 L1/L2
    assert all(s.layer == "L0" for s in bundle.loaded_sources)


def test_engagement_l0_loaded_with_cursor_optional(engagement_dir: Path):
    bundle = cl.load_context(task_type="offline_implementation", engagement_dir=engagement_dir)
    loaded = [s.path for s in bundle.loaded_sources]
    assert any(p.endswith("engagement.json") for p in loaded)
    assert any(p.endswith("scope.csv") for p in loaded)
    assert any(p.endswith("phase_status.json") for p in loaded)
    assert bundle.missing_required == []


def test_credential_and_draft_exclusion_never_read(engagement_dir: Path, run_dir: Path):
    marker = "SECRET_COOKIE_MARKER_ABC123"
    (run_dir / "auth_sessions.local.json").write_text(marker, encoding="utf-8")
    (run_dir / "sessions.jsonl").write_text(marker, encoding="utf-8")
    reports = run_dir / "reports"
    reports.mkdir()
    (reports / "draft_report.html").write_text(marker, encoding="utf-8")
    bundle = cl.load_context(
        task_type="review",
        engagement_dir=engagement_dir,
        run_dir=run_dir,
        include_history=True,
    )
    excluded = {(e.path, e.reason) for e in bundle.excluded_sources}
    assert any("auth_sessions.local.json" in p and r == "credential_file" for p, r in excluded)
    assert any("sessions.jsonl" in p and r == "credential_file" for p, r in excluded)
    assert any("draft_report.html" in p and r == "raw_response" for p, r in excluded)
    for source in bundle.loaded_sources:
        assert source.content is None or marker not in source.content


def test_history_gate_disabled_by_default(run_dir: Path):
    index = run_dir / cl.HISTORY_INDEX_NAME
    index.write_text(
        json.dumps([{"path": "runs/old/candidates.json", "classification": "historical_fact"}]),
        encoding="utf-8",
    )
    bundle = cl.load_context(task_type="review", run_dir=run_dir)
    assert bundle.historical_inputs == []
    assert any(e.reason == "history_disabled" for e in bundle.excluded_sources)


def test_history_gate_requires_allowed_task_type(run_dir: Path):
    (run_dir / cl.HISTORY_INDEX_NAME).write_text("[]", encoding="utf-8")
    bundle = cl.load_context(
        task_type="wz_phase", run_dir=run_dir, include_history=True
    )
    assert bundle.historical_inputs == []
    assert any(c.startswith("history_not_allowed_for_task_type") for c in bundle.context_conflicts)


def test_history_index_classification_and_conflicts(run_dir: Path):
    index = run_dir / cl.HISTORY_INDEX_NAME
    index.write_text(
        json.dumps(
            [
                {"path": "runs/old/a.json", "classification": "historical_fact"},
                {"path": "runs/old/b.json", "classification": "derived_pattern"},
                {"path": "runs/old/c.json", "classification": "not_a_classification"},
                {"bad": "entry"},
            ]
        ),
        encoding="utf-8",
    )
    bundle = cl.load_context(task_type="precision_analysis", run_dir=run_dir, include_history=True)
    assert len(bundle.historical_inputs) == 2
    assert any(c.startswith("history_index_bad_classification") for c in bundle.context_conflicts)
    assert any(c.startswith("history_index_bad_entry") for c in bundle.context_conflicts)


def test_scope_not_confirmed_blocks_active_actions():
    bundle = cl.load_context(task_type="offline_implementation")
    assert any(c.startswith("scope_not_confirmed") for c in bundle.context_conflicts)
    assert bundle.active_actions_blocked is True
    assert not bundle.fail_closed  # 快照本身有效，只是 scope 未确认


def test_blocked_actions_drift_fails_closed(monkeypatch, tmp_path: Path):
    tampered = tmp_path / "gov_exercise_config.json"
    real = json.loads(Path("gov_exercise_config.json").read_text(encoding="utf-8"))
    real["blocked_actions"] = real["blocked_actions"][:-1]  # 少一项
    tampered.write_text(json.dumps(real), encoding="utf-8")
    monkeypatch.setattr(cl, "config_path", lambda name, **kw: tampered)
    bundle = cl.load_context(task_type="offline_implementation")
    assert any(c.startswith("policy_snapshot_blocked_actions_drift") for c in bundle.context_conflicts)
    assert bundle.fail_closed


def test_missing_policy_snapshot_fails_closed(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cl, "policy_snapshot_path", lambda: tmp_path / "nope.json")
    bundle = cl.load_context(task_type="offline_implementation")
    assert "policy_snapshot_missing" in bundle.context_conflicts
    assert bundle.fail_closed


def test_missing_repo_l0_fail_fast_via_map_copy(tmp_path: Path):
    copied_map = tmp_path / "map.yaml"
    text = REPO_MAP.read_text(encoding="utf-8").replace(
        "path: AGENTS.md", "path: does_not_exist/AGENTS_MISSING.md"
    )
    copied_map.write_text(text, encoding="utf-8")
    bundle = cl.load_context(
        task_type="offline_implementation", workflow="wz", map_path=copied_map
    )
    assert any("AGENTS_MISSING" in p for p in bundle.missing_required)
    assert bundle.fail_closed
    # fail-fast：L0 坏掉后不再加载 L1
    assert all(s.layer == "L0" for s in bundle.loaded_sources)


def test_content_cap_truncates_but_hash_stays_full(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cl, "CONTENT_SIZE_CAP", 10)
    bundle = cl.load_context(task_type="offline_implementation")
    agents = next(s for s in bundle.loaded_sources if s.path == "AGENTS.md")
    assert agents.truncated is True
    assert len(agents.content) == 10
    assert len(agents.sha256) == 64


def test_snapshot_dict_contains_schema_required_fields():
    schema = json.loads(
        Path("contracts/context_snapshot_schema.json").read_text(encoding="utf-8")
    )
    bundle = cl.load_context(task_type="offline_implementation", workflow="wz")
    snap = bundle.to_snapshot_dict(engagement_id=None)
    for field in schema["required"]:
        assert field in snap, field
    valid_reasons = set(
        schema["properties"]["excluded_sources"]["items"]["properties"]["reason"]["enum"]
    )
    for excluded in snap["excluded_sources"]:
        assert excluded["reason"] in valid_reasons, excluded
    for historical in snap["historical_inputs"]:
        assert historical["classification"] in ("historical_fact", "derived_pattern", "stale_reference")


def test_summarize_reports_counts():
    bundle = cl.load_context(task_type="offline_implementation", workflow="fh")
    text = cl.summarize(bundle)
    assert f"loaded_files={bundle.total_files}" in text
    assert f"loaded_bytes={bundle.total_bytes}" in text
    assert f"excluded={bundle.excluded_count}" in text


def test_load_is_deterministic():
    # 严格分批逐项验证.md 第十二节第 6 类：重复/幂等例——同一输入两次加载结果一致。
    first = cl.load_context(task_type="offline_implementation", workflow="wz")
    second = cl.load_context(task_type="offline_implementation", workflow="wz")
    hashes_first = {s.path: s.sha256 for s in first.loaded_sources}
    hashes_second = {s.path: s.sha256 for s in second.loaded_sources}
    assert hashes_first == hashes_second
    assert first.total_files == second.total_files
    assert first.total_bytes == second.total_bytes
    assert first.context_conflicts == second.context_conflicts
