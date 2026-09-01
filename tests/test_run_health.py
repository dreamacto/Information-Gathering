"""run_health coverage 聚合与健康分修复测试（实施规格 3.2 / 13.2；batch1_3）。"""
from __future__ import annotations

import json

import run_health
from authorized_assessment.reporting import run_health as facade

ROOT = run_health.Path(__file__).resolve().parents[1]


def _write_targets(run_dir, targets_list=None, count=None):
    payload = {"source": "test", "imported_at": "2026-08-29T00:00:00+08:00"}
    if count is not None:
        payload["count"] = count
    if targets_list is not None:
        payload["targets"] = targets_list
    (run_dir / "targets.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_probes(run_dir, rows):
    with (run_dir / "probe_results.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _mk_run(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    return run_dir


def _target(url, host):
    return {"url": url, "name": host, "host": host, "scheme": "https", "port": 443, "source_line": ""}


# ---------------------------------------------------------------- 覆盖率语义


def test_coverage_uses_in_scope_targets_as_denominator(tmp_path):
    run_dir = _mk_run(tmp_path)
    _write_targets(run_dir, [_target("https://a.example", "a.example"),
                             _target("https://b.example", "b.example")])
    _write_probes(run_dir, [
        {"url": "https://a.example/", "ok": True, "status": 200},
        {"url": "https://b.example/", "ok": False, "status": 500},
    ])
    health = run_health.build_health(run_dir)
    assert health["unique_in_scope_targets"] == 2
    assert health["unique_targets_with_successful_probe"] == 1
    assert health["probe_coverage_ratio"] == 0.5


def test_out_of_scope_probes_do_not_inflate_coverage(tmp_path):
    run_dir = _mk_run(tmp_path)
    _write_targets(run_dir, [_target("https://a.example", "a.example")])
    _write_probes(run_dir, [
        {"url": f"https://out{i}.example/", "ok": True, "status": 200} for i in range(5)
    ])
    health = run_health.build_health(run_dir)
    assert health["probe_coverage_ratio"] == 0.0
    assert health["unique_targets_with_successful_probe"] == 0


def test_host_matching_counts_toward_target(tmp_path):
    run_dir = _mk_run(tmp_path)
    _write_targets(run_dir, [_target("https://a.example", "a.example")])
    _write_probes(run_dir, [
        {"url": "http://a.example:8080/deep/path?q=1", "ok": True, "status": 200},
    ])
    health = run_health.build_health(run_dir)
    assert health["probe_coverage_ratio"] == 1.0


def test_pct_is_always_clamped_to_unit_interval():
    assert run_health.pct(5, 2) == 1.0
    assert run_health.pct(0, 0) == 0.0
    assert run_health.pct(3, 10) == 0.3


def test_legacy_count_only_targets_still_supported(tmp_path):
    run_dir = _mk_run(tmp_path)
    _write_targets(run_dir, count=3)
    _write_probes(run_dir, [
        {"url": "https://a.example/", "ok": True, "status": 200},
        {"url": "https://b.example/", "ok": True, "status": 200},
        {"url": "https://c.example/", "ok": False, "status": 500},
    ])
    health = run_health.build_health(run_dir)
    assert health["unique_in_scope_targets"] == 3
    assert health["probe_coverage_ratio"] == round(2 / 3, 4)


# ---------------------------------------------------------------- 健康分负例修复


def test_all_failed_probes_cannot_yield_high_score(tmp_path):
    # 规格负例：全部失败但健康分较高 —— 修复前 target_count=0 时罚分分支不触发，score=100
    run_dir = _mk_run(tmp_path)
    _write_probes(run_dir, [
        {"url": f"https://x{i}.example/", "ok": False, "status": 0} for i in range(5)
    ])
    health = run_health.build_health(run_dir)
    assert health["probe_coverage_ratio"] == 0.0
    assert health["probe_ok_ratio"] == 0.0
    assert health["health_score"] <= 40
    assert any("No probe returned a successful response" in r for r in health["recommendations"])


def test_all_failed_with_targets_also_capped(tmp_path):
    run_dir = _mk_run(tmp_path)
    _write_targets(run_dir, [_target("https://a.example", "a.example")])
    _write_probes(run_dir, [{"url": "https://a.example/", "ok": False, "status": 500}])
    health = run_health.build_health(run_dir)
    assert health["health_score"] <= 40


def test_healthy_run_keeps_high_score(tmp_path):
    run_dir = _mk_run(tmp_path)
    _write_targets(run_dir, [_target("https://a.example", "a.example")])
    _write_probes(run_dir, [{"url": "https://a.example/", "ok": True, "status": 200}])
    health = run_health.build_health(run_dir)
    assert health["health_score"] >= 90
    assert health["probe_coverage_ratio"] == 1.0


# ---------------------------------------------------------------- 产物与 facade


def test_build_health_outputs_writes_json_and_markdown(tmp_path):
    run_dir = _mk_run(tmp_path)
    _write_targets(run_dir, [_target("https://a.example", "a.example")])
    _write_probes(run_dir, [{"url": "https://a.example/", "ok": True, "status": 200}])
    out = run_health.build_health_outputs(run_dir)
    assert (run_dir / "run_health.json").is_file()
    assert (run_dir / "reports" / "run_health.md").is_file()
    saved = json.loads((run_dir / "run_health.json").read_text(encoding="utf-8"))
    assert saved["unique_targets_with_successful_probe"] == 1
    md = (run_dir / "reports" / "run_health.md").read_text(encoding="utf-8")
    assert "In-scope targets probed successfully: 1/1" in md
    assert out["score"] == saved["health_score"]


def test_reporting_facade_exports_root_implementation():
    assert facade.build_health_outputs is run_health.build_health_outputs
    assert facade.build_health is run_health.build_health
    assert facade.pct is run_health.pct
    assert facade.write_markdown is run_health.write_markdown
