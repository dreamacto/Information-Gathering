"""Regression tests for hard separation between WZ and FH inputs."""
from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WZ_INIT = ROOT / ".agents" / "skills" / "wz" / "scripts" / "init_engagement.py"
WZ_AUDIT = ROOT / ".agents" / "skills" / "wz" / "scripts" / "audit_engagement.py"
IMPORTER = ROOT / "import_run_to_engagement.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def init_wz(tmp_path: Path) -> Path:
    mod = load("wz_isolation_init", WZ_INIT)
    out = tmp_path / "engagement"
    old = sys.argv
    sys.argv = [str(WZ_INIT), "example.com", "--output", str(out)]
    try:
        assert mod.main() == 0
    finally:
        sys.argv = old
    return out


def test_wz_init_does_not_consume_fh_workspace(tmp_path):
    fh = tmp_path / "fh-shaped" / "postrun_review"
    fh.mkdir(parents=True)
    marker = fh / "fh-marker.txt"
    marker.write_text("FH_ONLY_SENTINEL", encoding="utf-8")
    wz = init_wz(tmp_path)
    assert (wz / "engagement.json").is_file()
    assert marker.read_text(encoding="utf-8") == "FH_ONLY_SENTINEL"
    meta = json.loads((wz / "engagement.json").read_text(encoding="utf-8"))
    assert meta["workspace_type"] == "wz_engagement"
    assert meta["source_policy"] == "current_engagement_only"
    assert meta["inheritance_policy"] == "deny_by_default"


def test_wz_audit_rejects_fh_shaped_directory(tmp_path):
    audit = load("wz_isolation_audit", WZ_AUDIT)
    fh = tmp_path / "postrun_review"
    fh.mkdir()
    (fh / "target_review_queue.csv").write_text("item_id\n", encoding="utf-8")
    result = audit.audit(fh)
    assert result["state"] == "WZ_RUN_DIRECTORY_REJECTED"
    assert any("postrun_review" in issue for issue in result["issues"])


def test_wz_audit_rejects_wrong_workspace_type(tmp_path):
    audit = load("wz_isolation_audit_type", WZ_AUDIT)
    root = tmp_path / "engagement"
    root.mkdir()
    (root / "engagement.json").write_text(json.dumps({"workspace_type": "fh_postrun_review", "workflow": "fh"}), encoding="utf-8")
    result = audit.audit(root)
    assert result["state"] == "WZ_WORKSPACE_TYPE_MISMATCH"


def test_run_import_requires_explicit_historical_lead_ack(tmp_path):
    run = tmp_path / "20260901_example_run"
    run.mkdir()
    (run / "api_candidates.jsonl").write_text(json.dumps({"url": "https://example.com/api/item?id=1", "status": 200}) + "\n", encoding="utf-8")
    wz = init_wz(tmp_path / "target")
    result = subprocess.run([sys.executable, str(IMPORTER), "--run-dir", str(run), "--engagement", str(wz)], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    assert result.returncode != 0
    assert "required" in (result.stderr + result.stdout).lower()


def test_run_import_writes_isolated_historical_lead_copy(tmp_path):
    run = tmp_path / "20260901_example_run"
    run.mkdir()
    (run / "api_candidates.jsonl").write_text(json.dumps({"url": "https://example.com/api/item?id=1", "status": 200}) + "\n", encoding="utf-8")
    wz = init_wz(tmp_path / "target")
    main_inv = wz / "artifacts" / "endpoint-inventory.csv"
    before = main_inv.read_bytes()
    result = subprocess.run([
        sys.executable, str(IMPORTER), "--run-dir", str(run), "--engagement", str(wz),
        "--source-kind", "historical_lead", "--operator-ack", "YES",
    ], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    assert result.returncode == 0, result.stdout + result.stderr
    assert main_inv.read_bytes() == before
    copies = list((wz / "artifacts" / "imports" / "historical_leads" / run.name).glob("*.csv"))
    assert len(copies) == 1
    with copies[0].open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows and rows[0]["source_class"] == "historical_lead"
    assert rows[0]["current_validation_status"] == "unverified"
