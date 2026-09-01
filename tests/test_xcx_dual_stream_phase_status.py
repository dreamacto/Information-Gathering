"""Regression tests for xcx/wz phase cursor isolation."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".agents" / "skills" / "xcx" / "scripts" / "phase_status_routing.py"


def load_module():
    spec = importlib.util.spec_from_file_location("phase_status_routing_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_status(path: Path, phases: list[dict], *, stream: str | None = None):
    payload = {"schema_version": "1.0", "phases": phases}
    if stream is not None:
        payload["stream"] = stream
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_dual_stream_prefers_miniapp_cursor(tmp_path):
    mod = load_module()
    (tmp_path / "miniapp.json").write_text("{}", encoding="utf-8")
    write_status(tmp_path / "phase_status.json", [{"phase": "package_inventory", "status": "pending"}])
    write_status(tmp_path / "phase_status.miniapp.json", [{"phase": "package_inventory", "status": "complete"}], stream=mod.MINIAPP_STREAM)
    route = mod.resolve_phase_status(tmp_path)
    assert route.path.name == mod.MINIAPP_PHASE_STATUS_FILENAME
    assert route.stream == mod.MINIAPP_STREAM
    assert route.legacy_single_stream is False


def test_wz_cursor_is_rejected_when_miniapp_cursor_missing(tmp_path):
    mod = load_module()
    (tmp_path / "engagement.json").write_text(json.dumps({"engagement_name": "site", "target_input_sha256": "x"}), encoding="utf-8")
    (tmp_path / "miniapp.json").write_text("{}", encoding="utf-8")
    write_status(tmp_path / "phase_status.json", [{"phase": "retest", "status": "complete"}])
    route = mod.resolve_phase_status(tmp_path)
    assert route.path is None
    assert "phase_status.miniapp.json" in route.error
    assert "wz" in route.error


def test_legacy_standalone_xcx_is_read_only_compatibility(tmp_path):
    mod = load_module()
    (tmp_path / "miniapp.json").write_text("{}", encoding="utf-8")
    write_status(tmp_path / "phase_status.json", [
        {"phase": "identity", "status": "complete"},
        {"phase": "package_inventory", "status": "complete"},
        {"phase": "dynamic_mapping", "status": "pending"},
    ], stream=mod.MINIAPP_STREAM)
    route = mod.resolve_phase_status(tmp_path)
    assert route.path.name == mod.LEGACY_PHASE_STATUS_FILENAME
    assert route.legacy_single_stream is True


def test_new_workspace_write_route_is_miniapp_filename(tmp_path):
    mod = load_module()
    route = mod.resolve_phase_status(tmp_path, for_write=True)
    assert route.path.name == mod.MINIAPP_PHASE_STATUS_FILENAME
    assert not (tmp_path / mod.LEGACY_PHASE_STATUS_FILENAME).exists()
