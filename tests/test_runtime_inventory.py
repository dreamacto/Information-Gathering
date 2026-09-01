"""tests/test_runtime_inventory.py —— runtime_inventory 7.4 最小字段探针测试（Batch 4）。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from authorized_assessment.runtime import runtime_inventory as ri

ROOT = Path(__file__).resolve().parents[1]

# 规格 7.4 逐一对应的字段清单（顺序即契约顺序）
SPEC_74_MIN_FIELDS = (
    "python_path",
    "python_version",
    "requests_version",
    "urllib3_version",
    "pytest_available",
    "docx_available",
    "playwright_available",
    "crypto_available",
    "node_available",
    "java_available",
)


def test_min_fields_match_spec_740():
    assert ri.RUNTIME_INVENTORY_MIN_FIELDS == SPEC_74_MIN_FIELDS


def _ok_runner(returncode: int = 0):
    def runner(command, timeout):
        payload = {
            "python_version": "3.14.4",
            "requests": "2.33.1",
            "urllib3": "2.6.3",
            "pytest": "9.1.1",
            "docx": None,
            "playwright": None,
            "cryptography": "46.0.5",
            "Crypto": None,
        }
        return returncode, json.dumps(payload) + "\n"

    return runner


def test_probe_python_parses_versions_and_availability():
    fields = ri.probe_python("C:/fake/python.exe", runner=_ok_runner())
    assert fields["python_version"] == "3.14.4"
    assert fields["requests_version"] == "2.33.1"
    assert fields["urllib3_version"] == "2.6.3"
    assert fields["pytest_available"] is True
    assert fields["docx_available"] is False
    assert fields["playwright_available"] is False
    assert fields["crypto_available"] is True  # cryptography 或 Crypto 任一存在即可


def test_probe_python_crypto_via_pycryptodome():
    def runner(command, timeout):
        payload = {"python_version": "3.12.4", "requests": None, "urllib3": None,
                   "pytest": None, "docx": None, "playwright": None,
                   "cryptography": None, "Crypto": "3.21.0"}
        return 0, json.dumps(payload)

    assert ri.probe_python("python", runner=runner)["crypto_available"] is True


def test_probe_python_failure_yields_unknown_not_false():
    """探针失败必须记 None（unknown），不得伪造 False。"""
    fields = ri.probe_python("C:/fake/python.exe", runner=lambda cmd, t: (1, "boom"))
    for key in ("python_version", "requests_version", "urllib3_version"):
        assert fields[key] is None
    for key in ("pytest_available", "docx_available", "playwright_available", "crypto_available"):
        assert fields[key] is None


def test_probe_python_exception_yields_unknown():
    def runner(command, timeout):
        raise OSError("spawn failed")

    fields = ri.probe_python("C:/fake/python.exe", runner=runner)
    assert fields["python_version"] is None
    assert fields["pytest_available"] is None


def test_probe_python_empty_path_skips_subprocess():
    called = []

    def runner(command, timeout):
        called.append(command)
        return 0, "{}"

    assert ri.probe_python("", runner=runner)["python_version"] is None
    assert ri.probe_python(None, runner=runner)["python_version"] is None
    assert called == []


def test_probe_python_unparseable_output_yields_unknown():
    assert ri.probe_python("python", runner=lambda cmd, t: (0, "not json"))["python_version"] is None


def test_probe_external_which_and_java_path(tmp_path):
    java_exe = tmp_path / "java.exe"
    java_exe.write_bytes(b"")

    def which(name):
        return str(tmp_path / f"{name}.exe") if name == "node" else None

    result = ri.probe_external(str(java_exe), which_fn=which)
    assert result == {"node_available": True, "java_available": True}  # java 经绝对路径存在性判定

    result_no_path = ri.probe_external(None, which_fn=lambda name: None)
    assert result_no_path == {"node_available": False, "java_available": False}


def test_enrich_preserves_compat_keys_and_does_not_mutate_input():
    base = {
        "checked_at": "2026-08-29T00:00:00+08:00",
        "base_dir": str(ROOT),
        "tianhu_base": "",
        "python": "C:/fake/python.exe",
        "java": None,
        "tools": {"afrog": "x"},
    }
    snapshot = json.dumps(base, sort_keys=True)
    enriched = ri.enrich_runtime_inventory(base, runner=_ok_runner(), which_fn=lambda name: None)
    assert json.dumps(base, sort_keys=True) == snapshot  # 输入不被变异
    assert enriched["checked_at"] == base["checked_at"]  # 兼容键保留
    assert enriched["tools"] == base["tools"]
    assert enriched["python_path"] == "C:/fake/python.exe"
    for field in SPEC_74_MIN_FIELDS:
        assert field in enriched, field


def test_missing_min_fields_reports_spec_order():
    assert ri.missing_min_fields({}) == list(SPEC_74_MIN_FIELDS)
    full = {field: None for field in SPEC_74_MIN_FIELDS}
    assert ri.missing_min_fields(full) == []
    assert ri.missing_min_fields(None) == list(SPEC_74_MIN_FIELDS)


def test_runner_writes_enriched_inventory():
    """主编排器接线漂移防护：runtime_inventory 写盘点必须经 enrich_runtime_inventory。"""
    source = (ROOT / "gov_exercise_runner.py").read_text(encoding="utf-8")
    assert "from authorized_assessment.runtime.runtime_inventory import enrich_runtime_inventory" in source
    assert "runtime = enrich_runtime_inventory(collect_runtime_inventory(cfg))" in source


def test_probe_source_is_hermetic_and_executable():
    """探针源码零网络语义，且在当前解释器真实可执行、输出可解析（本地冒烟）。"""
    banned = ("socket", "urlopen", "http.client", "requests.get", "subprocess", "urllib.request")
    for word in banned:
        assert word not in ri.PROBE_SOURCE
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        exec(compile(ri.PROBE_SOURCE, "probe", "exec"), {})
    payload = json.loads(buffer.getvalue().strip())
    assert payload["python_version"]
    for module in ("requests", "urllib3", "pytest", "docx", "playwright", "cryptography", "Crypto"):
        assert module in payload
