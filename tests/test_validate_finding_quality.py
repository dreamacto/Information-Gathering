"""validate_finding_quality 入口测试（阻塞项 B4；batch2_3）。"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.maintenance.validate_finding_quality import (
    collect_violations,
    main,
    probe_evidence_gate_behaviour,
    probe_evidence_validator_negative,
    probe_finding_gate_behaviour,
)

ROOT = Path(__file__).resolve().parents[1]
FINDING_CONTRACT_FILES = [
    "finding_quality_schema.json",
    "finding_evidence_schema.json",
]


def test_real_repo_passes():
    violations = collect_violations(ROOT)
    assert violations == []


def test_missing_finding_contracts_is_violation(tmp_path):
    violations = collect_violations(tmp_path)
    assert any("missing contract file: finding_quality_schema.json" in v for v in violations)
    assert any("missing contract file: finding_evidence_schema.json" in v for v in violations)


def _copy_finding_contracts(tmp_path) -> Path:
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    for name in FINDING_CONTRACT_FILES:
        shutil.copy(ROOT / "contracts" / name, contracts / name)
    return tmp_path


def test_tampered_finding_status_states_detected(tmp_path):
    root = _copy_finding_contracts(tmp_path)
    path = root / "contracts" / "finding_quality_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["finding_status_states"] = ["signal", "confirmed"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "finding_quality_schema.finding_status_states drift" in v for v in violations
    )


def test_tampered_gate_reason_enum_detected(tmp_path):
    root = _copy_finding_contracts(tmp_path)
    path = root / "contracts" / "finding_quality_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["gate_reason_enums"]["authorization"] = ["authorization_proven", "invented_reason"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("gate_reason_enums drift" in v for v in violations)


def test_tampered_suppression_rules_detected(tmp_path):
    root = _copy_finding_contracts(tmp_path)
    path = root / "contracts" / "finding_quality_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["suppression_rules"]["RULE_10_LOW_VALUE_SITE"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("suppression_rules drift" in v for v in violations)
    assert any("exactly 10 rules" in v for v in violations)


def test_tampered_classification_enum_detected(tmp_path):
    root = _copy_finding_contracts(tmp_path)
    path = root / "contracts" / "finding_quality_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["classification_enums"]["submission_eligibility"] = ["eligible", "maybe"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("classification_enums.submission_eligibility drift" in v for v in violations)


def test_tampered_status_decision_order_detected(tmp_path):
    root = _copy_finding_contracts(tmp_path)
    path = root / "contracts" / "finding_quality_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["status_decision_order"] = data["status_decision_order"][1:]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("status_decision_order rule ids drift" in v for v in violations)
    assert any("exactly 10 rules" in v for v in violations)


def test_tampered_evidence_violation_codes_detected(tmp_path):
    root = _copy_finding_contracts(tmp_path)
    path = root / "contracts" / "finding_evidence_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["violation_codes"] = data["violation_codes"][:-1]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("finding_evidence_schema.violation_codes drift" in v for v in violations)


def test_cross_contract_status_drift_detected(tmp_path):
    """finding_evidence_schema 与 finding_quality_schema 的 8 状态互查。"""
    root = _copy_finding_contracts(tmp_path)
    path = root / "contracts" / "finding_evidence_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["finding_status_states"] = data["finding_status_states"] + ["whitebox_candidate"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "finding_evidence_schema.finding_status_states vs finding_quality_schema" in v
        for v in violations
    )


def test_unparseable_contract_detected(tmp_path):
    root = _copy_finding_contracts(tmp_path)
    path = root / "contracts" / "finding_quality_schema.json"
    path.write_text("{broken", encoding="utf-8")
    violations = collect_violations(root)
    assert any("unparseable contract file" in v for v in violations)


def test_probes_directly():
    assert probe_finding_gate_behaviour() == []
    assert probe_evidence_gate_behaviour() == []
    assert probe_evidence_validator_negative() == []


def test_main_json_output_and_exit_codes(tmp_path):
    ok = main(["--json", "--root", str(ROOT)])
    assert ok == 0
    failing = main(["--json", "--root", str(tmp_path)])
    assert failing == 1


def test_cli_script_real_run_passes():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "maintenance" / "validate_finding_quality.py")],
        capture_output=True,
        text=True,
        encoding="utf-8",  # batch14_5: hermetic——父进程 GBK locale 下子进程 UTF-8 输出会解码崩溃(stdout=None)
        cwd=ROOT,
        timeout=120,
        env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "通过" in proc.stdout or "violations" in proc.stdout


def test_cli_script_json_mode_parseable():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "maintenance" / "validate_finding_quality.py"), "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",  # batch14_5: hermetic——父进程 GBK locale 下子进程 UTF-8 输出会解码崩溃(stdout=None)
        cwd=ROOT,
        timeout=120,
        env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["violations"] == []


@pytest.mark.parametrize("name", FINDING_CONTRACT_FILES)
def test_finding_contract_files_exist(name):
    assert (ROOT / "contracts" / name).is_file()
