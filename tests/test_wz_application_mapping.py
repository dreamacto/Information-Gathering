"""wz skill application_mapping 五子阶段落地测试（batch5_1，实施规格 5.2/5.1）。

覆盖：
  - init_engagement.py：application-map 五产物骨架（4 CSV + graphql-manifest.json）、
    phase_status.json substatuses 五键种子、resume 升级既有工作区、骨架写入幂等；
  - audit_engagement.py：子状态映射合法性（未知子阶段/非法状态）、phase 完成时五子阶段
    全落盘强制、产物行契约（7 字段/not_applicable 需 reason/tested 需 evidence_ref）、
    tested 证据文件必须在工作区内可解析；
  - skill 常量 ↔ src/authorized_assessment/analysis/coverage_matrix.py 契约常量无漂移
    （与 coverage_substatus_schema.json 契约三层一致）。

skill 脚本自包含（不 import src 包），通过 importlib 按路径加载 canonical 脚本。
"""
from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from authorized_assessment.analysis import coverage_matrix  # noqa: E402

INIT_SCRIPT = ROOT / ".agents" / "skills" / "wz" / "scripts" / "init_engagement.py"
AUDIT_SCRIPT = ROOT / ".agents" / "skills" / "wz" / "scripts" / "audit_engagement.py"

APP_MAP_DIR = "artifacts/application-map"
EXPECTED_CSVS = {
    "websocket-inventory.csv",
    "file-surface-inventory.csv",
    "auth-surface-inventory.csv",
    "webhook-inventory.csv",
}
SUBPHASES = coverage_matrix.APPLICATION_MAP_SUBPHASES
FIELDS = coverage_matrix.APPLICATION_MAP_ROW_FIELDS


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def init_mod():
    return _load_module("wz_init_engagement", INIT_SCRIPT)


@pytest.fixture(scope="module")
def audit_mod():
    return _load_module("wz_audit_engagement", AUDIT_SCRIPT)


def _run_init(init_mod, tmp_path: Path, *extra: str) -> Path:
    out = tmp_path / "engagement"
    old_argv = sys.argv
    sys.argv = [str(INIT_SCRIPT), "example.com", "--output", str(out), *extra]
    try:
        code = init_mod.main()
    finally:
        sys.argv = old_argv
    assert code == 0, f"init failed with exit code {code}"
    return out


def _write_phase(root: Path, phase: str, remove: tuple[str, ...] = (), **fields) -> None:
    path = root / "phase_status.json"
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    for row in payload["phases"]:
        if row["phase"] == phase:
            row.update(fields)
            for key in remove:
                row.pop(key, None)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _phase_row(root: Path, phase: str) -> dict:
    payload = json.loads((root / "phase_status.json").read_text(encoding="utf-8-sig"))
    return next(row for row in payload["phases"] if row["phase"] == phase)


def _append_csv_row(path: Path, row: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8-sig", newline="") as handle:
        csv.DictWriter(handle, fieldnames=FIELDS).writerow(row)


def _set_manifest_rows(root: Path, rows: list[dict[str, str]]) -> None:
    path = root / APP_MAP_DIR / "graphql-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    manifest["rows"] = rows
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _appmap_issues(result: dict) -> list[str]:
    return [issue for issue in result["issues"] if issue.startswith("application_mapping")]


# ---------------------------------------------------------------------------
# 契约常量无漂移（skill 自包含常量 ↔ src 契约实现 ↔ coverage_substatus_schema）
# ---------------------------------------------------------------------------

def test_skill_constants_match_coverage_matrix_contract(init_mod, audit_mod):
    assert init_mod.APPLICATION_MAP_SUBPHASES == coverage_matrix.APPLICATION_MAP_SUBPHASES
    assert init_mod.APPLICATION_MAP_ROW_FIELDS == coverage_matrix.APPLICATION_MAP_ROW_FIELDS
    assert tuple(audit_mod.APPLICATION_MAP_SUBPHASES) == coverage_matrix.APPLICATION_MAP_SUBPHASES
    assert tuple(audit_mod.APPLICATION_MAP_ROW_FIELDS) == coverage_matrix.APPLICATION_MAP_ROW_FIELDS
    assert set(audit_mod.COVERAGE_SUBSTATUSES) == set(coverage_matrix.COVERAGE_SUBSTATUSES)
    assert len(coverage_matrix.APPLICATION_MAP_SUBPHASES) == 5
    assert len(coverage_matrix.APPLICATION_MAP_ROW_FIELDS) == 7


def test_artifact_paths_match_contract(audit_mod):
    assert audit_mod.APPLICATION_MAP_ARTIFACTS == {
        "graphql_mapping": "artifacts/application-map/graphql-manifest.json",
        "websocket_mapping": "artifacts/application-map/websocket-inventory.csv",
        "file_surface_mapping": "artifacts/application-map/file-surface-inventory.csv",
        "auth_surface_mapping": "artifacts/application-map/auth-surface-inventory.csv",
        "webhook_mapping": "artifacts/application-map/webhook-inventory.csv",
    }


# ---------------------------------------------------------------------------
# init：产物骨架 + substatuses 种子 + 幂等
# ---------------------------------------------------------------------------

def test_init_creates_application_map_artifacts(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    app_map = out / APP_MAP_DIR
    assert app_map.is_dir()
    assert {p.name for p in app_map.glob("*.csv")} == EXPECTED_CSVS
    assert (app_map / "graphql-manifest.json").is_file()


def test_init_csv_headers_are_seven_contract_fields(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    for name in EXPECTED_CSVS:
        with (out / APP_MAP_DIR / name).open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            assert tuple(reader.fieldnames or ()) == FIELDS
            assert list(reader) == []


def test_init_graphql_manifest_skeleton_structure(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    manifest = json.loads(
        (out / APP_MAP_DIR / "graphql-manifest.json").read_text(encoding="utf-8-sig"))
    assert manifest["schema_version"] == "1.0"
    assert manifest["contract"] == "coverage_substatus_schema"
    assert manifest["subphase"] == "graphql_mapping"
    assert list(manifest["row_fields"]) == list(FIELDS)
    assert manifest["rows"] == []


def test_init_seeds_five_empty_substatuses(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    substatuses = _phase_row(out, "application_mapping")["substatuses"]
    assert substatuses == {name: "" for name in SUBPHASES}


def test_init_resume_upgrades_legacy_phase_file_and_preserves_rows(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    # 模拟旧工作区：删除 substatuses + 在骨架 CSV 中留一行既有记录
    _write_phase(out, "application_mapping", remove=("substatuses",))
    legacy_row = {
        "applicable": "not_applicable",
        "status": "not_applicable",
        "source": "js_review",
        "asset": "example.com",
        "endpoint_or_surface": "realtime channels",
        "reason": "no websocket references in JS bundle",
        "evidence_ref": "",
    }
    _append_csv_row(out / APP_MAP_DIR / "websocket-inventory.csv", legacy_row)
    # resume：补 substatuses，且既有产物行不被清空（骨架写入幂等）
    assert _run_init(init_mod, tmp_path, "--resume") == out
    substatuses = _phase_row(out, "application_mapping")["substatuses"]
    assert substatuses == {name: "" for name in SUBPHASES}
    with (out / APP_MAP_DIR / "websocket-inventory.csv").open(
            encoding="utf-8-sig", newline="") as handle:
        assert list(csv.DictReader(handle)) == [legacy_row]


# ---------------------------------------------------------------------------
# audit：映射合法性 / 完成可证明性 / 行契约负例
# ---------------------------------------------------------------------------

def test_audit_fresh_workspace_reports_no_application_map_issues(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    result = audit_mod.audit(out)
    assert _appmap_issues(result) == []
    assert result["application_mapping_substatuses"] == {name: "" for name in SUBPHASES}
    assert result["state"] == "AUTHORIZATION_PENDING"


def test_audit_complete_without_substatuses_is_flagged(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _write_phase(out, "application_mapping", status="complete", remove=("substatuses",))
    result = audit_mod.audit(out)
    assert any("substatuses are not recorded" in i for i in _appmap_issues(result))


def test_audit_complete_with_unrecorded_or_unproven_substatus_is_flagged(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _write_phase(
        out,
        "application_mapping",
        status="complete",
        substatuses={
            "graphql_mapping": "",
            "websocket_mapping": "approval_required",
            "file_surface_mapping": "tested",
            "auth_surface_mapping": "not_applicable",
            "webhook_mapping": "not_applicable",
        },
    )
    result = audit_mod.audit(out)
    issues = _appmap_issues(result)
    assert any("graphql_mapping has no recorded substatus" in i for i in issues)
    assert any(
        "websocket_mapping is 'approval_required'" in i and "proven" in i for i in issues
    )


def test_audit_illegal_substatus_value_and_unknown_subphase_flagged(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _write_phase(
        out,
        "application_mapping",
        substatuses={
            "graphql_mapping": "done",
            "websocket_mapping": "tested",
            "file_surface_mapping": "not_applicable",
            "auth_surface_mapping": "not_applicable",
            "webhook_mapping": "not_applicable",
            "mystery_mapping": "tested",
        },
    )
    result = audit_mod.audit(out)
    issues = _appmap_issues(result)
    assert any("graphql_mapping: invalid substatus 'done'" in i for i in issues)
    assert any("unknown subphase 'mystery_mapping'" in i for i in issues)


def test_audit_complete_with_empty_artifacts_flagged(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _write_phase(out, "application_mapping", status="complete",
                 substatuses={name: "tested" for name in SUBPHASES})
    issues = _appmap_issues(audit_mod.audit(out))
    for subphase in SUBPHASES:
        assert any(subphase in i and "has no rows" in i for i in issues), \
            f"missing no-rows issue for {subphase}"


def test_audit_complete_with_valid_proven_rows_is_clean(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    evidence = out / "notes" / "phase-history" / "websocket_mapping.md"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("websocket mapping evidence\n", encoding="utf-8")
    _append_csv_row(out / APP_MAP_DIR / "websocket-inventory.csv", {
        "applicable": "applicable",
        "status": "tested",
        "source": "js_review",
        "asset": "example.com",
        "endpoint_or_surface": "wss://example.com/realtime",
        "reason": "",
        "evidence_ref": "notes/phase-history/websocket_mapping.md",
    })
    na_row = {
        "applicable": "not_applicable",
        "status": "not_applicable",
        "source": "js_review",
        "asset": "example.com",
        "endpoint_or_surface": "surface not referenced by JS or traffic",
        "reason": "no discoverable references in JS bundle or captured traffic",
        "evidence_ref": "",
    }
    for name in ("file-surface-inventory.csv", "auth-surface-inventory.csv", "webhook-inventory.csv"):
        _append_csv_row(out / APP_MAP_DIR / name, dict(na_row))
    _set_manifest_rows(out, [dict(na_row)])
    substatuses = {
        "graphql_mapping": "not_applicable",
        "websocket_mapping": "tested",
        "file_surface_mapping": "not_applicable",
        "auth_surface_mapping": "not_applicable",
        "webhook_mapping": "not_applicable",
    }
    _write_phase(out, "application_mapping", status="complete", substatuses=substatuses)
    result = audit_mod.audit(out)
    assert _appmap_issues(result) == []
    assert result["application_mapping_substatuses"] == substatuses


def test_audit_not_applicable_row_without_reason_flagged(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _append_csv_row(out / APP_MAP_DIR / "webhook-inventory.csv", {
        "applicable": "applicable",
        "status": "not_applicable",
        "source": "js_review",
        "asset": "example.com",
        "endpoint_or_surface": "webhooks",
        "reason": "",
        "evidence_ref": "",
    })
    _write_phase(out, "application_mapping", substatuses={"webhook_mapping": "not_applicable"})
    result = audit_mod.audit(out)
    assert any(
        "webhook_mapping[0]" in i and "not_applicable without reason" in i
        for i in _appmap_issues(result)
    )


def test_audit_not_applicable_without_applicability_decision_flagged(init_mod, audit_mod, tmp_path):
    """13.2 负例：未做适用性判定（applicable=applicable）不得宣称 not_applicable。"""
    out = _run_init(init_mod, tmp_path)
    _append_csv_row(out / APP_MAP_DIR / "websocket-inventory.csv", {
        "applicable": "applicable",
        "status": "not_applicable",
        "source": "guess",
        "asset": "example.com",
        "endpoint_or_surface": "graphql",
        "reason": "probably absent",
        "evidence_ref": "",
    })
    _write_phase(out, "application_mapping", substatuses={"websocket_mapping": "not_applicable"})
    result = audit_mod.audit(out)
    assert any(
        "websocket_mapping[0]" in i and "applicable=not_applicable" in i
        for i in _appmap_issues(result)
    )


def test_audit_tested_row_without_evidence_ref_flagged(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _append_csv_row(out / APP_MAP_DIR / "auth-surface-inventory.csv", {
        "applicable": "applicable",
        "status": "tested",
        "source": "traffic",
        "asset": "example.com",
        "endpoint_or_surface": "auth surfaces",
        "reason": "",
        "evidence_ref": "",
    })
    _write_phase(out, "application_mapping", substatuses={"auth_surface_mapping": "tested"})
    result = audit_mod.audit(out)
    assert any(
        "auth_surface_mapping[0]" in i and "lacks evidence_ref" in i
        for i in _appmap_issues(result)
    )


def test_audit_tested_row_with_unresolvable_evidence_flagged(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _append_csv_row(out / APP_MAP_DIR / "websocket-inventory.csv", {
        "applicable": "applicable",
        "status": "tested",
        "source": "traffic",
        "asset": "example.com",
        "endpoint_or_surface": "wss://example.com/ws",
        "reason": "",
        "evidence_ref": "evidence/raw/does-not-exist.md",
    })
    _write_phase(out, "application_mapping", status="complete",
                 substatuses={name: "not_applicable" for name in SUBPHASES}
                 | {"websocket_mapping": "tested"})
    result = audit_mod.audit(out)
    assert any(
        "websocket_mapping" in i and "does not resolve" in i for i in _appmap_issues(result)
    )


def test_audit_substatus_tested_without_matching_artifact_row_flagged(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _append_csv_row(out / APP_MAP_DIR / "file-surface-inventory.csv", {
        "applicable": "applicable",
        "status": "approval_required",
        "source": "traffic",
        "asset": "example.com",
        "endpoint_or_surface": "/upload",
        "reason": "upload testing requires operator approval",
        "evidence_ref": "",
    })
    _write_phase(out, "application_mapping", status="complete",
                 substatuses={name: "not_applicable" for name in SUBPHASES}
                 | {"file_surface_mapping": "tested"})
    result = audit_mod.audit(out)
    assert any(
        "file_surface_mapping" in i and "no matching row" in i for i in _appmap_issues(result)
    )


def test_audit_missing_artifact_at_completion_flagged(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    (out / APP_MAP_DIR / "webhook-inventory.csv").unlink()
    _write_phase(out, "application_mapping", status="complete",
                 substatuses={name: "not_applicable" for name in SUBPHASES})
    result = audit_mod.audit(out)
    assert any("artifact missing for webhook_mapping" in i for i in _appmap_issues(result))


def test_audit_broken_csv_header_flagged(init_mod, audit_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    (out / APP_MAP_DIR / "auth-surface-inventory.csv").write_text(
        "applicable,status\n", encoding="utf-8")
    _write_phase(out, "application_mapping", status="complete",
                 substatuses={name: "not_applicable" for name in SUBPHASES})
    result = audit_mod.audit(out)
    assert any(
        "auth_surface_mapping" in i and "header missing required fields" in i
        for i in _appmap_issues(result)
    )


def test_audit_state_gate_unchanged_by_application_mapping(init_mod, audit_mod, tmp_path):
    """回归护栏：子阶段缺口阻止关闭但不改变既有状态机语义——授权门仍优先，
    application_mapping complete 而子状态未落盘时产生 application_mapping 前缀 issue。"""
    out = _run_init(init_mod, tmp_path)
    assert audit_mod.audit(out)["state"] == "AUTHORIZATION_PENDING"
    _write_phase(out, "application_mapping", status="complete", remove=("substatuses",))
    result = audit_mod.audit(out)
    assert result["state"] == "AUTHORIZATION_PENDING"
    assert _appmap_issues(result)
