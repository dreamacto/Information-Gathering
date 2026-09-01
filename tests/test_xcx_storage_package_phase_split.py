"""tests/test_xcx_storage_package_phase_split.py —— xcx client_storage_crypto 存储
拆分 + package_integrity_update_review 插入落地测试（batch11_0，实施规格 6.2/6.3/6.6；
契约 miniapp_storage_package_schema）。

覆盖：
  - init/audit skill 常量 ↔ contracts/miniapp_storage_package_schema.json ↔
    contracts/coverage_substatus_schema.json 三层无漂移；PHASES/CORE_PHASES 拆分
    位置正确（package_integrity_update_review 在 source_reconstruction 后、
    static_analysis 前；local_data_exposure/crypto_and_secret_handling 替换
    client_storage_crypto 原位置）且 client_storage_crypto 不再存在；
  - init：三 phase substatuses 种子（空串=未记录）、三个 review 产物骨架（规格
    1542/1619/1620 行路径、骨架形状、契约名）、--resume 幂等、既有工作区
    client_storage_crypto 行 resume 升级为两行（状态回 pending、reason 留痕、不携带
    complete）、缺失 package_integrity_update_review 行插入（source_reconstruction
    后；无该行时兜底追加）；
  - audit：storage_package_review_issues 正例（全分支 proven 且产物一致 → 零违例）
    与负例（未记录分支/非法状态/未知分支/缺产物/缺 summary/branch_status 不一致/
    not_applicable 缺 reason/tested 证据不可解析/authorization_basis 非法/契约字段
    错误/行未知分支与非法状态/汇总重复分支）。

skill 脚本自包含（不 import src 包），通过 importlib 按路径加载 canonical 脚本；
纯离线，不发任何网络请求。
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

INIT_SCRIPT = ROOT / ".agents" / "skills" / "xcx" / "scripts" / "init_miniapp_engagement.py"
AUDIT_SCRIPT = ROOT / ".agents" / "skills" / "xcx" / "scripts" / "audit_miniapp_engagement.py"
CONTRACT_PATH = ROOT / "contracts" / "miniapp_storage_package_schema.json"
COVERAGE_CONTRACT_PATH = ROOT / "contracts" / "coverage_substatus_schema.json"

STORAGE_PACKAGE_PHASES = (
    "package_integrity_update_review",
    "local_data_exposure",
    "crypto_and_secret_handling",
)


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


@pytest.fixture(scope="module")
def init_mod():
    return _load_module("xcx_init_miniapp_b11", INIT_SCRIPT)


@pytest.fixture(scope="module")
def audit_mod():
    return _load_module("xcx_audit_miniapp_b11", AUDIT_SCRIPT)


@pytest.fixture(scope="module")
def contract():
    return _load_json(CONTRACT_PATH)


@pytest.fixture(scope="module")
def coverage_contract():
    return _load_json(COVERAGE_CONTRACT_PATH)


def _run_init(init_mod, tmp_path: Path, *extra: str) -> Path:
    out = tmp_path / "engagement"
    old_argv = sys.argv
    sys.argv = [str(INIT_SCRIPT), "demo-miniapp", "--output", str(out), *extra]
    try:
        code = init_mod.main()
    finally:
        sys.argv = old_argv
    assert code == 0, f"init failed with exit code {code}"
    return out


def _phase_rows(root: Path) -> list[dict]:
    payload = _load_json(root / "phase_status.miniapp.json")
    return payload["phases"]


def _phase_row(root: Path, phase: str) -> dict:
    return next(row for row in _phase_rows(root) if row["phase"] == phase)


def _update_phase(root: Path, phase: str, **fields) -> dict:
    """读-改-写整个 payload，避免丢失未涉及的顶层键或其他行的改动。"""
    payload = _load_json(root / "phase_status.miniapp.json")
    row = next(r for r in payload["phases"] if r["phase"] == phase)
    row.update(fields)
    _write_json(root / "phase_status.miniapp.json", payload)
    return row


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _skeleton(init_mod, phase: str) -> dict:
    return init_mod.storage_package_review_skeleton(phase)


# ---------------------------------------------------------------------------
# 契约常量无漂移（skill 自包含常量 ↔ miniapp_storage_package_schema ↔
# coverage_substatus_schema）
# ---------------------------------------------------------------------------

def test_contract_defines_exactly_three_phases(contract):
    assert tuple(contract["phases"].keys()) == STORAGE_PACKAGE_PHASES


def test_branch_constants_match_contract(init_mod, audit_mod, contract):
    for phase in STORAGE_PACKAGE_PHASES:
        branches = tuple(contract["phases"][phase]["branches"])
        assert init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase] == branches
        assert tuple(audit_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]) == branches
        assert len(branches) >= 4


def test_artifact_paths_match_spec(init_mod, audit_mod, contract):
    expected = {
        "package_integrity_update_review": "artifacts/miniapp/package/package-integrity-review.json",
        "local_data_exposure": "artifacts/miniapp/storage/local-data-review.json",
        "crypto_and_secret_handling": "artifacts/miniapp/crypto/secret-review.json",
    }
    assert init_mod.STORAGE_PACKAGE_REVIEW_ARTIFACTS == expected
    assert dict(audit_mod.STORAGE_PACKAGE_REVIEW_ARTIFACTS) == expected
    for phase in STORAGE_PACKAGE_PHASES:
        assert contract["phases"][phase]["artifact"] == expected[phase]


def test_coverage_substatus_enum_single_source(audit_mod, contract, coverage_contract):
    assert set(audit_mod.COVERAGE_SUBSTATUSES) == set(coverage_contract["status_values"])
    assert set(contract["coverage_substatus"]["status_values"]) == set(
        coverage_contract["status_values"]
    )
    assert set(audit_mod.PROVEN_SUBSTATUSES) == set(contract["coverage_substatus"]["proven_values"])
    assert set(audit_mod.AUTHORIZATION_BASIS_VALUES) == set(contract["authorization_basis_values"])


def test_phase_split_positions_and_no_legacy_name(init_mod, audit_mod):
    phases = init_mod.PHASES
    assert "client_storage_crypto" not in phases
    assert "client_storage_crypto" not in audit_mod.CORE_PHASES
    for phase in STORAGE_PACKAGE_PHASES:
        assert phase in phases
        assert phase in audit_mod.CORE_PHASES
    assert (
        phases.index("package_integrity_update_review")
        == phases.index("source_reconstruction") + 1
    )
    assert phases.index("static_analysis") == phases.index("package_integrity_update_review") + 1
    assert phases.index("local_data_exposure") == phases.index("business_logic_testing") + 1
    assert phases.index("crypto_and_secret_handling") == phases.index("local_data_exposure") + 1
    assert phases.index("webview_bridge_links") == phases.index("crypto_and_secret_handling") + 1


def test_skeleton_fields_match_contract(init_mod, contract):
    fields = init_mod.AUTH_REVIEW_SKELETON_FIELDS
    assert tuple(fields["row_fields"]) == tuple(contract["artifact_fields"]["row_fields"])
    assert tuple(fields["summary_fields"]) == tuple(contract["artifact_fields"]["summary_fields"])
    artifact_keys = set(contract["artifact_fields"]["artifact_keys"])
    for phase in STORAGE_PACKAGE_PHASES:
        assert set(_skeleton(init_mod, phase).keys()) == artifact_keys


# ---------------------------------------------------------------------------
# init：substatuses 种子 + 产物骨架 + 幂等 + resume 升级
# ---------------------------------------------------------------------------

def test_init_seeds_storage_package_phases_with_empty_substatuses(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    names = [row["phase"] for row in _phase_rows(out)]
    for phase in STORAGE_PACKAGE_PHASES:
        assert phase in names
        row = _phase_row(out, phase)
        assert row["status"] == "pending"
        assert row["substatuses"] == {
            name: "" for name in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]
        }
    assert "client_storage_crypto" not in names


def test_init_seeds_three_artifact_skeletons(init_mod, tmp_path, contract):
    out = _run_init(init_mod, tmp_path)
    for phase in STORAGE_PACKAGE_PHASES:
        path = out / init_mod.STORAGE_PACKAGE_REVIEW_ARTIFACTS[phase]
        assert path.is_file()
        data = _load_json(path)
        assert data["schema_version"] == "1.0"
        assert data["contract"] == "miniapp_storage_package_schema"
        assert data["phase"] == phase
        assert data["observation_schema_version"] == "1.0"
        assert data["substatuses"] == {
            name: "" for name in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]
        }
        assert data["rows"] == []
        assert data["summaries"] == []
        assert data["violations"] == []
        assert data["authorization_basis"] == ""
        assert list(data["row_fields"]) == list(contract["artifact_fields"]["row_fields"])
        assert list(data["summary_fields"]) == list(contract["artifact_fields"]["summary_fields"])


def test_init_resume_is_idempotent(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    before = (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig")
    artifact_before = (
        out / init_mod.STORAGE_PACKAGE_REVIEW_ARTIFACTS["package_integrity_update_review"]
    ).read_text(encoding="utf-8-sig")
    _run_init(init_mod, tmp_path, "--resume")
    assert (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig") == before
    assert (
        out / init_mod.STORAGE_PACKAGE_REVIEW_ARTIFACTS["package_integrity_update_review"]
    ).read_text(encoding="utf-8-sig") == artifact_before


def test_init_resume_upgrades_legacy_client_storage_crypto(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    # 模拟拆分前的旧工作区：两行合并回一行 client_storage_crypto（complete 不可证明）
    payload = _load_json(out / "phase_status.miniapp.json")
    phases = payload["phases"]
    first_idx = next(i for i, r in enumerate(phases) if r["phase"] == "local_data_exposure")
    last_idx = next(i for i, r in enumerate(phases) if r["phase"] == "crypto_and_secret_handling")
    legacy_row = {
        "phase": "client_storage_crypto",
        "required": True,
        "status": "complete",
        "reason": "legacy aggregate completion",
        "artifacts": [],
        "updated_at": "2026-01-01T00:00:00+08:00",
    }
    payload["phases"] = phases[:first_idx] + [legacy_row] + phases[last_idx + 1:]
    _write_json(out / "phase_status.miniapp.json", payload)

    _run_init(init_mod, tmp_path, "--resume")

    names = [row["phase"] for row in _phase_rows(out)]
    assert "client_storage_crypto" not in names
    for phase in ("local_data_exposure", "crypto_and_secret_handling"):
        row = _phase_row(out, phase)
        assert row["status"] == "pending"
        assert "migrated_from_client_storage_crypto" in row["reason"]
        assert "old_status=complete" in row["reason"]
        assert row["substatuses"] == {
            name: "" for name in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]
        }
    # 幂等：再次 resume 不再变化
    snapshot = (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig")
    _run_init(init_mod, tmp_path, "--resume")
    assert (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig") == snapshot


def test_init_resume_inserts_missing_package_phase_row(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    # 模拟旧工作区：删除 package_integrity_update_review 行
    payload = _load_json(out / "phase_status.miniapp.json")
    payload["phases"] = [
        r for r in payload["phases"] if r["phase"] != "package_integrity_update_review"
    ]
    _write_json(out / "phase_status.miniapp.json", payload)

    _run_init(init_mod, tmp_path, "--resume")

    names = [row["phase"] for row in _phase_rows(out)]
    assert "package_integrity_update_review" in names
    row = _phase_row(out, "package_integrity_update_review")
    assert row["status"] == "pending"
    assert "inserted_by_package_integrity_split" in row["reason"]
    assert row["substatuses"] == {
        name: "" for name in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[
            "package_integrity_update_review"
        ]
    }
    phases = init_mod.PHASES
    inserted_names = [r["phase"] for r in _phase_rows(out)]
    assert inserted_names.index("package_integrity_update_review") == (
        inserted_names.index("source_reconstruction") + 1
    )
    assert phases.index("static_analysis") == phases.index(
        "package_integrity_update_review"
    ) + 1
    # 幂等
    snapshot = (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig")
    _run_init(init_mod, tmp_path, "--resume")
    assert (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig") == snapshot


def test_init_resume_appends_package_row_without_source_reconstruction(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    payload = _load_json(out / "phase_status.miniapp.json")
    payload["phases"] = [
        r for r in payload["phases"]
        if r["phase"] not in {"package_integrity_update_review", "source_reconstruction"}
    ]
    _write_json(out / "phase_status.miniapp.json", payload)

    _run_init(init_mod, tmp_path, "--resume")

    names = [row["phase"] for row in _phase_rows(out)]
    assert "package_integrity_update_review" in names
    assert names.index("package_integrity_update_review") == len(names) - 1


# ---------------------------------------------------------------------------
# audit：storage_package_review_issues 正例/负例
# ---------------------------------------------------------------------------

def _audit_storage(audit_mod, root: Path, phase: str):
    row = next((r for r in _phase_rows(root) if r["phase"] == phase), None)
    return audit_mod.storage_package_review_issues(root, phase, row)


def test_audit_pending_phase_has_no_storage_issues(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    for phase in STORAGE_PACKAGE_PHASES:
        assert _audit_storage(audit_mod, out, phase) == []


def test_audit_complete_with_unrecorded_branches_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _update_phase(out, "package_integrity_update_review", status="complete")
    issues = _audit_storage(audit_mod, out, "package_integrity_update_review")
    assert any("no recorded substatus" in issue for issue in issues)


def test_audit_complete_without_matching_summary_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    phase = "package_integrity_update_review"
    _update_phase(
        out,
        phase,
        status="complete",
        substatuses={name: "tested" for name in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]},
    )
    issues = _audit_storage(audit_mod, out, phase)
    for branch in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]:
        assert any(
            f"{phase}.{branch}" in issue and "no matching summary" in issue for issue in issues
        )


def test_audit_complete_without_artifact_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    phase = "local_data_exposure"
    (out / init_mod.STORAGE_PACKAGE_REVIEW_ARTIFACTS[phase]).unlink()
    _update_phase(
        out,
        phase,
        status="complete",
        substatuses={name: "not_applicable" for name in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]},
    )
    issues = _audit_storage(audit_mod, out, phase)
    assert any("missing or invalid" in issue for issue in issues)


def test_audit_invalid_and_unknown_substatus_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    phase = "crypto_and_secret_handling"
    payload = _load_json(out / "phase_status.miniapp.json")
    row = next(r for r in payload["phases"] if r["phase"] == phase)
    row["substatuses"]["hardcoded_secrets"] = "complete"
    row["substatuses"]["unknown_branch"] = "tested"
    _write_json(out / "phase_status.miniapp.json", payload)
    issues = _audit_storage(audit_mod, out, phase)
    assert any("invalid substatus 'complete'" in issue for issue in issues)
    assert any("unknown review branch 'unknown_branch'" in issue for issue in issues)


def test_audit_artifact_shape_violations_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    phase = "local_data_exposure"
    artifact = _skeleton(init_mod, phase)
    artifact["contract"] = "wrong_contract"
    artifact["phase"] = "crypto_and_secret_handling"
    artifact["rows"] = [
        {"branch": "unknown_branch", "status": "signal"},
        {"branch": "token_persistence", "status": "not-a-status"},
    ]
    artifact["summaries"] = [
        {"branch": "unknown_branch", "branch_status": "tested"},
        {"branch": "token_persistence", "branch_status": "bogus"},
        {"branch": "token_persistence", "branch_status": "tested"},
    ]
    artifact["authorization_basis"] = "self_created_credentials"
    _write_json(out / init_mod.STORAGE_PACKAGE_REVIEW_ARTIFACTS[phase], artifact)
    issues = _audit_storage(audit_mod, out, phase)
    text = "\n".join(issues)
    assert "contract must be miniapp_storage_package_schema" in text
    assert "phase field mismatch" in text
    assert "row has unknown branch 'unknown_branch'" in text
    assert "row has invalid status 'not-a-status'" in text
    assert "summary has unknown branch 'unknown_branch'" in text
    assert "invalid branch_status 'bogus'" in text
    assert "duplicate summary for branch 'token_persistence'" in text
    assert "authorization_basis 'self_created_credentials' is not one of" in text


def test_audit_not_applicable_without_reason_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    phase = "local_data_exposure"
    _update_phase(
        out,
        phase,
        status="complete",
        substatuses={name: "not_applicable" for name in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]},
    )
    artifact = _skeleton(init_mod, phase)
    artifact["summaries"] = [
        {"branch": name, "branch_status": "not_applicable", "reason": ""}
        for name in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]
    ]
    _write_json(out / init_mod.STORAGE_PACKAGE_REVIEW_ARTIFACTS[phase], artifact)
    issues = _audit_storage(audit_mod, out, phase)
    for branch in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]:
        assert any(
            f"{phase}.{branch}" in issue and "lacks reason" in issue for issue in issues
        )


def test_audit_tested_without_resolvable_evidence_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    phase = "crypto_and_secret_handling"
    _update_phase(
        out,
        phase,
        status="complete",
        substatuses={name: "tested" for name in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]},
    )
    artifact = _skeleton(init_mod, phase)
    artifact["summaries"] = [
        {
            "branch": name,
            "branch_status": "tested",
            "evidence_ref": "notes/missing-storage-evidence.md",
            "reason": "observed",
            "precondition": "operator-supplied package copy only",
        }
        for name in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]
    ]
    _write_json(out / init_mod.STORAGE_PACKAGE_REVIEW_ARTIFACTS[phase], artifact)
    issues = _audit_storage(audit_mod, out, phase)
    for branch in init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]:
        assert any(
            f"{phase}.{branch}" in issue and "evidence_ref does not resolve" in issue
            for issue in issues
        )


def test_audit_fully_proven_phase_passes(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    (out / "notes").mkdir(parents=True, exist_ok=True)
    (out / "notes" / "storage-evidence.md").write_text("# storage evidence\n", encoding="utf-8")
    for phase in STORAGE_PACKAGE_PHASES:
        branches = init_mod.STORAGE_PACKAGE_REVIEW_BRANCHES[phase]
        substatuses = {
            name: ("not_applicable" if i == 0 else "tested") for i, name in enumerate(branches)
        }
        _update_phase(out, phase, status="complete", substatuses=substatuses)
        artifact = _skeleton(init_mod, phase)
        artifact["authorization_basis"] = "operator_supplied_material"
        artifact["summaries"] = [
            {
                "branch": name,
                "branch_status": substatuses[name],
                "reason": "" if substatuses[name] == "tested"
                else "no package/storage material in scope",
                "evidence_ref": "" if substatuses[name] == "not_applicable"
                else "notes/storage-evidence.md",
                "precondition": "operator-supplied authorization material or package copy only",
            }
            for name in branches
        ]
        _write_json(out / init_mod.STORAGE_PACKAGE_REVIEW_ARTIFACTS[phase], artifact)
        assert _audit_storage(audit_mod, out, phase) == []


def test_audit_missing_phase_row_is_silent(audit_mod, tmp_path):
    assert audit_mod.storage_package_review_issues(
        tmp_path, "local_data_exposure", None
    ) == []


def test_audit_integration_surfaces_storage_issues(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _update_phase(out, "crypto_and_secret_handling", status="complete")
    buffer = io.StringIO()
    old_argv = sys.argv
    sys.argv = [str(AUDIT_SCRIPT), str(out), "--json"]
    try:
        with contextlib.redirect_stdout(buffer):
            code = audit_mod.main()
    finally:
        sys.argv = old_argv
    assert code != 0
    result = json.loads(buffer.getvalue())
    assert any(issue.startswith("crypto_and_secret_handling") for issue in result["issues"])
    assert result["state"] != "CLOSED"
