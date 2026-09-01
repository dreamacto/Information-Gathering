"""tests/test_xcx_cloud_reconciliation_phase_split.py —— xcx static/dynamic 对账插入 +
plugins_cloud_third_party 云拆分落地测试（batch12_0，实施规格 6.2/6.4/6.7；契约
miniapp_reconciliation_schema + miniapp_cloud_schema）。

覆盖：
  - init/audit skill 常量 ↔ 两份新契约 ↔ contracts/coverage_substatus_schema.json
    多层无漂移；PHASES/CORE_PHASES 拆分位置正确（static_dynamic_reconciliation 在
    dynamic_mapping 后、platform_login_exchange 前；三个云 phase 替换
    plugins_cloud_third_party 原位置）且 plugins_cloud_third_party 不再存在；
  - 十值端点状态（规格 1570-1581 行）为 CSV 行级枚举、与 coverage_substatus 六值
    不同源（互不映射）；attribution 枚举与 audit KNOWN_HOST_STATES 同源对齐；
  - init：四 phase substatuses 种子、两个 review JSON 骨架 + 两个 CSV 表头种子、
    --resume 幂等、既有工作区 plugins_cloud_third_party 行 resume 升级为三行、
    缺失 static_dynamic_reconciliation 行插入 dynamic_mapping 后（无锚点兜底追加）；
  - audit：cloud_json_review_issues 正例（review JSON 形状违例/全 proven 正例）、
    static_dynamic_reconciliation_issues 与 third_party_boundary_issues 的 CSV
    审计正负例（表头精确匹配、行枚举、判定行 reason、tested 需 ≥1 行、
    not_applicable 需 phase reason）。

skill 脚本自包含（不 import src 包），通过 importlib 按路径加载 canonical 脚本；
纯离线，不发任何网络请求。
"""
from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

INIT_SCRIPT = ROOT / ".agents" / "skills" / "xcx" / "scripts" / "init_miniapp_engagement.py"
AUDIT_SCRIPT = ROOT / ".agents" / "skills" / "xcx" / "scripts" / "audit_miniapp_engagement.py"
RECONCILIATION_CONTRACT_PATH = ROOT / "contracts" / "miniapp_reconciliation_schema.json"
CLOUD_CONTRACT_PATH = ROOT / "contracts" / "miniapp_cloud_schema.json"
COVERAGE_CONTRACT_PATH = ROOT / "contracts" / "coverage_substatus_schema.json"

RECONCILIATION_PHASES = ("static_dynamic_reconciliation",)
CLOUD_PHASES = (
    "cloud_function_testing",
    "cloud_storage_acl_testing",
    "third_party_platform_boundary",
)
ALL_NEW_PHASES = RECONCILIATION_PHASES + CLOUD_PHASES

SPEC_ENDPOINT_STATES = (
    "static_only",
    "dynamic_only",
    "both_seen",
    "feature_gated",
    "stale",
    "version_specific",
    "third_party",
    "platform_shared",
    "unreachable",
    "needs_manual_validation",
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
    return _load_module("xcx_init_miniapp_b12", INIT_SCRIPT)


@pytest.fixture(scope="module")
def audit_mod():
    return _load_module("xcx_audit_miniapp_b12", AUDIT_SCRIPT)


@pytest.fixture(scope="module")
def reconciliation_contract():
    return _load_json(RECONCILIATION_CONTRACT_PATH)


@pytest.fixture(scope="module")
def cloud_contract():
    return _load_json(CLOUD_CONTRACT_PATH)


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
    payload = _load_json(root / "phase_status.miniapp.json")
    row = next(r for r in payload["phases"] if r["phase"] == phase)
    row.update(fields)
    _write_json(root / "phase_status.miniapp.json", payload)
    return row


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_csv(path: Path, fields, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# 契约常量无漂移（skill 自包含常量 ↔ 两份新契约 ↔ coverage_substatus_schema）
# ---------------------------------------------------------------------------

def test_contracts_define_exactly_expected_phases(reconciliation_contract, cloud_contract):
    assert tuple(reconciliation_contract["phases"].keys()) == RECONCILIATION_PHASES
    assert tuple(cloud_contract["phases"].keys()) == CLOUD_PHASES


def test_reconciliation_branches_match_contract(init_mod, audit_mod, reconciliation_contract):
    for phase in RECONCILIATION_PHASES:
        branches = tuple(reconciliation_contract["phases"][phase]["branches"])
        assert init_mod.RECONCILIATION_REVIEW_BRANCHES[phase] == branches
        assert tuple(audit_mod.RECONCILIATION_REVIEW_BRANCHES[phase]) == branches
        assert len(branches) >= 4


def test_cloud_branches_match_contract(init_mod, audit_mod, cloud_contract):
    for phase in CLOUD_PHASES:
        branches = tuple(cloud_contract["phases"][phase]["branches"])
        assert init_mod.CLOUD_REVIEW_BRANCHES[phase] == branches
        assert tuple(audit_mod.CLOUD_REVIEW_BRANCHES[phase]) == branches
        assert len(branches) >= 2


def test_artifact_paths_match_spec(init_mod, audit_mod, reconciliation_contract, cloud_contract):
    expected = {
        "static_dynamic_reconciliation": "artifacts/miniapp/reconciliation/static-dynamic-endpoints.csv",
        "cloud_function_testing": "artifacts/miniapp/cloud/cloud-function-review.json",
        "cloud_storage_acl_testing": "artifacts/miniapp/cloud/object-storage-review.json",
        "third_party_platform_boundary": "artifacts/miniapp/cloud/third-party-boundary.csv",
    }
    merged_init = {**init_mod.RECONCILIATION_REVIEW_ARTIFACTS, **init_mod.CLOUD_REVIEW_ARTIFACTS}
    merged_audit = {**audit_mod.RECONCILIATION_REVIEW_ARTIFACTS, **audit_mod.CLOUD_REVIEW_ARTIFACTS}
    assert merged_init == expected
    assert merged_audit == expected
    for phase in RECONCILIATION_PHASES:
        assert reconciliation_contract["phases"][phase]["artifact"] == expected[phase]
    for phase in CLOUD_PHASES:
        assert cloud_contract["phases"][phase]["artifact"] == expected[phase]


def test_reconciliation_endpoint_states_match_spec(init_mod, audit_mod, reconciliation_contract):
    contract_states = tuple(
        reconciliation_contract["phases"]["static_dynamic_reconciliation"]["endpoint_states"]
    )
    assert tuple(init_mod.RECONCILIATION_ENDPOINT_STATES) == SPEC_ENDPOINT_STATES
    assert tuple(audit_mod.RECONCILIATION_ENDPOINT_STATES) == SPEC_ENDPOINT_STATES
    assert contract_states == SPEC_ENDPOINT_STATES


def test_endpoint_states_disjoint_from_coverage_substatus(
    audit_mod, reconciliation_contract, coverage_contract
):
    """十值端点状态为 CSV 行级枚举，与 coverage_substatus 六值不同源：两枚举互不
    映射、互不 substitute（batch12_0 卡片出入留痕 2）。唯一语义交集为
    needs_manual_validation（同名但分别承载行级判定与 phase 覆盖语义），其余九值
    与五值各自独立——不同源不等于不相交，测试锁定交集恰为一值。"""
    six_values = set(coverage_contract["status_values"])
    row_states = set(reconciliation_contract["phases"]["static_dynamic_reconciliation"]["endpoint_states"])
    assert len(row_states) == 10
    assert row_states & six_values == {"needs_manual_validation"}
    assert len(row_states - six_values) == 9
    contract_status_values = set(reconciliation_contract["coverage_substatus"]["status_values"])
    assert contract_status_values == six_values


def test_coverage_substatus_enum_single_source(audit_mod, cloud_contract, coverage_contract):
    assert set(audit_mod.COVERAGE_SUBSTATUSES) == set(coverage_contract["status_values"])
    assert set(cloud_contract["coverage_substatus"]["status_values"]) == set(
        coverage_contract["status_values"]
    )
    # proven 子集在 miniapp 契约的 coverage_substatus 段定义（与 batch10/11 契约同构；
    # coverage_substatus_schema 顶层只定义六值枚举与不变量）。
    assert set(audit_mod.PROVEN_SUBSTATUSES) == set(cloud_contract["coverage_substatus"]["proven_values"])
    assert set(audit_mod.AUTHORIZATION_BASIS_VALUES) == set(cloud_contract["authorization_basis_values"])


def test_attribution_values_match_known_host_states(audit_mod, cloud_contract):
    """attribution 归属枚举与 audit KNOWN_HOST_STATES 同源对齐（单一来源：hosts
    分类状态；契约 invariant 留痕）。"""
    assert set(audit_mod.THIRD_PARTY_ATTRIBUTION_VALUES) == set(audit_mod.KNOWN_HOST_STATES)
    assert len(audit_mod.THIRD_PARTY_ATTRIBUTION_VALUES) == 8
    assert set(cloud_contract["phases"]["third_party_platform_boundary"]["attribution_values"]) == set(
        audit_mod.THIRD_PARTY_ATTRIBUTION_VALUES
    )


def test_csv_fields_match_contract(init_mod, audit_mod, reconciliation_contract, cloud_contract):
    assert tuple(init_mod.RECONCILIATION_CSV_FIELDS) == tuple(
        reconciliation_contract["phases"]["static_dynamic_reconciliation"]["csv_fields"]
    )
    assert tuple(audit_mod.RECONCILIATION_CSV_FIELDS) == tuple(
        reconciliation_contract["phases"]["static_dynamic_reconciliation"]["csv_fields"]
    )
    assert tuple(init_mod.THIRD_PARTY_CSV_FIELDS) == tuple(
        cloud_contract["phases"]["third_party_platform_boundary"]["csv_fields"]
    )
    assert tuple(audit_mod.THIRD_PARTY_CSV_FIELDS) == tuple(
        cloud_contract["phases"]["third_party_platform_boundary"]["csv_fields"]
    )


def test_phase_split_positions_and_no_legacy_name(init_mod, audit_mod):
    phases = init_mod.PHASES
    assert "plugins_cloud_third_party" not in phases
    assert "plugins_cloud_third_party" not in audit_mod.CORE_PHASES
    for phase in ALL_NEW_PHASES:
        assert phase in phases
        assert phase in audit_mod.CORE_PHASES
    assert phases.index("static_dynamic_reconciliation") == phases.index("dynamic_mapping") + 1
    assert phases.index("platform_login_exchange") == phases.index("static_dynamic_reconciliation") + 1
    assert (
        phases.index("cloud_function_testing")
        == phases.index("webview_bridge_links") + 1
    )
    assert phases.index("cloud_storage_acl_testing") == phases.index("cloud_function_testing") + 1
    assert (
        phases.index("third_party_platform_boundary")
        == phases.index("cloud_storage_acl_testing") + 1
    )
    assert (
        phases.index("candidate_validation")
        == phases.index("third_party_platform_boundary") + 1
    )


def test_skeleton_fields_match_contract(init_mod, cloud_contract):
    fields = init_mod.AUTH_REVIEW_SKELETON_FIELDS
    assert tuple(fields["row_fields"]) == tuple(cloud_contract["artifact_fields"]["row_fields"])
    assert tuple(fields["summary_fields"]) == tuple(cloud_contract["artifact_fields"]["summary_fields"])
    artifact_keys = set(cloud_contract["artifact_fields"]["artifact_keys"])
    for phase in ("cloud_function_testing", "cloud_storage_acl_testing"):
        assert set(init_mod.cloud_review_skeleton(phase).keys()) == artifact_keys


# ---------------------------------------------------------------------------
# init：substatuses 种子 + 产物骨架 + 幂等 + resume 升级
# ---------------------------------------------------------------------------

def test_init_seeds_new_phases_with_empty_substatuses(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    names = [row["phase"] for row in _phase_rows(out)]
    for phase in ALL_NEW_PHASES:
        assert phase in names
        row = _phase_row(out, phase)
        assert row["status"] == "pending"
        branches = init_mod.RECONCILIATION_REVIEW_BRANCHES.get(phase) or init_mod.CLOUD_REVIEW_BRANCHES[phase]
        assert row["substatuses"] == {name: "" for name in branches}
    assert "plugins_cloud_third_party" not in names


def test_init_seeds_csv_headers_and_json_skeletons(init_mod, tmp_path, cloud_contract):
    out = _run_init(init_mod, tmp_path)
    recon_path = out / init_mod.RECONCILIATION_REVIEW_ARTIFACTS["static_dynamic_reconciliation"]
    assert recon_path.is_file()
    with recon_path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))
    assert rows == [list(init_mod.RECONCILIATION_CSV_FIELDS)]
    tp_path = out / init_mod.CLOUD_REVIEW_ARTIFACTS["third_party_platform_boundary"]
    with tp_path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))
    assert rows == [list(init_mod.THIRD_PARTY_CSV_FIELDS)]
    for phase in ("cloud_function_testing", "cloud_storage_acl_testing"):
        path = out / init_mod.CLOUD_REVIEW_ARTIFACTS[phase]
        assert path.is_file()
        data = _load_json(path)
        assert data["schema_version"] == "1.0"
        assert data["contract"] == "miniapp_cloud_schema"
        assert data["phase"] == phase
        assert data["observation_schema_version"] == "1.0"
        assert data["substatuses"] == {name: "" for name in init_mod.CLOUD_REVIEW_BRANCHES[phase]}
        assert data["rows"] == []
        assert data["summaries"] == []
        assert data["violations"] == []
        assert data["authorization_basis"] == ""


def test_init_resume_is_idempotent(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    before = (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig")
    recon_before = (
        out / init_mod.RECONCILIATION_REVIEW_ARTIFACTS["static_dynamic_reconciliation"]
    ).read_text(encoding="utf-8-sig")
    cloud_before = (
        out / init_mod.CLOUD_REVIEW_ARTIFACTS["cloud_function_testing"]
    ).read_text(encoding="utf-8-sig")
    _run_init(init_mod, tmp_path, "--resume")
    assert (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig") == before
    assert (
        out / init_mod.RECONCILIATION_REVIEW_ARTIFACTS["static_dynamic_reconciliation"]
    ).read_text(encoding="utf-8-sig") == recon_before
    assert (
        out / init_mod.CLOUD_REVIEW_ARTIFACTS["cloud_function_testing"]
    ).read_text(encoding="utf-8-sig") == cloud_before


def test_init_resume_upgrades_legacy_plugins_cloud_third_party(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    # 模拟拆分前的旧工作区：三行合并回一行 plugins_cloud_third_party（complete 不可证明）
    payload = _load_json(out / "phase_status.miniapp.json")
    phases = payload["phases"]
    first_idx = next(i for i, r in enumerate(phases) if r["phase"] == "cloud_function_testing")
    last_idx = next(i for i, r in enumerate(phases) if r["phase"] == "third_party_platform_boundary")
    legacy_row = {
        "phase": "plugins_cloud_third_party",
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
    assert "plugins_cloud_third_party" not in names
    for phase in CLOUD_PHASES:
        row = _phase_row(out, phase)
        assert row["status"] == "pending"
        assert "migrated_from_plugins_cloud_third_party" in row["reason"]
        assert "old_status=complete" in row["reason"]
        assert row["substatuses"] == {name: "" for name in init_mod.CLOUD_REVIEW_BRANCHES[phase]}
    # 幂等：再次 resume 不再变化
    snapshot = (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig")
    _run_init(init_mod, tmp_path, "--resume")
    assert (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig") == snapshot


def test_init_resume_inserts_missing_reconciliation_row(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    payload = _load_json(out / "phase_status.miniapp.json")
    payload["phases"] = [
        r for r in payload["phases"] if r["phase"] != "static_dynamic_reconciliation"
    ]
    _write_json(out / "phase_status.miniapp.json", payload)

    _run_init(init_mod, tmp_path, "--resume")

    names = [row["phase"] for row in _phase_rows(out)]
    assert "static_dynamic_reconciliation" in names
    row = _phase_row(out, "static_dynamic_reconciliation")
    assert row["status"] == "pending"
    assert "inserted_by_static_dynamic_reconciliation_split" in row["reason"]
    assert row["substatuses"] == {
        name: ""
        for name in init_mod.RECONCILIATION_REVIEW_BRANCHES["static_dynamic_reconciliation"]
    }
    assert names.index("static_dynamic_reconciliation") == names.index("dynamic_mapping") + 1
    # 幂等
    snapshot = (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig")
    _run_init(init_mod, tmp_path, "--resume")
    assert (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig") == snapshot


def test_init_resume_appends_reconciliation_row_without_anchor(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    payload = _load_json(out / "phase_status.miniapp.json")
    payload["phases"] = [
        r for r in payload["phases"]
        if r["phase"] not in {"static_dynamic_reconciliation", "dynamic_mapping"}
    ]
    _write_json(out / "phase_status.miniapp.json", payload)

    _run_init(init_mod, tmp_path, "--resume")

    names = [row["phase"] for row in _phase_rows(out)]
    assert "static_dynamic_reconciliation" in names
    assert names.index("static_dynamic_reconciliation") == len(names) - 1


# ---------------------------------------------------------------------------
# audit：cloud_json_review_issues / static_dynamic_reconciliation_issues /
# third_party_boundary_issues 正例与负例
# ---------------------------------------------------------------------------

def _audit_new(audit_mod, root: Path, phase: str):
    if phase in audit_mod.RECONCILIATION_REVIEW_BRANCHES:
        fn = audit_mod.static_dynamic_reconciliation_issues
    elif audit_mod.CLOUD_REVIEW_ARTIFACTS[phase].endswith(".csv"):
        fn = audit_mod.third_party_boundary_issues
    else:
        fn = audit_mod.cloud_json_review_issues
    row = next((r for r in _phase_rows(root) if r["phase"] == phase), None)
    return fn(root, phase, row)


def test_audit_missing_phase_row_is_silent(audit_mod, tmp_path):
    for phase in ALL_NEW_PHASES:
        if phase in audit_mod.RECONCILIATION_REVIEW_BRANCHES:
            assert audit_mod.static_dynamic_reconciliation_issues(tmp_path, phase, None) == []
        elif audit_mod.CLOUD_REVIEW_ARTIFACTS[phase].endswith(".csv"):
            assert audit_mod.third_party_boundary_issues(tmp_path, phase, None) == []
        else:
            assert audit_mod.cloud_json_review_issues(tmp_path, phase, None) == []


def test_audit_pending_new_phases_have_no_issues(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    for phase in ALL_NEW_PHASES:
        assert _audit_new(audit_mod, out, phase) == []


def test_audit_reconciliation_complete_with_unrecorded_branches_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _update_phase(out, "static_dynamic_reconciliation", status="complete")
    issues = _audit_new(audit_mod, out, "static_dynamic_reconciliation")
    assert any("no recorded substatus" in issue for issue in issues)


def test_audit_reconciliation_csv_header_mismatch_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    recon_path = out / audit_mod.RECONCILIATION_REVIEW_ARTIFACTS["static_dynamic_reconciliation"]
    fields = [f for f in audit_mod.RECONCILIATION_CSV_FIELDS if f != "notes"]
    _write_csv(recon_path, fields, [])
    issues = _audit_new(audit_mod, out, "static_dynamic_reconciliation")
    assert any("header must be exactly" in issue for issue in issues)


def test_audit_reconciliation_invalid_row_status_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    recon_path = out / audit_mod.RECONCILIATION_REVIEW_ARTIFACTS["static_dynamic_reconciliation"]
    _write_csv(
        recon_path,
        audit_mod.RECONCILIATION_CSV_FIELDS,
        [
            {"status": "not-a-state", "reason": ""},
            {"status": "unreachable", "reason": ""},
            {"status": "both_seen", "reason": ""},
        ],
    )
    issues = _audit_new(audit_mod, out, "static_dynamic_reconciliation")
    text = "\n".join(issues)
    assert "invalid status 'not-a-state'" in text
    assert "status 'unreachable' requires a non-empty reason" in text
    assert not any("both_seen" in issue and "reason" in issue for issue in issues)


def test_audit_reconciliation_tested_branch_without_rows_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    phase = "static_dynamic_reconciliation"
    branches = audit_mod.RECONCILIATION_REVIEW_BRANCHES[phase]
    _update_phase(out, phase, status="complete", substatuses={name: "tested" for name in branches})
    # CSV 保留表头但无数据行
    issues = _audit_new(audit_mod, out, phase)
    for branch in branches:
        assert any(
            f"tested branch {branch} requires at least one recorded row" in issue
            for issue in issues
        )


def test_audit_reconciliation_fully_proven_passes(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    phase = "static_dynamic_reconciliation"
    branches = audit_mod.RECONCILIATION_REVIEW_BRANCHES[phase]
    substatuses = {name: ("not_applicable" if i == 0 else "tested") for i, name in enumerate(branches)}
    _update_phase(
        out, phase, status="complete", substatuses=substatuses,
        reason="static_only branch not applicable: no static endpoint baseline material in scope",
    )
    recon_path = out / audit_mod.RECONCILIATION_REVIEW_ARTIFACTS[phase]
    _write_csv(
        recon_path,
        audit_mod.RECONCILIATION_CSV_FIELDS,
        [
            {
                "endpoint_id": "ep-0001", "host": "api.example.com", "method": "GET",
                "path": "/v1/items", "source_material": "mat-0001",
                "static_evidence_ref": "endpoints.csv", "dynamic_evidence_ref": "dynamic.csv",
                "status": "both_seen", "reason": "", "notes": "",
            }
        ],
    )
    assert _audit_new(audit_mod, out, phase) == []


def test_audit_third_party_invalid_rows_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    tp_path = out / audit_mod.CLOUD_REVIEW_ARTIFACTS["third_party_platform_boundary"]
    _write_csv(
        tp_path,
        audit_mod.THIRD_PARTY_CSV_FIELDS,
        [
            {"service_type": "video", "attribution": "mine", "boundary_status": "vulnerable", "reason": ""},
            {"service_type": "map", "attribution": "confirmation_required", "boundary_status": "", "reason": ""},
        ],
    )
    issues = _audit_new(audit_mod, out, "third_party_platform_boundary")
    text = "\n".join(issues)
    assert "invalid service_type 'video'" in text
    assert "invalid attribution 'mine'" in text
    assert "invalid boundary_status 'vulnerable'" in text
    assert "attribution 'confirmation_required' requires a non-empty reason" in text


def test_audit_third_party_fully_proven_passes(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    phase = "third_party_platform_boundary"
    branches = audit_mod.CLOUD_REVIEW_BRANCHES[phase]
    substatuses = {name: ("not_applicable" if i == 0 else "tested") for i, name in enumerate(branches)}
    _update_phase(
        out, phase, status="complete", substatuses=substatuses,
        reason="third_party_service_boundary not applicable: no third-party service in scope",
    )
    tp_path = out / audit_mod.CLOUD_REVIEW_ARTIFACTS[phase]
    _write_csv(
        tp_path,
        audit_mod.THIRD_PARTY_CSV_FIELDS,
        [
            {
                "row_id": "tp-0001", "service_name": "map-sdk", "service_type": "map",
                "host": "map.vendor.com", "attribution": "third_party",
                "boundary_status": "signal", "evidence_ref": "hosts.csv",
                "reason": "", "notes": "",
            },
            {
                "row_id": "tp-0002", "service_name": "cloud-env-shared", "service_type": "sdk",
                "host": "tcb.example.com", "attribution": "platform_shared",
                "boundary_status": "signal", "evidence_ref": "hosts.csv",
                "reason": "", "notes": "",
            },
        ],
    )
    assert _audit_new(audit_mod, out, phase) == []


def test_audit_cloud_json_shape_violations_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    phase = "cloud_function_testing"
    artifact = init_mod.cloud_review_skeleton(phase)
    artifact["contract"] = "wrong_contract"
    artifact["phase"] = "cloud_storage_acl_testing"
    artifact["rows"] = [
        {"branch": "unknown_branch", "status": "signal"},
        {"branch": "anonymous_invocation", "status": "not-a-status"},
    ]
    artifact["summaries"] = [
        {"branch": "unknown_branch", "branch_status": "tested"},
        {"branch": "anonymous_invocation", "branch_status": "bogus"},
        {"branch": "anonymous_invocation", "branch_status": "tested"},
    ]
    artifact["authorization_basis"] = "self_created_credentials"
    _write_json(out / audit_mod.CLOUD_REVIEW_ARTIFACTS[phase], artifact)
    issues = _audit_new(audit_mod, out, phase)
    text = "\n".join(issues)
    assert "contract must be miniapp_cloud_schema" in text
    assert "phase field mismatch" in text
    assert "row has unknown branch 'unknown_branch'" in text
    assert "row has invalid status 'not-a-status'" in text
    assert "summary has unknown branch 'unknown_branch'" in text
    assert "invalid branch_status 'bogus'" in text
    assert "duplicate summary for branch 'anonymous_invocation'" in text
    assert "authorization_basis 'self_created_credentials' is not one of" in text


def test_audit_cloud_json_fully_proven_passes(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    (out / "notes").mkdir(parents=True, exist_ok=True)
    (out / "notes" / "cloud-evidence.md").write_text("# cloud evidence\n", encoding="utf-8")
    for phase in ("cloud_function_testing", "cloud_storage_acl_testing"):
        branches = audit_mod.CLOUD_REVIEW_BRANCHES[phase]
        substatuses = {
            name: ("not_applicable" if i == 0 else "tested") for i, name in enumerate(branches)
        }
        _update_phase(out, phase, status="complete", substatuses=substatuses)
        artifact = init_mod.cloud_review_skeleton(phase)
        artifact["authorization_basis"] = "operator_supplied_material"
        artifact["summaries"] = [
            {
                "branch": name,
                "branch_status": substatuses[name],
                "reason": "" if substatuses[name] == "tested"
                else "no cloud material in scope",
                "evidence_ref": "" if substatuses[name] == "not_applicable"
                else "notes/cloud-evidence.md",
                "precondition": "operator-supplied material or local traffic only",
            }
            for name in branches
        ]
        _write_json(out / audit_mod.CLOUD_REVIEW_ARTIFACTS[phase], artifact)
        assert _audit_new(audit_mod, out, phase) == []


def test_audit_integration_surfaces_new_issues(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _update_phase(out, "cloud_storage_acl_testing", status="complete")
    _update_phase(out, "static_dynamic_reconciliation", status="complete")
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
    issues = "\n".join(result["issues"])
    assert any(issue.startswith("cloud_storage_acl_testing") for issue in result["issues"])
    assert "static_dynamic_reconciliation" in issues
    assert result["state"] != "CLOSED"
