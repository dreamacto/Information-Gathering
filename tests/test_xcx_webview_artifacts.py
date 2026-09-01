"""tests/test_xcx_webview_artifacts.py —— xcx webview_bridge_links 三固定 CSV 产物
落地测试（batch13_1/batch13_2，实施规格 6.8 1662-1682 行；契约
miniapp_webview_schema）。

覆盖：
  - init/audit skill 常量 ↔ 契约（batch13_2 接入）多层无漂移；七分支一一对应规格
    1674-1680 行七项覆盖；分支→产物 1:1；三 CSV 产物路径与规格 1667-1669 行逐字；
  - init：webview 分支 substatuses 种子、三 CSV 表头种子、--resume 幂等、既有工作区
    无 substatuses 行 resume 补种升级（旧 complete 回置 pending + reason 留痕）、
    已有 substatuses 键的工作区零改动；
  - audit：webview_bridge_links_issues 正负例（表头精确匹配、行级枚举/判定行
    reason、未知分支键、tested 需分支所属产物 ≥1 行、not_applicable 需 phase
    reason、全 proven 正例）；
  - 镜像字节一致性（canonical ↔ .claude/.opencode，全量无例外；B2 已于
    batch14_1 收口）。

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
WEBVIEW_CONTRACT_PATH = ROOT / "contracts" / "miniapp_webview_schema.json"
COVERAGE_CONTRACT_PATH = ROOT / "contracts" / "coverage_substatus_schema.json"

WEBVIEW_PHASE = "webview_bridge_links"

# 规格 6.8 1674-1680 行七项覆盖 → 七分支（batch13_0 D1）
SPEC_COVERAGE_BRANCHES = (
    "webview_allowed_domains",
    "postmessage_origin",
    "bridge_method_exposure",
    "custom_scheme",
    "deep_link_sensitive_params",
    "external_app_browser_jump",
    "cookie_token_sharing_boundary",
)
# 规格 6.8 1667-1669 行三个固定产物路径（逐字）
SPEC_ARTIFACT_PATHS = (
    "artifacts/miniapp/webview/webview-origin-inventory.csv",
    "artifacts/miniapp/webview/bridge-method-inventory.csv",
    "artifacts/miniapp/webview/deep-link-review-queue.csv",
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
    return _load_module("xcx_init_miniapp_b13", INIT_SCRIPT)


@pytest.fixture(scope="module")
def audit_mod():
    return _load_module("xcx_audit_miniapp_b13", AUDIT_SCRIPT)


@pytest.fixture(scope="module")
def webview_contract():
    return _load_json(WEBVIEW_CONTRACT_PATH)


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


def _audit_webview(audit_mod, root: Path):
    row = next((r for r in _phase_rows(root) if r["phase"] == WEBVIEW_PHASE), None)
    return audit_mod.webview_bridge_links_issues(root, WEBVIEW_PHASE, row)


# ---------------------------------------------------------------------------
# 常量形状：七分支、三产物路径逐字、分支→产物 1:1、CSV 列/枚举 init↔audit 同源
# ---------------------------------------------------------------------------

def test_webview_branches_match_seven_coverage_items(init_mod, audit_mod):
    assert tuple(init_mod.WEBVIEW_REVIEW_BRANCHES[WEBVIEW_PHASE]) == SPEC_COVERAGE_BRANCHES
    assert tuple(audit_mod.WEBVIEW_REVIEW_BRANCHES[WEBVIEW_PHASE]) == SPEC_COVERAGE_BRANCHES
    assert len(SPEC_COVERAGE_BRANCHES) == 7


def test_webview_artifact_paths_match_spec_verbatim(init_mod, audit_mod):
    assert tuple(init_mod.WEBVIEW_REVIEW_ARTIFACTS[WEBVIEW_PHASE]) == SPEC_ARTIFACT_PATHS
    assert (
        init_mod.WEBVIEW_ORIGIN_INVENTORY_CSV,
        init_mod.WEBVIEW_BRIDGE_METHOD_CSV,
        init_mod.WEBVIEW_DEEP_LINK_QUEUE_CSV,
    ) == SPEC_ARTIFACT_PATHS
    for rel in SPEC_ARTIFACT_PATHS:
        assert rel.startswith("artifacts/miniapp/webview/")
        assert rel.endswith(".csv")


def test_webview_branch_to_artifact_mapping_is_one_to_one(init_mod, audit_mod):
    """分支→产物 1:1（batch13_0 D1）：每分支恰映射一个产物、每个产物至少承载一个
    分支、映射不含分支集合之外的键；init 与 audit 映射一致。"""
    branches = set(SPEC_COVERAGE_BRANCHES)
    artifacts = set(SPEC_ARTIFACT_PATHS)
    for mod in (init_mod, audit_mod):
        mapping = mod.WEBVIEW_BRANCH_ARTIFACTS
        assert set(mapping) == branches
        assert set(mapping.values()) <= artifacts
        # 每产物至少承载一个分支（无空产物）
        assert set(mapping.values()) == artifacts
    # 三个分支域的具体归属（batch13_0 D1：cookie/token 共享边界按 per-origin 记录）
    assert init_mod.WEBVIEW_BRANCH_ARTIFACTS["webview_allowed_domains"] == init_mod.WEBVIEW_ORIGIN_INVENTORY_CSV
    assert init_mod.WEBVIEW_BRANCH_ARTIFACTS["postmessage_origin"] == init_mod.WEBVIEW_ORIGIN_INVENTORY_CSV
    assert init_mod.WEBVIEW_BRANCH_ARTIFACTS["cookie_token_sharing_boundary"] == init_mod.WEBVIEW_ORIGIN_INVENTORY_CSV
    assert init_mod.WEBVIEW_BRANCH_ARTIFACTS["bridge_method_exposure"] == init_mod.WEBVIEW_BRIDGE_METHOD_CSV
    for branch in ("custom_scheme", "deep_link_sensitive_params", "external_app_browser_jump"):
        assert init_mod.WEBVIEW_BRANCH_ARTIFACTS[branch] == init_mod.WEBVIEW_DEEP_LINK_QUEUE_CSV


def test_webview_csv_fields_and_enums_match_between_scripts(init_mod, audit_mod):
    cases = [
        ("WEBVIEW_ORIGIN_CSV_FIELDS", 11),
        ("WEBVIEW_BRIDGE_CSV_FIELDS", 9),
        ("WEBVIEW_DEEP_LINK_CSV_FIELDS", 9),
        ("WEBVIEW_COOKIE_TOKEN_SHARED_VALUES", 5),
        ("WEBVIEW_CAPABILITY_VALUES", 7),
        ("WEBVIEW_BRIDGE_REASON_CAPABILITIES", 4),
        ("WEBVIEW_SCHEME_TYPES", 3),
        ("WEBVIEW_JUMP_TARGETS", 4),
        ("WEBVIEW_REASON_JUMP_TARGETS", 3),
    ]
    for name, length in cases:
        init_value = tuple(getattr(init_mod, name))
        audit_value = tuple(getattr(audit_mod, name))
        assert init_value == audit_value, name
        assert len(init_value) == length, name
    # 三组 CSV 列均含 shape 锁定必需列：row_id/boundary_status/evidence_ref/reason/notes
    for name in ("WEBVIEW_ORIGIN_CSV_FIELDS", "WEBVIEW_BRIDGE_CSV_FIELDS", "WEBVIEW_DEEP_LINK_CSV_FIELDS"):
        fields = getattr(init_mod, name)
        for required in ("row_id", "boundary_status", "evidence_ref", "reason", "notes"):
            assert required in fields, (name, required)
    # 判定子集是枚举的真子集
    assert set(init_mod.WEBVIEW_BRIDGE_REASON_CAPABILITIES) < set(init_mod.WEBVIEW_CAPABILITY_VALUES)
    assert set(init_mod.WEBVIEW_REASON_JUMP_TARGETS) < set(init_mod.WEBVIEW_JUMP_TARGETS)


def test_webview_phase_position_unchanged(init_mod, audit_mod):
    """6.8 是既有 phase 增产物：PHASES 位置不变（crypto 之后、cloud_function 之前），
    phase 名集合不因本批增删。"""
    phases = init_mod.PHASES
    assert "webview_bridge_links" in phases
    assert phases.index(WEBVIEW_PHASE) == phases.index("crypto_and_secret_handling") + 1
    assert phases.index("cloud_function_testing") == phases.index(WEBVIEW_PHASE) + 1
    assert WEBVIEW_PHASE in audit_mod.CORE_PHASES


# ---------------------------------------------------------------------------
# init：substatuses 种子 + 三 CSV 表头种子 + 幂等 + resume 升级
# ---------------------------------------------------------------------------

def test_init_seeds_webview_substatuses_and_csv_headers(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    row = _phase_row(out, WEBVIEW_PHASE)
    assert row["status"] == "pending"
    assert row["substatuses"] == {name: "" for name in SPEC_COVERAGE_BRANCHES}
    for rel, fields in init_mod.WEBVIEW_CSV_FIELDS_BY_ARTIFACT.items():
        path = out / rel
        assert path.is_file(), rel
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            assert next(csv.reader(handle)) == list(fields), rel


def test_init_resume_is_idempotent(init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    before_status = (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig")
    before_csvs = {
        rel: (out / rel).read_text(encoding="utf-8-sig")
        for rel in SPEC_ARTIFACT_PATHS
    }
    _run_init(init_mod, tmp_path, "--resume")
    assert (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig") == before_status
    for rel, content in before_csvs.items():
        assert (out / rel).read_text(encoding="utf-8-sig") == content


def test_init_resume_upgrades_legacy_webview_row_without_substatuses(init_mod, tmp_path):
    """batch13_0 D6：旧工作区 webview 行无 substatuses 键 → 补种七分支；旧 complete
    聚合对新分支不可证明 → 回置 pending + reason 留痕（不携带旧状态）。幂等。"""
    out = _run_init(init_mod, tmp_path)
    payload = _load_json(out / "phase_status.miniapp.json")
    row = next(r for r in payload["phases"] if r["phase"] == WEBVIEW_PHASE)
    del row["substatuses"]
    row["status"] = "complete"
    row["reason"] = "legacy aggregate completion"
    _write_json(out / "phase_status.miniapp.json", payload)

    _run_init(init_mod, tmp_path, "--resume")

    upgraded = _phase_row(out, WEBVIEW_PHASE)
    assert upgraded["status"] == "pending"
    assert "migrated_pre_webview_artifacts" in upgraded["reason"]
    assert "old_status=complete" in upgraded["reason"]
    assert upgraded["substatuses"] == {name: "" for name in SPEC_COVERAGE_BRANCHES}
    # 幂等：再次 resume 不再变化
    snapshot = (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig")
    _run_init(init_mod, tmp_path, "--resume")
    assert (out / "phase_status.miniapp.json").read_text(encoding="utf-8-sig") == snapshot


def test_init_resume_leaves_substated_webview_row_untouched(init_mod, tmp_path):
    """已有 substatuses 键的工作区零改动（幂等边界）：status 保持、substatuses 保持。"""
    out = _run_init(init_mod, tmp_path)
    payload = _load_json(out / "phase_status.miniapp.json")
    row = next(r for r in payload["phases"] if r["phase"] == WEBVIEW_PHASE)
    row["status"] = "complete"
    row["substatuses"] = {name: "tested" for name in SPEC_COVERAGE_BRANCHES}
    _write_json(out / "phase_status.miniapp.json", payload)

    _run_init(init_mod, tmp_path, "--resume")

    after = _phase_row(out, WEBVIEW_PHASE)
    assert after["status"] == "complete"
    assert after["substatuses"] == {name: "tested" for name in SPEC_COVERAGE_BRANCHES}


# ---------------------------------------------------------------------------
# audit：webview_bridge_links_issues 正例与负例
# ---------------------------------------------------------------------------

def test_audit_missing_webview_row_is_silent(audit_mod, tmp_path):
    assert audit_mod.webview_bridge_links_issues(tmp_path, WEBVIEW_PHASE, None) == []


def test_audit_pending_webview_has_no_issues(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    assert _audit_webview(audit_mod, out) == []


def test_audit_webview_complete_without_substatuses_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    payload = _load_json(out / "phase_status.miniapp.json")
    row = next(r for r in payload["phases"] if r["phase"] == WEBVIEW_PHASE)
    del row["substatuses"]
    row["status"] = "complete"
    _write_json(out / "phase_status.miniapp.json", payload)
    issues = _audit_webview(audit_mod, out)
    text = "\n".join(issues)
    assert "substatuses are not recorded" in text
    for branch in SPEC_COVERAGE_BRANCHES:
        assert any(f"branch {branch} has no recorded substatus" in issue for issue in issues)


def test_audit_webview_header_mismatch_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    origin_path = out / audit_mod.WEBVIEW_ORIGIN_INVENTORY_CSV
    fields = [f for f in audit_mod.WEBVIEW_ORIGIN_CSV_FIELDS if f != "notes"]
    _write_csv(origin_path, fields, [])
    issues = _audit_webview(audit_mod, out)
    assert any(
        f"{audit_mod.WEBVIEW_ORIGIN_INVENTORY_CSV} header must be exactly" in issue
        for issue in issues
    )


def test_audit_webview_invalid_rows_rejected(audit_mod, init_mod, tmp_path):
    """三产物行级校验：空必填列、非法枚举、判定行缺 reason（三类判定规则逐一）。"""
    out = _run_init(init_mod, tmp_path)
    _write_csv(
        out / audit_mod.WEBVIEW_ORIGIN_INVENTORY_CSV,
        audit_mod.WEBVIEW_ORIGIN_CSV_FIELDS,
        [
            {"webview_origin": "", "cookie_token_shared": "shared", "reason": "", "notes": ""},
            {"webview_origin": "cdn.example.com", "cookie_token_shared": "auth_token", "reason": "", "notes": ""},
            {"webview_origin": "static.example.com", "cookie_token_shared": "none", "reason": "", "notes": ""},
        ],
    )
    _write_csv(
        out / audit_mod.WEBVIEW_BRIDGE_METHOD_CSV,
        audit_mod.WEBVIEW_BRIDGE_CSV_FIELDS,
        [
            {"method_name": "getToken", "exposed_scope": "all", "capability": "not-a-capability", "reason": "", "notes": ""},
            {"method_name": "saveFile", "exposed_scope": "", "capability": "file_access", "reason": "", "notes": ""},
            {"method_name": "navigate", "exposed_scope": "all", "capability": "navigation", "reason": "", "notes": ""},
        ],
    )
    _write_csv(
        out / audit_mod.WEBVIEW_DEEP_LINK_QUEUE_CSV,
        audit_mod.WEBVIEW_DEEP_LINK_CSV_FIELDS,
        [
            {"deep_link_pattern": "", "scheme_type": "scheme", "sensitive_params": "", "jump_target": "in_app", "reason": "", "notes": ""},
            {"deep_link_pattern": "app://order", "scheme_type": "custom_scheme", "sensitive_params": "object_id", "jump_target": "in_app", "reason": "", "notes": ""},
            {"deep_link_pattern": "app://share", "scheme_type": "custom_scheme", "sensitive_params": "", "jump_target": "somewhere", "reason": "", "notes": ""},
        ],
    )
    issues = _audit_webview(audit_mod, out)
    text = "\n".join(issues)
    # origin：空域名 + 非法枚举 + 判定值缺 reason + none 不需要 reason
    assert "has empty webview_origin" in text
    assert "invalid cookie_token_shared 'shared'" in text
    assert "cookie_token_shared 'auth_token' requires a non-empty reason" in text
    assert not any("'none' requires a non-empty reason" in issue for issue in issues)
    # bridge：非法 capability + 空暴露面 + file_access 判定行缺 reason + navigation 不需要
    assert "invalid capability 'not-a-capability'" in text
    assert "has empty exposed_scope" in text
    assert "capability 'file_access' requires a non-empty reason" in text
    assert not any("'navigation' requires" in issue for issue in issues)
    # deep link：空模式 + 非法 scheme_type + 敏感参数行缺 reason + 非法 jump_target
    assert "has empty deep_link_pattern" in text
    assert "invalid scheme_type 'scheme'" in text
    assert "deep link with sensitive params or external/unconfirmed jump requires" in text
    assert "invalid jump_target 'somewhere'" in text


def test_audit_webview_unknown_branch_key_rejected(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    _update_phase(out, WEBVIEW_PHASE, substatuses={"not_a_branch": "tested"})
    issues = _audit_webview(audit_mod, out)
    assert any("unknown review branch 'not_a_branch'" in issue for issue in issues)


def test_audit_webview_tested_requires_rows_in_own_artifact(audit_mod, init_mod, tmp_path):
    """batch13_0 D5/D1 关键语义：tested 分支的 ≥1 行按分支所属产物计——仅 bridge
    产物有行时，bridge 分支不报缺行，origin/deeplink 两域分支各自报缺行且消息指向
    各自产物路径。"""
    out = _run_init(init_mod, tmp_path)
    branches = audit_mod.WEBVIEW_REVIEW_BRANCHES[WEBVIEW_PHASE]
    _update_phase(
        out, WEBVIEW_PHASE, status="complete",
        substatuses={name: "tested" for name in branches},
    )
    _write_csv(
        out / audit_mod.WEBVIEW_BRIDGE_METHOD_CSV,
        audit_mod.WEBVIEW_BRIDGE_CSV_FIELDS,
        [
            {
                "row_id": "bm-0001", "method_name": "navigate", "exposed_scope": "all",
                "capability": "navigation", "source_material": "app.js",
                "boundary_status": "signal", "evidence_ref": "hosts.csv",
                "reason": "", "notes": "",
            }
        ],
    )
    issues = _audit_webview(audit_mod, out)
    # bridge 分支有行：不报缺行
    assert not any(
        "tested branch bridge_method_exposure requires" in issue for issue in issues
    )
    # origin 域三分支：缺行消息指向 origin 产物
    for branch in ("webview_allowed_domains", "postmessage_origin", "cookie_token_sharing_boundary"):
        assert any(
            f"tested branch {branch} requires at least one recorded row in "
            f"{audit_mod.WEBVIEW_ORIGIN_INVENTORY_CSV}" in issue
            for issue in issues
        )
    # deeplink 域三分支：缺行消息指向 deep link 产物
    for branch in ("custom_scheme", "deep_link_sensitive_params", "external_app_browser_jump"):
        assert any(
            f"tested branch {branch} requires at least one recorded row in "
            f"{audit_mod.WEBVIEW_DEEP_LINK_QUEUE_CSV}" in issue
            for issue in issues
        )


def test_audit_webview_not_applicable_branch_requires_phase_reason(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    branches = audit_mod.WEBVIEW_REVIEW_BRANCHES[WEBVIEW_PHASE]
    _update_phase(
        out, WEBVIEW_PHASE, status="complete",
        substatuses={name: "not_applicable" for name in branches},
        reason="",
    )
    issues = _audit_webview(audit_mod, out)
    for branch in branches:
        assert any(
            f"not_applicable branch {branch} requires a phase reason" in issue
            for issue in issues
        )


def test_audit_webview_fully_proven_passes(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    branches = audit_mod.WEBVIEW_REVIEW_BRANCHES[WEBVIEW_PHASE]
    substatuses = {
        "webview_allowed_domains": "tested",
        "postmessage_origin": "tested",
        "cookie_token_sharing_boundary": "tested",
        "bridge_method_exposure": "tested",
        "custom_scheme": "not_applicable",
        "deep_link_sensitive_params": "not_applicable",
        "external_app_browser_jump": "not_applicable",
    }
    assert set(substatuses) == set(branches)
    _update_phase(
        out, WEBVIEW_PHASE, status="complete", substatuses=substatuses,
        reason="no custom scheme or deep link declared in package manifest materials",
    )
    _write_csv(
        out / audit_mod.WEBVIEW_ORIGIN_INVENTORY_CSV,
        audit_mod.WEBVIEW_ORIGIN_CSV_FIELDS,
        [
            {
                "row_id": "wo-0001", "webview_origin": "https://h5.example.com",
                "business_purpose": "activity page", "source_material": "app.json",
                "source_location": "webview domains", "postmessage_target_origin": "",
                "cookie_token_shared": "none", "boundary_status": "signal",
                "evidence_ref": "hosts.csv", "reason": "", "notes": "",
            },
        ],
    )
    _write_csv(
        out / audit_mod.WEBVIEW_BRIDGE_METHOD_CSV,
        audit_mod.WEBVIEW_BRIDGE_CSV_FIELDS,
        [
            {
                "row_id": "bm-0001", "method_name": "navigate", "exposed_scope": "h5.example.com",
                "capability": "navigation", "source_material": "app.js",
                "boundary_status": "signal", "evidence_ref": "hosts.csv",
                "reason": "", "notes": "",
            },
        ],
    )
    # deep link 产物保留表头（not_applicable 分支无需行）
    assert _audit_webview(audit_mod, out) == []


def test_audit_integration_surfaces_webview_issues(audit_mod, init_mod, tmp_path):
    out = _run_init(init_mod, tmp_path)
    payload = _load_json(out / "phase_status.miniapp.json")
    row = next(r for r in payload["phases"] if r["phase"] == WEBVIEW_PHASE)
    del row["substatuses"]
    row["status"] = "complete"
    _write_json(out / "phase_status.miniapp.json", payload)
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
    assert any(issue.startswith(WEBVIEW_PHASE) for issue in result["issues"])
    assert result["state"] != "CLOSED"


# ---------------------------------------------------------------------------
# 契约锁（batch13_2）：契约 ↔ init/audit 常量多方无漂移
# ---------------------------------------------------------------------------

def test_contract_defines_exactly_webview_phase(webview_contract):
    assert webview_contract["contract"] == "miniapp_webview_schema"
    assert tuple(webview_contract["phases"].keys()) == (WEBVIEW_PHASE,)
    assert tuple(webview_contract["phases"][WEBVIEW_PHASE]["branches"]) == SPEC_COVERAGE_BRANCHES


def test_contract_artifacts_match_spec_and_script_mapping(init_mod, audit_mod, webview_contract):
    artifacts = webview_contract["phases"][WEBVIEW_PHASE]["artifacts"]
    assert tuple(a["artifact"] for a in artifacts) == SPEC_ARTIFACT_PATHS
    # 分支→产物 1:1：无交集、并集恰为七分支（集合级——契约按产物分组，扁平序
    # 与规格覆盖项序不同是预期），且与脚本映射分组一致
    seen: list[str] = []
    for entry in artifacts:
        assert set(entry["branches"]).isdisjoint(seen)
        seen.extend(entry["branches"])
    assert len(seen) == 7
    assert set(seen) == set(SPEC_COVERAGE_BRANCHES)
    for entry in artifacts:
        rel = entry["artifact"]
        for mod in (init_mod, audit_mod):
            for branch in entry["branches"]:
                assert mod.WEBVIEW_BRANCH_ARTIFACTS[branch] == rel


def test_contract_csv_fields_match_scripts(init_mod, audit_mod, webview_contract):
    fields_by_rel = {
        init_mod.WEBVIEW_ORIGIN_INVENTORY_CSV: init_mod.WEBVIEW_ORIGIN_CSV_FIELDS,
        init_mod.WEBVIEW_BRIDGE_METHOD_CSV: init_mod.WEBVIEW_BRIDGE_CSV_FIELDS,
        init_mod.WEBVIEW_DEEP_LINK_QUEUE_CSV: init_mod.WEBVIEW_DEEP_LINK_CSV_FIELDS,
    }
    for entry in webview_contract["phases"][WEBVIEW_PHASE]["artifacts"]:
        rel = entry["artifact"]
        assert tuple(entry["csv_fields"]) == tuple(fields_by_rel[rel])
        assert tuple(entry["csv_fields"]) == tuple(getattr(audit_mod, {
            audit_mod.WEBVIEW_ORIGIN_INVENTORY_CSV: "WEBVIEW_ORIGIN_CSV_FIELDS",
            audit_mod.WEBVIEW_BRIDGE_METHOD_CSV: "WEBVIEW_BRIDGE_CSV_FIELDS",
            audit_mod.WEBVIEW_DEEP_LINK_QUEUE_CSV: "WEBVIEW_DEEP_LINK_CSV_FIELDS",
        }[rel]))


def test_contract_row_enums_match_scripts(init_mod, audit_mod, webview_contract):
    expected = {
        init_mod.WEBVIEW_ORIGIN_INVENTORY_CSV: {
            "cookie_token_shared": tuple(init_mod.WEBVIEW_COOKIE_TOKEN_SHARED_VALUES),
        },
        init_mod.WEBVIEW_BRIDGE_METHOD_CSV: {
            "capability": tuple(init_mod.WEBVIEW_CAPABILITY_VALUES),
        },
        init_mod.WEBVIEW_DEEP_LINK_QUEUE_CSV: {
            "scheme_type": tuple(init_mod.WEBVIEW_SCHEME_TYPES),
            "jump_target": tuple(init_mod.WEBVIEW_JUMP_TARGETS),
        },
    }
    for entry in webview_contract["phases"][WEBVIEW_PHASE]["artifacts"]:
        rel = entry["artifact"]
        assert set(entry["row_enums"]) == set(expected[rel])
        for column, values in expected[rel].items():
            assert tuple(entry["row_enums"][column]) == values
            audit_name = {
                "cookie_token_shared": "WEBVIEW_COOKIE_TOKEN_SHARED_VALUES",
                "capability": "WEBVIEW_CAPABILITY_VALUES",
                "scheme_type": "WEBVIEW_SCHEME_TYPES",
                "jump_target": "WEBVIEW_JUMP_TARGETS",
            }[column]
            assert tuple(getattr(audit_mod, audit_name)) == values


def test_contract_reason_rules_match_audit_judgment_sets(init_mod, audit_mod, webview_contract):
    artifacts = {
        entry["artifact"]: entry
        for entry in webview_contract["phases"][WEBVIEW_PHASE]["artifacts"]
    }
    bridge_req = artifacts[init_mod.WEBVIEW_BRIDGE_METHOD_CSV]["row_requirements"]
    assert tuple(bridge_req["reason_required_capabilities"]) == tuple(
        audit_mod.WEBVIEW_BRIDGE_REASON_CAPABILITIES
    )
    deeplink_req = artifacts[init_mod.WEBVIEW_DEEP_LINK_QUEUE_CSV]["row_requirements"]
    assert tuple(deeplink_req["reason_required_jump_targets"]) == tuple(
        audit_mod.WEBVIEW_REASON_JUMP_TARGETS
    )
    # required_non_empty 列必须是该产物 csv_fields 的子集
    for entry in webview_contract["phases"][WEBVIEW_PHASE]["artifacts"]:
        assert set(entry["row_requirements"]["required_non_empty"]) <= set(entry["csv_fields"])


def test_contract_coverage_substatus_single_source(audit_mod, webview_contract, coverage_contract):
    six_values = set(coverage_contract["status_values"])
    assert set(webview_contract["coverage_substatus"]["status_values"]) == six_values
    assert set(audit_mod.COVERAGE_SUBSTATUSES) == six_values
    assert set(webview_contract["coverage_substatus"]["proven_values"]) == set(
        audit_mod.PROVEN_SUBSTATUSES
    )


def test_contract_structure_and_red_lines(webview_contract):
    for key in (
        "schema_version", "contract", "description", "type", "phases",
        "coverage_substatus", "red_lines", "invariants",
    ):
        assert key in webview_contract
    red_lines = "\n".join(webview_contract["red_lines"])
    # 规格 6.8 离线纪律红线：Cookie/token 不自动注入或重放；深链不自动拉起外部 App
    assert "不自动注入" in red_lines and "不重放" in red_lines
    assert "外部 App/浏览器" in red_lines
    invariants = "\n".join(webview_contract["invariants"])
    assert "1667-1669" in invariants
    assert "1674-1680" in invariants


# ---------------------------------------------------------------------------
# 镜像字节一致性（canonical ↔ .claude/.opencode；全量无例外，B2 已于
# batch14_1 收口）
# ---------------------------------------------------------------------------

def test_xcx_webview_script_mirrors_are_byte_identical():
    for rel in (
        "scripts/init_miniapp_engagement.py",
        "scripts/audit_miniapp_engagement.py",
    ):
        canonical = ROOT / ".agents" / "skills" / "xcx" / rel
        for mirror_name in (".claude", ".opencode"):
            mirror = ROOT / mirror_name / "skills" / "xcx" / rel
            assert mirror.is_file(), f"missing mirror file: {mirror_name}/{rel}"
            assert mirror.read_bytes() == canonical.read_bytes(), (
                f"mirror drift: {mirror_name}/skills/xcx/{rel}"
            )
