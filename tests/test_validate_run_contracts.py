"""validate_run_contracts 入口测试（阻塞项 B3；batch1_4 建立，batch2_3/batch3_3/batch6_0 扩展）。"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.maintenance.validate_run_contracts import collect_violations, main

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_FILES = [
    "workflow_schema.json",
    "run_quality_schema.json",
    "rule_precedence.json",
    "context_snapshot_schema.json",
    "candidate_identity_schema.json",
    "tool_capability_schema.json",
    "injection_candidate_schema.json",
    "graphql_schema.json",
    "api_reconciliation_schema.json",
    "miniapp_auth_schema.json",
    "miniapp_storage_package_schema.json",
    "miniapp_reconciliation_schema.json",
    "miniapp_cloud_schema.json",
    "miniapp_webview_schema.json",
]


def test_real_repo_contracts_pass():
    violations = collect_violations(ROOT)
    assert violations == []


def test_missing_contract_file_is_violation(tmp_path):
    violations = collect_violations(tmp_path)
    assert any("missing contract file" in v for v in violations)
    assert any("run_lifecycle import failed" not in v for v in violations)


def _copy_contracts(tmp_path) -> Path:
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    for name in CONTRACT_FILES:
        shutil.copy(ROOT / "contracts" / name, contracts / name)
    return tmp_path


def test_tampered_report_states_detected(tmp_path):
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "workflow_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["report_lifecycle_states"] = ["report_generated", "report_done"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("report_lifecycle_states drift" in v for v in violations)


def test_tampered_quality_states_detected(tmp_path):
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "run_quality_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["quality_status_states"] = ["GOOD", "BAD"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("quality_status_states drift" in v for v in violations)
    assert any("quality gate module" in v for v in violations)


def test_tampered_gate_threshold_detected(tmp_path):
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "run_quality_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["gate_thresholds"]["probe_coverage_min"] = 0.1
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("gate threshold drift for probe_coverage_min" in v for v in violations)


def test_unparseable_contract_detected(tmp_path):
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "workflow_schema.json"
    path.write_text("{broken", encoding="utf-8")
    violations = collect_violations(root)
    assert any("unparseable contract file" in v for v in violations)


def test_main_json_output_and_exit_codes(tmp_path):
    ok = main(["--json", "--root", str(ROOT)])
    assert ok == 0
    failing = main(["--json", "--root", str(tmp_path)])
    assert failing == 1


def test_cli_script_real_run_passes():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "maintenance" / "validate_run_contracts.py")],
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
        [sys.executable, str(ROOT / "scripts" / "maintenance" / "validate_run_contracts.py"), "--json"],
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


@pytest.mark.parametrize("name", CONTRACT_FILES)
def test_contract_files_exist(name):
    assert (ROOT / "contracts" / name).is_file()


# ---------------------------------------------------------------------------
# Batch 2（batch2_3）：finding quality 8 状态纳入状态模型漂移校验
# ---------------------------------------------------------------------------

def test_run_contracts_flags_missing_finding_contracts(tmp_path):
    """4 个 run 契约齐全但缺 finding 契约的 tmp 根必须被标记。"""
    root = _copy_contracts(tmp_path)
    violations = collect_violations(root)
    assert any("missing contract file: finding_quality_schema.json" in v for v in violations)


def test_run_contracts_detects_finding_status_drift(tmp_path):
    """finding_quality_schema 状态枚举篡改必须被 run 契约校验入口检出（三方交叉）。"""
    root = _copy_contracts(tmp_path)
    contracts = root / "contracts"
    for name in ("finding_quality_schema.json", "finding_evidence_schema.json"):
        shutil.copy(ROOT / "contracts" / name, contracts / name)
    path = contracts / "finding_quality_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["finding_status_states"] = ["signal", "confirmed"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "finding status states drift between finding_quality_schema and finding quality gate module" in v
        for v in violations
    )


# ---------------------------------------------------------------------------
# Batch 3（batch3_3）：candidate_identity 契约纳入 run 契约校验
# ---------------------------------------------------------------------------

def _copy_all_contracts(tmp_path) -> Path:
    root = _copy_contracts(tmp_path)
    contracts = root / "contracts"
    for name in ("finding_quality_schema.json", "finding_evidence_schema.json"):
        shutil.copy(ROOT / "contracts" / name, contracts / name)
    return root


def test_run_contracts_flags_missing_candidate_identity_schema(tmp_path):
    root = tmp_path
    contracts = root / "contracts"
    contracts.mkdir()
    for name in CONTRACT_FILES[:4]:  # 既有 4 个 run 契约齐全，仅缺 candidate_identity_schema
        shutil.copy(ROOT / "contracts" / name, contracts / name)
    violations = collect_violations(root)
    assert any("missing contract file: candidate_identity_schema.json" in v for v in violations)


def test_run_contracts_detects_candidate_identity_key_drift(tmp_path):
    """key_fields.generic 字段集篡改必须被检出（契约 ↔ canonical_keys 双向无漂移）。"""
    root = _copy_all_contracts(tmp_path)
    path = root / "contracts" / "candidate_identity_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["key_fields"]["generic"] = ["canonical_target", "endpoint"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("candidate_identity_schema.key_fields.generic drift" in v for v in violations)
    assert any("key fields drift between candidate_identity_schema" in v for v in violations)


def test_run_contracts_detects_candidate_identity_merge_keys_missing(tmp_path):
    root = _copy_all_contracts(tmp_path)
    path = root / "contracts" / "candidate_identity_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["merge_keys"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("candidate_identity_schema.merge_keys.fields missing or drifted" in v for v in violations)


def test_run_contracts_detects_candidate_identity_quota_drift(tmp_path):
    root = _copy_all_contracts(tmp_path)
    path = root / "contracts" / "candidate_identity_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["quota_rules"]["max_per_system_and_family"] = 10
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("quota drift" in v and "max_per_system_and_family" in v for v in violations)


def test_run_contracts_detects_candidate_identity_cross_run_drift(tmp_path):
    root = _copy_all_contracts(tmp_path)
    path = root / "contracts" / "candidate_identity_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["cross_run_retention"]["fields"] = ["first_seen", "last_seen"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("candidate_identity_schema.cross_run_retention.fields missing or drifted" in v for v in violations)
    assert any("cross-run retention fields drift" in v for v in violations)


# ---------------------------------------------------------------------------
# Batch 4（batch4_1）：tool_capability 契约纳入（第 6 契约）
# ---------------------------------------------------------------------------

def _copy_tool_inputs(root: Path) -> None:
    """把 registry 校验所需的真实输入拷入 tmp 根（contracts 由 _copy_contracts 负责）。"""
    (root / "tools").mkdir(exist_ok=True)
    shutil.copy(ROOT / "tools" / "tool_registry.json", root / "tools" / "tool_registry.json")
    shutil.copy(ROOT / "gov_exercise_config.json", root / "gov_exercise_config.json")
    shutil.copy(ROOT / "tool_strategy.json", root / "tool_strategy.json")


def test_run_contracts_flags_missing_tool_registry(tmp_path):
    """6 契约齐全但缺 tools/tool_registry.json 的 tmp 根必须被标记。"""
    root = _copy_contracts(tmp_path)
    violations = collect_violations(root)
    assert any("missing registry file" in v for v in violations)


def test_run_contracts_detects_registry_status_drift(tmp_path):
    """registry active 条目路径不可解析（fail-closed 漂移）必须被检出。"""
    root = _copy_contracts(tmp_path)
    _copy_tool_inputs(root)
    registry_path = root / "tools" / "tool_registry.json"
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    data["tools"][0]["path"] = "tools/managed/__no_such_tool__/missing.exe"
    registry_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any("status=active 但路径不可解析" in v for v in violations)
    assert any(data["tools"][0]["tool_id"] in v for v in violations)


def test_run_contracts_detects_unregistered_strategy_reference(tmp_path):
    """tool_strategy 引用 registry 中不存在的逻辑工具名必须被检出（13.2 负例）。"""
    root = _copy_contracts(tmp_path)
    _copy_tool_inputs(root)
    strategy_path = root / "tool_strategy.json"
    strategy = json.loads(strategy_path.read_text(encoding="utf-8"))
    strategy["phases"]["template_validation"]["primary"] = "ghost_scanner"
    strategy_path.write_text(json.dumps(strategy, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any("ghost_scanner" in v and "未登记" in v for v in violations)


def test_run_contracts_detects_tool_contract_field_drift(tmp_path):
    """tool_capability_schema 字段集与 registry 模块常量漂移必须被检出。"""
    root = _copy_contracts(tmp_path)
    _copy_tool_inputs(root)
    contract_path = root / "contracts" / "tool_capability_schema.json"
    data = json.loads(contract_path.read_text(encoding="utf-8"))
    data["status_values"] = ["active", "unavailable", "hold", "retired", "conditional"]
    contract_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any("tool_capability_schema.status_values drift" in v for v in violations)


# ---------------------------------------------------------------------------
# Batch 6（batch6_0）：injection_candidate 契约纳入（第 7 契约）
# ---------------------------------------------------------------------------

def test_run_contracts_flags_missing_injection_candidate_schema(tmp_path):
    """其余 6 契约齐全但缺 injection_candidate_schema.json 的 tmp 根必须被标记。"""
    root = _copy_contracts(tmp_path)
    (root / "contracts" / "injection_candidate_schema.json").unlink()
    violations = collect_violations(root)
    assert any("missing contract file: injection_candidate_schema.json" in v for v in violations)


def test_run_contracts_detects_injection_category_drift(tmp_path):
    """injection_candidate_schema.categories 与实现常量漂移必须被检出。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "injection_candidate_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["categories"] = ["sql", "nosql"]
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any("injection_candidate_schema.categories drift" in v for v in violations)


def test_run_contracts_detects_injection_candidate_status_drift(tmp_path):
    """candidate_status_values 与 finding quality gate 8 状态漂移必须被检出（三方交叉）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "injection_candidate_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["candidate_status_values"] = ["signal", "confirmed"]
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "candidate status states drift between injection_candidate_schema and finding quality gate module" in v
        for v in violations
    )


def test_run_contracts_detects_injection_upgrade_rule_unknown_kind(tmp_path):
    """upgrade_rules 引用未知证据形态 / 不覆盖全部 category 必须被检出（13.2 负例）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "injection_candidate_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["upgrade_rules"]["sql"]["required_any_groups"][0] = ["ghost_kind"]
    del data["upgrade_rules"]["lfi"]
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any("unknown evidence kind: 'ghost_kind'" in v for v in violations)
    assert any("must cover exactly all 15 categories" in v for v in violations)


def test_run_contracts_detects_injection_upgrade_rule_drift_vs_module(tmp_path):
    """upgrade_rules 与模块 _UPGRADE_RULES 语义漂移（放宽 sql 为任一证据即可）必须被检出。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "injection_candidate_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["upgrade_rules"]["sql"] = {"required_any_groups": [["error_based", "differential", "semantic_anomaly"]]}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "injection_candidate_schema.upgrade_rules.sql drift against module rules" in v for v in violations
    )


# ---------------------------------------------------------------------------
# Batch 7（batch7_0）：graphql 契约纳入（第 8 契约）
# ---------------------------------------------------------------------------

def test_run_contracts_flags_missing_graphql_schema(tmp_path):
    """其余 7 契约齐全但缺 graphql_schema.json 的 tmp 根必须被标记。"""
    root = _copy_contracts(tmp_path)
    (root / "contracts" / "graphql_schema.json").unlink()
    violations = collect_violations(root)
    assert any("missing contract file: graphql_schema.json" in v for v in violations)


def test_run_contracts_detects_graphql_category_drift(tmp_path):
    """graphql_schema.review_categories 与实现常量漂移必须被检出。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "graphql_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["review_categories"] = ["introspection_exposure"]
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any("graphql_schema.review_categories drift" in v for v in violations)


def test_run_contracts_detects_graphql_never_upgrade_violation(tmp_path):
    """把永不升级类别（introspection_exposure）加进 upgrade_rules 必须被检出（11.3）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "graphql_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["upgrade_rules"]["introspection_exposure"] = {
        "required_any_groups": [["introspection_enabled"]]
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any("never_upgrade_rule drift" in v for v in violations)
    assert any("upgrade_rules drift" in v for v in violations)


def test_run_contracts_detects_graphql_upgrade_rule_drift_vs_module(tmp_path):
    """upgrade_rules 与模块 GRAPHQL_UPGRADE_RULES 语义漂移必须被检出。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "graphql_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["upgrade_rules"]["object_authorization"] = {
        "required_any_groups": [["cross_user_object_access"], ["unauthenticated_data_access"]]
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "graphql_schema.upgrade_rules.object_authorization drift against module rules" in v
        for v in violations
    )


def test_run_contracts_detects_graphql_observation_version_drift(tmp_path):
    """observation_schema.version 与模块 OBSERVATION_SCHEMA_VERSION 漂移必须被检出。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "graphql_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["observation_schema"]["version"] = "0.9"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any("observation_schema.version drift" in v for v in violations)


def test_run_contracts_detects_graphql_status_drift_vs_finding_gate(tmp_path):
    """candidate_status_values 与 finding quality gate 8 状态漂移必须被检出。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "graphql_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["candidate_status_values"] = ["signal", "confirmed"]
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "candidate status states drift between graphql_schema and finding quality gate module" in v
        for v in violations
    )


# ---------------------------------------------------------------------------
# Batch 8（batch8_10）：api_reconciliation 第 9 契约纳入 run 契约校验
# ---------------------------------------------------------------------------

def test_run_contracts_detects_reconciliation_status_drift(tmp_path):
    """对账六状态篡改必须被检出（操作员决定⑤：枚举入契约）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "api_reconciliation_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["reconciliation_statuses"] = ["doc_only", "traffic_only", "matched"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("api_reconciliation_schema.reconciliation_statuses drift" in v for v in violations)


def test_run_contracts_detects_version_labels_drift(tmp_path):
    """版本登记表篡改必须被检出（操作员决定⑥：版本化实现定义入契约）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "api_reconciliation_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["versioned_definition"]["version_labels"] = ["v1", "v2"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("version_labels drift against module" in v for v in violations)


def test_run_contracts_detects_inventory_csv_fields_drift(tmp_path):
    """盘点 CSV 表头篡改必须被检出（操作员决定⑥：表头入契约）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "api_reconciliation_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["csv_artifacts"]["files"]["api-version-inventory.csv"]["fields"] = ["endpoint_or_surface"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("api-version-inventory.csv.fields drift" in v for v in violations)


def test_run_contracts_detects_missing_api_reconciliation_schema(tmp_path):
    """其余契约齐全但缺 api_reconciliation_schema.json 必须被标记。"""
    root = _copy_contracts(tmp_path)
    (root / "contracts" / "api_reconciliation_schema.json").unlink()
    violations = collect_violations(root)
    assert any(
        "missing contract file: api_reconciliation_schema.json" in v for v in violations
    )


def test_run_contracts_detects_ofa_default_drift(tmp_path):
    """子状态 default 篡改必须被检出（操作员决定②：缺省 inconclusive）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "api_reconciliation_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["object_field_authorization"]["default"] = "candidate"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any("object_field_authorization.default must be inconclusive" in v for v in violations)


# ---------------------------------------------------------------------------
# Batch 10（batch10_4）：miniapp_auth 契约纳入 run 契约校验（第 10 契约）
# ---------------------------------------------------------------------------

def test_run_contracts_detects_missing_miniapp_auth_schema(tmp_path):
    """其余契约齐全但缺 miniapp_auth_schema.json 必须被标记。"""
    root = _copy_contracts(tmp_path)
    (root / "contracts" / "miniapp_auth_schema.json").unlink()
    violations = collect_violations(root)
    assert any("missing contract file: miniapp_auth_schema.json" in v for v in violations)


def test_run_contracts_detects_miniapp_auth_branch_drift(tmp_path):
    """phase 分支篡改必须被检出（契约 ↔ 三模块引擎常量无漂移）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_auth_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["phases"]["platform_login_exchange"]["branches"] = ["login_code_one_time"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "miniapp_auth_schema.phases.platform_login_exchange.branches drift" in v
        for v in violations
    )


def test_run_contracts_detects_miniapp_auth_artifact_path_drift(tmp_path):
    """产物路径篡改必须被检出（规格 1591-1593 行路径锁定）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_auth_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["phases"]["signature_replay"]["artifact"] = "artifacts/miniapp/auth/wrong.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "miniapp_auth_schema.phases.signature_replay.artifact drift" in v for v in violations
    )


def test_run_contracts_detects_miniapp_auth_row_fields_drift(tmp_path):
    """共享形状常量（row_fields）篡改必须被检出。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_auth_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["artifact_fields"]["row_fields"] = ["row_id", "branch"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "miniapp_auth_schema.artifact_fields.row_fields drift" in v for v in violations
    )


# ---------------------------------------------------------------------------
# Batch 11（batch11_4）：miniapp_storage_package 契约纳入 run 契约校验（第 11 契约）
# ---------------------------------------------------------------------------

def test_run_contracts_detects_missing_miniapp_storage_package_schema(tmp_path):
    """其余契约齐全但缺 miniapp_storage_package_schema.json 必须被标记。"""
    root = _copy_contracts(tmp_path)
    (root / "contracts" / "miniapp_storage_package_schema.json").unlink()
    violations = collect_violations(root)
    assert any(
        "missing contract file: miniapp_storage_package_schema.json" in v for v in violations
    )


def test_run_contracts_detects_miniapp_storage_package_branch_drift(tmp_path):
    """phase 分支篡改必须被检出（契约 ↔ 三模块引擎常量无漂移）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_storage_package_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["phases"]["local_data_exposure"]["branches"] = ["token_persistence"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "miniapp_storage_package_schema.phases.local_data_exposure.branches drift" in v
        for v in violations
    )


def test_run_contracts_detects_miniapp_storage_package_artifact_path_drift(tmp_path):
    """产物路径篡改必须被检出（规格 1542/1619/1620 行路径锁定）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_storage_package_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["phases"]["package_integrity_update_review"]["artifact"] = (
        "artifacts/miniapp/package/wrong.json"
    )
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "miniapp_storage_package_schema.phases.package_integrity_update_review.artifact drift"
        in v
        for v in violations
    )


def test_run_contracts_detects_miniapp_storage_package_row_fields_drift(tmp_path):
    """共享形状常量（row_fields）篡改必须被检出。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_storage_package_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["artifact_fields"]["row_fields"] = ["row_id", "branch"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "miniapp_storage_package_schema.artifact_fields.row_fields drift" in v
        for v in violations
    )


# ---------------------------------------------------------------------------
# Construction table 00: orchestration contracts
# ---------------------------------------------------------------------------

ORCHESTRATION_CONTRACT_FILES = (
    "assessment_schema.json", "worker_manifest_schema.json", "task_envelope_schema.json",
    "worker_result_schema.json", "policy_decision_schema.json", "checkpoint_schema.json",
    "event_schema.json", "metric_event_schema.json", "approval_schema.json",
    "graph_schema.json", "worker_error_schema.json",
)


def _copy_orchestration_contracts(tmp_path: Path) -> Path:
    root = _copy_contracts(tmp_path)
    for name in ORCHESTRATION_CONTRACT_FILES:
        shutil.copy(ROOT / "contracts" / name, root / "contracts" / name)
    return root


@pytest.mark.parametrize("name", ORCHESTRATION_CONTRACT_FILES)
def test_orchestration_contracts_are_checked(name, tmp_path):
    root = _copy_orchestration_contracts(tmp_path)
    (root / "contracts" / name).unlink()
    violations = collect_violations(root)
    assert any(f"missing contract file: {name}" in item for item in violations)


def test_orchestration_worker_permission_drift_is_detected(tmp_path):
    root = _copy_orchestration_contracts(tmp_path)
    path = root / "contracts" / "worker_manifest_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["properties"]["permissions"]["properties"]["write_scope"] = {"const": True}
    path.write_text(json.dumps(data), encoding="utf-8")
    violations = collect_violations(root)
    assert any("worker_manifest_schema.permissions.write_scope must be false" in item for item in violations)


def test_orchestration_task_action_drift_is_detected(tmp_path):
    root = _copy_orchestration_contracts(tmp_path)
    path = root / "contracts" / "task_envelope_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["properties"]["action"]["enum"] = ["shell"]
    path.write_text(json.dumps(data), encoding="utf-8")
    violations = collect_violations(root)
    assert any("task_envelope_schema.action enum drift" in item for item in violations)


def test_orchestration_sensitive_property_is_detected(tmp_path):
    root = _copy_orchestration_contracts(tmp_path)
    path = root / "contracts" / "event_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["properties"]["token"] = {"type": "string"}
    path.write_text(json.dumps(data), encoding="utf-8")
    violations = collect_violations(root)
    assert any("event_schema.json forbidden sensitive property names" in item for item in violations)


# ---------------------------------------------------------------------------
# Batch 12（batch12_5）：miniapp_reconciliation + miniapp_cloud 契约纳入 run 契约
# 校验（第 12/13 契约）
# ---------------------------------------------------------------------------

def test_run_contracts_detects_missing_miniapp_reconciliation_schema(tmp_path):
    """其余契约齐全但缺 miniapp_reconciliation_schema.json 必须被标记。"""
    root = _copy_contracts(tmp_path)
    (root / "contracts" / "miniapp_reconciliation_schema.json").unlink()
    violations = collect_violations(root)
    assert any(
        "missing contract file: miniapp_reconciliation_schema.json" in v for v in violations
    )


def test_run_contracts_detects_miniapp_reconciliation_branch_drift(tmp_path):
    """对账 phase 分支篡改必须被检出（契约 ↔ 对账模块常量无漂移）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_reconciliation_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["phases"]["static_dynamic_reconciliation"]["branches"] = ["static_endpoint_base"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "miniapp_reconciliation_schema.phases.static_dynamic_reconciliation.branches drift"
        in v
        for v in violations
    )


def test_run_contracts_detects_miniapp_reconciliation_endpoint_states_drift(tmp_path):
    """十值端点状态篡改必须被检出（规格 1570-1581 行行级枚举锁定）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_reconciliation_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    states = data["phases"]["static_dynamic_reconciliation"]["endpoint_states"]
    states.remove("unreachable")
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "static_dynamic_reconciliation.endpoint_states drift" in v for v in violations
    )


def test_run_contracts_detects_missing_miniapp_cloud_schema(tmp_path):
    """其余契约齐全但缺 miniapp_cloud_schema.json 必须被标记。"""
    root = _copy_contracts(tmp_path)
    (root / "contracts" / "miniapp_cloud_schema.json").unlink()
    violations = collect_violations(root)
    assert any(
        "missing contract file: miniapp_cloud_schema.json" in v for v in violations
    )


def test_run_contracts_detects_miniapp_cloud_branch_drift(tmp_path):
    """云 phase 分支篡改必须被检出（契约 ↔ 三模块引擎常量无漂移）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_cloud_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["phases"]["cloud_storage_acl_testing"]["branches"] = ["object_storage_acl"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "miniapp_cloud_schema.phases.cloud_storage_acl_testing.branches drift" in v
        for v in violations
    )


def test_run_contracts_detects_miniapp_cloud_artifact_format_drift(tmp_path):
    """artifact_format（形状族）篡改必须被检出（review JSON / CSV 形状区分锁定）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_cloud_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["phases"]["third_party_platform_boundary"]["artifact_format"] = "review_json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "third_party_platform_boundary.artifact_format drift" in v for v in violations
    )


def test_run_contracts_detects_miniapp_cloud_attribution_drift(tmp_path):
    """第三方 CSV 归属枚举篡改必须被检出（与 hosts 分类状态同源对齐锁定）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_cloud_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    values = data["phases"]["third_party_platform_boundary"]["attribution_values"]
    values.remove("platform_shared")
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "third_party_platform_boundary.attribution_values drift" in v for v in violations
    )


# ---------------------------------------------------------------------------
# Batch 13（batch13_4）：miniapp_webview 契约纳入 run 契约校验（第 14 契约；
# 实现 = audit skill 脚本常量，importlib 离线加载）
# ---------------------------------------------------------------------------

def test_run_contracts_detects_missing_miniapp_webview_schema(tmp_path):
    """其余契约齐全但缺 miniapp_webview_schema.json 必须被标记。"""
    root = _copy_contracts(tmp_path)
    (root / "contracts" / "miniapp_webview_schema.json").unlink()
    violations = collect_violations(root)
    assert any(
        "missing contract file: miniapp_webview_schema.json" in v for v in violations
    )


def test_run_contracts_detects_miniapp_webview_branch_drift(tmp_path):
    """webview 七分支篡改必须被检出（契约 ↔ audit 脚本常量无漂移）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_webview_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["phases"]["webview_bridge_links"]["branches"] = ["webview_allowed_domains"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "miniapp_webview_schema.phases.webview_bridge_links.branches drift" in v
        for v in violations
    )


def test_run_contracts_detects_miniapp_webview_artifact_paths_drift(tmp_path):
    """三产物路径/顺序篡改必须被检出（规格 1667-1669 行逐字锁定）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_webview_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    artifacts = data["phases"]["webview_bridge_links"]["artifacts"]
    artifacts[0]["artifact"] = "artifacts/miniapp/webview/wrong-name.csv"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "artifacts paths drift" in v for v in violations
    )


def test_run_contracts_detects_miniapp_webview_csv_fields_drift(tmp_path):
    """CSV 列篡改必须被检出（契约 ↔ audit 脚本列常量无漂移）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_webview_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    artifacts = data["phases"]["webview_bridge_links"]["artifacts"]
    artifacts[1]["csv_fields"].remove("capability")
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "bridge-method-inventory.csv].csv_fields drift" in v for v in violations
    )


def test_run_contracts_detects_miniapp_webview_enum_drift(tmp_path):
    """行级枚举篡改必须被检出（cookie_token_shared/capability 等与 audit 常量同源）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_webview_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    artifacts = data["phases"]["webview_bridge_links"]["artifacts"]
    artifacts[0]["row_enums"]["cookie_token_shared"].remove("none")
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "row_enums.cookie_token_shared drift" in v for v in violations
    )


def test_run_contracts_detects_miniapp_webview_branch_grouping_drift(tmp_path):
    """分支→产物分组篡改必须被检出（1:1 映射与 audit WEBVIEW_BRANCH_ARTIFACTS 一致）。"""
    root = _copy_contracts(tmp_path)
    path = root / "contracts" / "miniapp_webview_schema.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    artifacts = data["phases"]["webview_bridge_links"]["artifacts"]
    artifacts[0]["branches"] = ["webview_allowed_domains"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    violations = collect_violations(root)
    assert any(
        "webview-origin-inventory.csv] branches drift against audit WEBVIEW_BRANCH_ARTIFACTS" in v
        for v in violations
    )
    assert any("branch union drift" in v for v in violations)
