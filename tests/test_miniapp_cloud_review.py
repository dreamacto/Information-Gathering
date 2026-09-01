"""tests/test_miniapp_cloud_review.py —— 小程序云函数/对象存储/第三方边界三模块
共享测试文件（实施规格 6.7 1646 行指定文件名；batch12_2/3/4 逐子项追加）。

已覆盖段：
  - cloud_function_testing（batch12_2）：src/authorized_assessment/miniapp/
    cloud_function_review.py（Batch 12 共享引擎宿主）——契约常量无漂移、分支/证据
    形态/升级规则结构、统一筛选模式（形态永不升级/确认升级/status_hint/not_
    applicable 需 reason）、12 键 artifact 形状 build/validate（CSV 形状 phase 混用
    拒绝）、CLI、导入纪律。

后续段（按批次追加）：cloud_storage_acl_testing（batch12_3）、
third_party_platform_boundary（batch12_4）——均已落地。

纯离线，不发任何网络请求、不调用云函数。
"""
from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
CLOUD_CONTRACT_PATH = ROOT / "contracts" / "miniapp_cloud_schema.json"

from authorized_assessment.miniapp import cloud_function_review as cfr
from authorized_assessment.miniapp import cloud_storage_review as csr
from authorized_assessment.miniapp import third_party_boundary_review as tpb
from authorized_assessment.triage import injection_candidates as ic

SPEC_CLOUD_FUNCTION_BRANCHES = (
    "anonymous_invocation",
    "function_parameter_role_validation",
    "cloud_env_id_mixing",
)


@pytest.fixture(scope="module")
def cloud_contract():
    return json.loads(CLOUD_CONTRACT_PATH.read_text(encoding="utf-8-sig"))


def _obs(branch: str, evidence: dict, **extra) -> dict:
    observation = {
        "branch": branch,
        "applicability": "applicable",
        "evidence": evidence,
        "source": "local-traffic-export",
    }
    observation.update(extra)
    return observation


# ===========================================================================
# cloud_function_testing 段（batch12_2）
# ===========================================================================

def test_cloud_function_constants_match_contract(cloud_contract):
    phase_contract = cloud_contract["phases"]["cloud_function_testing"]
    assert cfr.MINIAPP_CLOUD_CONTRACT == cloud_contract["contract"] == "miniapp_cloud_schema"
    assert cfr.MINIAPP_CLOUD_SCHEMA_VERSION == cloud_contract["schema_version"] == "1.0"
    assert cfr.CLOUD_FUNCTION_BRANCHES == tuple(phase_contract["branches"]) == (
        SPEC_CLOUD_FUNCTION_BRANCHES
    )
    assert cfr.CLOUD_REVIEW_ARTIFACTS["cloud_function_testing"] == phase_contract["artifact"]


def test_cloud_phases_and_artifacts_match_contract(cloud_contract):
    assert cfr.CLOUD_PHASES == tuple(cloud_contract["phases"].keys())
    for phase, artifact in cfr.CLOUD_REVIEW_ARTIFACTS.items():
        assert cloud_contract["phases"][phase]["artifact"] == artifact
    assert cfr.CLOUD_REVIEW_JSON_PHASES == tuple(
        cloud_contract["artifact_fields"]["review_json_phases"]
    )


def test_cloud_function_branches_match_skill_scripts():
    import importlib.util

    def _load(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    init_mod = _load(
        "xcx_init_b12_cfr",
        ROOT / ".agents" / "skills" / "xcx" / "scripts" / "init_miniapp_engagement.py",
    )
    audit_mod = _load(
        "xcx_audit_b12_cfr",
        ROOT / ".agents" / "skills" / "xcx" / "scripts" / "audit_miniapp_engagement.py",
    )
    assert init_mod.CLOUD_REVIEW_BRANCHES["cloud_function_testing"] == cfr.CLOUD_FUNCTION_BRANCHES
    assert tuple(audit_mod.CLOUD_REVIEW_BRANCHES["cloud_function_testing"]) == (
        cfr.CLOUD_FUNCTION_BRANCHES
    )


def test_upgrade_rules_structure():
    """升级规则结构锁：每分支有规则；确认形态不出现在永不升级集合；永不升级集合
    ⊆ 全部证据形态；观察映射覆盖全部形态。"""
    confirmed = {k for k in cfr.CLOUD_FUNCTION_EVIDENCE_KINDS if k.endswith("_confirmed")}
    insufficient = set(cfr.CLOUD_FUNCTION_INSUFFICIENT_KINDS)
    assert confirmed and not confirmed & insufficient
    assert insufficient < set(cfr.CLOUD_FUNCTION_EVIDENCE_KINDS)
    for branch in cfr.CLOUD_FUNCTION_BRANCHES:
        rule = cfr.CLOUD_FUNCTION_UPGRADE_RULES[branch]
        groups = rule["required_any_groups"]
        used = {kind for group in groups for kind in group}
        assert used & confirmed, f"branch {branch} rule must use a confirmed kind"
    mapped = set(cfr.CLOUD_FUNCTION_OBSERVATION_EVIDENCE_MAP.values())
    assert mapped == set(cfr.CLOUD_FUNCTION_EVIDENCE_KINDS)


def test_red_line_constant():
    assert "任何写入、批量读取和真实支付必须审批" in cfr.CLOUD_MINIMAL_READ_RULE
    assert "不触发写型云函数" in cfr.CLOUD_MINIMAL_READ_RULE


def test_screen_form_observations_stay_signal():
    """仅形态/支持性观察永不升级（signal 不是漏洞）。"""
    rows, summaries, violations = cfr.screen_cloud_function_observations(
        [
            _obs("anonymous_invocation", {"cloud_function_anonymous_flag_observed": True}),
            _obs(
                "function_parameter_role_validation",
                {
                    "function_param_validation_code_observed": True,
                    "function_role_check_code_observed": True,
                },
            ),
            _obs("cloud_env_id_mixing", {"cloud_env_id_observed": True}),
        ]
    )
    assert violations == []
    assert all(row["status"] == "signal" for row in rows)
    assert len(summaries) == 3
    by_branch = {s["branch"]: s for s in summaries}
    # 聚合语义（batch8 起既定）：无 definitive 结果且无 not_applicable → inconclusive
    assert by_branch["anonymous_invocation"]["branch_status"] == "inconclusive"
    assert by_branch["anonymous_invocation"]["tested_count"] == 0


def test_screen_confirmed_observation_upgrades_to_candidate():
    rows, summaries, violations = cfr.screen_cloud_function_observations(
        [
            _obs(
                "anonymous_invocation",
                {
                    "anonymous_call_clue_observed": True,
                    "anonymous_invocation_processed_confirmed": True,
                },
                evidence_ref="evidence/raw/anonymous-call.json",
                precondition="existing read-only traffic only; no new invocation sent",
            ),
            _obs(
                "cloud_env_id_mixing",
                {"cloud_env_id_shared_clue_observed": True, "cloud_env_id_cross_tenant_confirmed": True},
                evidence_ref="evidence/raw/env-id-config.json",
                precondition="operator-supplied config copy only",
            ),
        ]
    )
    assert violations == []
    assert [row["status"] for row in rows] == ["candidate", "candidate"]
    by_branch = {s["branch"]: s for s in summaries}
    # 聚合语义（batch8 起既定）：candidate ∈ definitive → branch_status=tested
    assert by_branch["anonymous_invocation"]["branch_status"] == "tested"
    assert by_branch["cloud_env_id_mixing"]["status_counts"]["candidate"] == 1
    assert by_branch["cloud_env_id_mixing"]["precondition"] == "operator-supplied config copy only"


def test_screen_status_hint_and_evidence_ref_rules():
    # status_hint 尊重人工判定（8 状态合法值原样返回）
    rows, _, violations = cfr.screen_cloud_function_observations(
        [_obs("anonymous_invocation", {"anonymous_call_clue_observed": True},
              status_hint="needs_manual_validation",
              evidence_ref="evidence/raw/clue.json")]
    )
    assert violations == []
    assert rows[0]["status"] == "needs_manual_validation"
    # candidate/needs_manual_validation 缺 evidence_ref 记违例
    rows, _, violations = cfr.screen_cloud_function_observations(
        [_obs("anonymous_invocation",
              {"anonymous_invocation_processed_confirmed": True},
              evidence_ref="")]
    )
    assert any("evidence_ref 为空" in v for v in violations)


def test_screen_not_applicable_without_reason_is_violation():
    """观察级 not_applicable 无 reason 记违例（batch10 语义沿用，batch11 三域已
    覆盖，batch12 云域沿用）。"""
    rows, summaries, violations = cfr.screen_cloud_function_observations(
        [_obs("cloud_env_id_mixing", {}, applicability="not_applicable", reason="")]
    )
    assert rows == []
    assert any("not_applicable 但 reason 为空" in v for v in violations)


def test_screen_unknown_branch_and_version_mismatch_rejected():
    _, _, violations = cfr.screen_cloud_function_observations(
        [_obs("unknown_branch", {"cloud_env_id_observed": True})]
    )
    assert any("branch 非法" in v for v in violations)
    _, _, violations = cfr.screen_cloud_function_observations(
        [_obs("anonymous_invocation", {"anonymous_call_clue_observed": True},
              observation_schema_version="0.9")]
    )
    assert any("observation_schema_version" in v for v in violations)


def test_build_artifact_shape_and_csv_phase_rejection():
    rows, summaries, violations = cfr.screen_cloud_function_observations(
        [_obs("anonymous_invocation", {"anonymous_call_clue_observed": True})]
    )
    artifact = cfr.build_cloud_function_review_artifact(
        rows, summaries, violations,
        authorization_basis="operator_supplied_material",
        updated_at="2026-08-30T12:00:00+08:00",
    )
    assert set(artifact.keys()) == set(cfr.CLOUD_REVIEW_ARTIFACT_KEYS)
    assert artifact["contract"] == "miniapp_cloud_schema"
    assert artifact["phase"] == "cloud_function_testing"
    assert artifact["observation_schema_version"] == ic.OBSERVATION_SCHEMA_VERSION == "1.0"
    assert artifact["substatuses"] == {s["branch"]: s["branch_status"] for s in summaries}
    # CSV 形状 phase 混用 review JSON 构建被拒绝（契约 artifact_format 区分）
    with pytest.raises(ValueError):
        cfr.build_cloud_review_artifact(
            "third_party_platform_boundary", rows, summaries, violations,
            "operator_supplied_material", "2026-08-30T12:00:00+08:00",
        )


def test_validate_artifact_accepts_valid_and_rejects_tampering():
    rows, summaries, violations = cfr.screen_cloud_function_observations(
        [_obs("anonymous_invocation",
              {"anonymous_invocation_processed_confirmed": True},
              evidence_ref="evidence/raw/anonymous-call.json",
              precondition="existing read-only traffic only")]
    )
    artifact = cfr.build_cloud_function_review_artifact(
        rows, summaries, violations,
        authorization_basis="operator_supplied_material",
        updated_at="2026-08-30T12:00:00+08:00",
    )
    assert cfr.validate_cloud_function_review_artifact(artifact) == []

    tampered = dict(artifact)
    tampered["contract"] = "wrong"
    tampered["phase"] = "cloud_storage_acl_testing"
    tampered["schema_version"] = "9.9"
    tampered["authorization_basis"] = "self_created_credentials"
    tampered["substatuses"] = {"unknown_branch": "complete", "anonymous_invocation": "tested"}
    tampered["rows"] = [
        {"row_id": "r1", "branch": "unknown_branch", "status": "signal",
         "evidence_kinds": ["unknown_kind"], "source": "s", "evidence_ref": "",
         "precondition": "", "reason": ""},
        {"row_id": "r2", "branch": "anonymous_invocation", "status": "candidate",
         "evidence_kinds": [], "source": "s", "evidence_ref": "",
         "precondition": "", "reason": ""},
    ]
    tampered["summaries"] = [
        {"branch": "unknown_branch", "branch_status": "bogus",
         "applicability_counts": {"applicable": 0, "not_applicable": 0, "unknown": 0},
         "status_counts": {}, "tested_count": 0, "reason": "", "source": "",
         "precondition": ""},
    ]
    issues = cfr.validate_cloud_function_review_artifact(tampered)
    text = "\n".join(issues)
    assert "contract 必须为 miniapp_cloud_schema" in text
    assert "phase 必须为 cloud_function_testing" in text
    assert "schema_version 必须为 1.0" in text
    assert "authorization_basis 'self_created_credentials' 非法" in text
    assert "substatuses 未知分支" in text
    assert "substatuses.unknown_branch 非法: 'complete'" in text
    assert "branch 非法" in text
    assert "evidence_kinds 未知形态" in text
    assert "evidence_kinds 不能为空" in text
    assert "evidence_ref 为空" in text
    # category_status 消息经 branch 键适配复用 ic.validate_category_summary
    assert "category_status 非法: 'bogus'" in text
    assert "status_counts 缺少键" in text
    # CSV 形状 phase 传入校验直接返回违例（非异常）
    issues = cfr.validate_cloud_review_artifact(
        artifact, "third_party_platform_boundary",
        cfr.CLOUD_FUNCTION_BRANCHES, cfr.CLOUD_FUNCTION_EVIDENCE_KINDS,
        cfr.CLOUD_FUNCTION_INSUFFICIENT_KINDS, cfr.CLOUD_FUNCTION_UPGRADE_RULES,
    )
    assert issues and "CSV 形状" in issues[0]


def test_cli_writes_contract_shaped_artifact(tmp_path):
    observations = tmp_path / "observations.json"
    observations.write_text(
        json.dumps({"observations": [
            _obs("anonymous_invocation",
                 {"anonymous_call_clue_observed": True,
                  "anonymous_invocation_processed_confirmed": True},
                 evidence_ref="evidence/raw/anonymous-call.json",
                 precondition="existing read-only traffic only; no new invocation sent"),
        ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    out = tmp_path / "cloud" / "cloud-function-review.json"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.cloud_function_review",
         "--observations", str(observations), "--out", str(out),
         "--authorization-basis", "operator_supplied_material"],
        capture_output=True, text=True,
        encoding="utf-8",  # batch14_5: hermetic——子进程 UTF-8 中文输出，GBK locale 父进程解码崩溃(stdout=None)
        timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC), "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode == 0, result.stderr
    artifact = json.loads(out.read_text(encoding="utf-8-sig"))
    assert artifact["phase"] == "cloud_function_testing"
    assert artifact["contract"] == "miniapp_cloud_schema"
    assert artifact["rows"][0]["status"] == "candidate"
    assert cfr.validate_cloud_function_review_artifact(artifact) == []


def test_import_has_no_environment_side_effect():
    """导入纪律：子进程全新导入模块前后 os.environ 不得变化（CLI 兜底仅 __main__）。"""
    code = (
        "import os, sys; "
        "before = dict(os.environ); "
        f"sys.path.insert(0, r'{SRC}'); "
        "import authorized_assessment.miniapp.cloud_function_review; "
        "changed = {k: os.environ[k] for k in os.environ if before.get(k) != os.environ[k]}; "
        "removed = [k for k in before if k not in os.environ]; "
        "assert not changed and not removed, (changed, removed); "
        "print('IMPORT_CLEAN')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert "IMPORT_CLEAN" in result.stdout


# ===========================================================================
# cloud_storage_acl_testing 段（batch12_3）
# ===========================================================================

SPEC_CLOUD_STORAGE_BRANCHES = (
    "cloud_database_rules",
    "object_storage_acl",
    "signed_url_binding",
)


def test_cloud_storage_constants_match_contract(cloud_contract):
    phase_contract = cloud_contract["phases"]["cloud_storage_acl_testing"]
    assert csr.CLOUD_STORAGE_BRANCHES == tuple(phase_contract["branches"]) == (
        SPEC_CLOUD_STORAGE_BRANCHES
    )
    assert cfr.CLOUD_REVIEW_ARTIFACTS["cloud_storage_acl_testing"] == phase_contract["artifact"]


def test_cloud_storage_branches_match_skill_scripts():
    import importlib.util

    def _load(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    init_mod = _load(
        "xcx_init_b12_csr",
        ROOT / ".agents" / "skills" / "xcx" / "scripts" / "init_miniapp_engagement.py",
    )
    audit_mod = _load(
        "xcx_audit_b12_csr",
        ROOT / ".agents" / "skills" / "xcx" / "scripts" / "audit_miniapp_engagement.py",
    )
    assert init_mod.CLOUD_REVIEW_BRANCHES["cloud_storage_acl_testing"] == csr.CLOUD_STORAGE_BRANCHES
    assert tuple(audit_mod.CLOUD_REVIEW_BRANCHES["cloud_storage_acl_testing"]) == (
        csr.CLOUD_STORAGE_BRANCHES
    )


def test_cloud_storage_upgrade_rules_structure():
    confirmed = {k for k in csr.CLOUD_STORAGE_EVIDENCE_KINDS if k.endswith("_confirmed")}
    insufficient = set(csr.CLOUD_STORAGE_INSUFFICIENT_KINDS)
    assert confirmed and not confirmed & insufficient
    assert insufficient < set(csr.CLOUD_STORAGE_EVIDENCE_KINDS)
    for branch in csr.CLOUD_STORAGE_BRANCHES:
        groups = csr.CLOUD_STORAGE_UPGRADE_RULES[branch]["required_any_groups"]
        used = {kind for group in groups for kind in group}
        assert used & confirmed, f"branch {branch} rule must use a confirmed kind"
    assert set(csr.CLOUD_STORAGE_OBSERVATION_EVIDENCE_MAP.values()) == set(
        csr.CLOUD_STORAGE_EVIDENCE_KINDS
    )


def test_cloud_storage_red_line_constant():
    assert "不批量读取对象" in csr.CLOUD_STORAGE_NO_BULK_READ_RULE
    assert "不下载对象内容" in csr.CLOUD_STORAGE_NO_BULK_READ_RULE


def test_cloud_storage_form_observations_stay_inconclusive():
    rows, summaries, violations = csr.screen_cloud_storage_observations(
        [
            _obs("cloud_database_rules", {"db_rule_open_marker_observed": True}),
            _obs("object_storage_acl",
                 {"storage_acl_public_marker_observed": True, "storage_listing_marker_observed": True}),
            _obs("signed_url_binding",
                 {"signed_url_long_expiry_observed": True,
                  "signed_url_no_path_binding_clue_observed": True}),
        ]
    )
    assert violations == []
    assert all(row["status"] == "signal" for row in rows)
    by_branch = {s["branch"]: s for s in summaries}
    assert by_branch["cloud_database_rules"]["branch_status"] == "inconclusive"
    assert by_branch["signed_url_binding"]["tested_count"] == 0


def test_cloud_storage_confirmed_observation_upgrades():
    rows, summaries, violations = csr.screen_cloud_storage_observations(
        [
            _obs("signed_url_binding",
                 {"signed_url_no_path_binding_clue_observed": True,
                  "signed_url_cross_object_confirmed": True},
                 evidence_ref="evidence/raw/signed-url-probe.json",
                 precondition="minimal read verification only; no bulk reads or downloads"),
            _obs("cloud_database_rules",
                 {"db_rule_open_marker_observed": True, "db_rule_unauthorized_access_confirmed": True},
                 evidence_ref="evidence/raw/db-rule.json",
                 precondition="operator-supplied policy copy only"),
        ]
    )
    assert violations == []
    assert [row["status"] for row in rows] == ["candidate", "candidate"]
    by_branch = {s["branch"]: s for s in summaries}
    assert by_branch["signed_url_binding"]["branch_status"] == "tested"
    assert by_branch["signed_url_binding"]["precondition"] == (
        "minimal read verification only; no bulk reads or downloads"
    )


def test_cloud_storage_build_and_validate_round_trip():
    rows, summaries, violations = csr.screen_cloud_storage_observations(
        [_obs("object_storage_acl",
              {"object_acl_unauthorized_access_confirmed": True},
              evidence_ref="evidence/raw/acl-check.json",
              precondition="existing read-only evidence re-review")]
    )
    artifact = csr.build_cloud_storage_review_artifact(
        rows, summaries, violations,
        authorization_basis="local_traffic",
        updated_at="2026-08-30T12:00:00+08:00",
    )
    assert set(artifact.keys()) == set(cfr.CLOUD_REVIEW_ARTIFACT_KEYS)
    assert artifact["contract"] == "miniapp_cloud_schema"
    assert artifact["phase"] == "cloud_storage_acl_testing"
    assert csr.validate_cloud_storage_review_artifact(artifact) == []
    # 宿主通用校验同样接受该 artifact（同一形状，parameterized phase）
    assert cfr.validate_cloud_review_artifact(
        artifact, "cloud_storage_acl_testing",
        csr.CLOUD_STORAGE_BRANCHES, csr.CLOUD_STORAGE_EVIDENCE_KINDS,
        csr.CLOUD_STORAGE_INSUFFICIENT_KINDS, csr.CLOUD_STORAGE_UPGRADE_RULES,
    ) == []


def test_cloud_storage_cli_writes_artifact(tmp_path):
    observations = tmp_path / "observations.json"
    observations.write_text(
        json.dumps({"observations": [
            _obs("signed_url_binding",
                 {"signed_url_long_expiry_observed": True,
                  "signed_url_expiry_not_enforced_confirmed": True},
                 evidence_ref="evidence/raw/expiry-check.json",
                 precondition="minimal read verification only"),
        ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    out = tmp_path / "cloud" / "object-storage-review.json"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.cloud_storage_review",
         "--observations", str(observations), "--out", str(out)],
        capture_output=True, text=True,
        encoding="utf-8",  # batch14_5: hermetic——子进程 UTF-8 中文输出，GBK locale 父进程解码崩溃(stdout=None)
        timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC), "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode == 0, result.stderr
    artifact = json.loads(out.read_text(encoding="utf-8-sig"))
    assert artifact["phase"] == "cloud_storage_acl_testing"
    assert artifact["contract"] == "miniapp_cloud_schema"
    assert artifact["rows"][0]["status"] == "candidate"
    assert csr.validate_cloud_storage_review_artifact(artifact) == []


def test_cloud_storage_import_has_no_environment_side_effect():
    code = (
        "import os, sys; "
        "before = dict(os.environ); "
        f"sys.path.insert(0, r'{SRC}'); "
        "import authorized_assessment.miniapp.cloud_storage_review; "
        "changed = {k: os.environ[k] for k in os.environ if before.get(k) != os.environ[k]}; "
        "removed = [k for k in before if k not in os.environ]; "
        "assert not changed and not removed, (changed, removed); "
        "print('IMPORT_CLEAN')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert "IMPORT_CLEAN" in result.stdout


# ===========================================================================
# third_party_platform_boundary 段（batch12_4）
# ===========================================================================

SPEC_THIRD_PARTY_BRANCHES = (
    "third_party_service_boundary",
    "platform_shared_asset_attribution",
)


def _tp_obs(branch: str, evidence: dict, **extra) -> dict:
    observation = {
        "branch": branch,
        "applicability": "applicable",
        "evidence": evidence,
        "source": "package-config-copy",
        "service_name": "map-sdk",
        "service_type": "map",
        "host": "map.vendor.com",
        "attribution": "third_party",
    }
    observation.update(extra)
    return observation


def test_third_party_constants_match_contract(cloud_contract):
    phase_contract = cloud_contract["phases"]["third_party_platform_boundary"]
    assert tpb.THIRD_PARTY_BRANCHES == tuple(phase_contract["branches"]) == (
        SPEC_THIRD_PARTY_BRANCHES
    )
    assert cfr.CLOUD_REVIEW_ARTIFACTS["third_party_platform_boundary"] == phase_contract["artifact"]
    assert tpb.THIRD_PARTY_CSV_FIELDS == tuple(phase_contract["csv_fields"])
    assert tpb.THIRD_PARTY_SERVICE_TYPES == tuple(phase_contract["service_types"])
    assert tpb.THIRD_PARTY_ATTRIBUTION_VALUES == tuple(phase_contract["attribution_values"])


def test_third_party_attribution_matches_known_host_states():
    """attribution 归属枚举与 audit KNOWN_HOST_STATES 集合相等（单一来源对齐，
    序不敏感）。"""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "xcx_audit_b12_tpb",
        ROOT / ".agents" / "skills" / "xcx" / "scripts" / "audit_miniapp_engagement.py",
    )
    audit_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit_mod)
    assert set(tpb.THIRD_PARTY_ATTRIBUTION_VALUES) == set(audit_mod.KNOWN_HOST_STATES)
    # 模块与 skill init/audit 的 CSV 列/服务类型同源
    import importlib

    init_spec = importlib.util.spec_from_file_location(
        "xcx_init_b12_tpb",
        ROOT / ".agents" / "skills" / "xcx" / "scripts" / "init_miniapp_engagement.py",
    )
    init_mod = importlib.util.module_from_spec(init_spec)
    init_spec.loader.exec_module(init_mod)
    assert init_mod.THIRD_PARTY_CSV_FIELDS == tpb.THIRD_PARTY_CSV_FIELDS
    assert audit_mod.THIRD_PARTY_CSV_FIELDS == tpb.THIRD_PARTY_CSV_FIELDS
    assert init_mod.THIRD_PARTY_SERVICE_TYPES == tpb.THIRD_PARTY_SERVICE_TYPES


def test_third_party_upgrade_rules_structure():
    confirmed = {k for k in tpb.THIRD_PARTY_EVIDENCE_KINDS if k.endswith("_confirmed")}
    insufficient = set(tpb.THIRD_PARTY_INSUFFICIENT_KINDS)
    assert len(confirmed) == 2 and not confirmed & insufficient
    for branch in tpb.THIRD_PARTY_BRANCHES:
        groups = tpb.THIRD_PARTY_UPGRADE_RULES[branch]["required_any_groups"]
        used = {kind for group in groups for kind in group}
        assert used & confirmed, f"branch {branch} rule must use a confirmed kind"
    assert set(tpb.THIRD_PARTY_OBSERVATION_EVIDENCE_MAP.values()) == set(
        tpb.THIRD_PARTY_EVIDENCE_KINDS
    )


def test_third_party_red_line_constants():
    assert "不触发真实支付" in tpb.THIRD_PARTY_NO_PAYMENT_RULE
    assert "不批量读取" in tpb.THIRD_PARTY_NO_PAYMENT_RULE
    assert "不得误报为自有资产" in tpb.THIRD_PARTY_ATTRIBUTION_RULE


def test_third_party_form_observations_stay_signal():
    rows, summaries, violations = tpb.screen_third_party_boundary_observations(
        [
            _tp_obs("third_party_service_boundary", {"third_party_endpoint_observed": True}),
            _tp_obs("third_party_service_boundary",
                    {"business_data_to_third_party_clue_observed": True},
                    service_type="analytics"),
            _tp_obs("platform_shared_asset_attribution",
                    {"platform_asset_marker_observed": True,
                     "asset_attribution_mismatch_clue_observed": True},
                    service_type="sdk", attribution="platform_shared"),
        ]
    )
    assert violations == []
    assert all(row["boundary_status"] == "signal" for row in rows)
    assert len(rows) == 3
    assert rows[0]["row_id"] == "tp-0001" and rows[2]["row_id"] == "tp-0003"
    by_branch = {s["branch"]: s for s in summaries}
    assert by_branch["third_party_service_boundary"]["branch_status"] == "inconclusive"
    assert by_branch["platform_shared_asset_attribution"]["tested_count"] == 0


def test_third_party_confirmed_observation_upgrades():
    rows, summaries, violations = tpb.screen_third_party_boundary_observations(
        [
            _tp_obs("third_party_service_boundary",
                    {"business_data_to_third_party_clue_observed": True,
                     "third_party_unauthorized_data_flow_confirmed": True},
                    service_type="payment",
                    evidence_ref="evidence/raw/payment-flow.json",
                    precondition="observation only; no real payment triggered"),
            _tp_obs("platform_shared_asset_attribution",
                    {"platform_shared_asset_misattributed_confirmed": True},
                    service_type="sdk", attribution="platform_shared",
                    evidence_ref="evidence/raw/asset-attribution.json",
                    precondition="existing read-only evidence re-review"),
        ]
    )
    assert violations == []
    assert [row["boundary_status"] for row in rows] == ["candidate", "candidate"]
    by_branch = {s["branch"]: s for s in summaries}
    assert by_branch["third_party_service_boundary"]["branch_status"] == "tested"
    assert by_branch["platform_shared_asset_attribution"]["status_counts"]["candidate"] == 1
    assert by_branch["third_party_service_boundary"]["precondition"] == (
        "observation only; no real payment triggered"
    )


def test_third_party_not_applicable_without_reason_is_violation():
    rows, summaries, violations = tpb.screen_third_party_boundary_observations(
        [_tp_obs("third_party_service_boundary", {},
                 applicability="not_applicable", reason="")]
    )
    assert rows == []
    assert any("not_applicable 但 reason 为空" in v for v in violations)


def test_third_party_row_validation_rejects_invalid():
    rows = [
        {"row_id": "tp-0001", "service_type": "video", "attribution": "mine",
         "boundary_status": "vulnerable", "reason": ""},
        {"row_id": "tp-0002", "service_type": "map",
         "attribution": "confirmation_required", "boundary_status": "", "reason": ""},
        {"row_id": "tp-0003", "service_type": "push", "attribution": "third_party",
         "boundary_status": "candidate", "reason": "", "evidence_ref": ""},
        "not-a-mapping",
    ]
    violations = tpb.validate_third_party_boundary_rows(rows)
    text = "\n".join(violations)
    assert "row 1: service_type 非法 'video'" in text
    assert "row 1: attribution 非法 'mine'" in text
    assert "row 1: boundary_status 非法 'vulnerable'" in text
    assert "row 2: attribution 'confirmation_required' 需要非空 reason" in text
    assert "row 3: boundary_status=candidate 但 evidence_ref 为空" in text
    assert "row 4" in text and "键值映射" in text


def test_third_party_render_csv_header_exact_and_round_trip():
    rows, _summaries, violations = tpb.screen_third_party_boundary_observations(
        [_tp_obs("third_party_service_boundary", {"third_party_endpoint_observed": True})]
    )
    assert violations == []
    text = tpb.render_third_party_boundary_csv(rows)
    reader = csv.reader(io.StringIO(text))
    header = next(reader)
    assert header == list(tpb.THIRD_PARTY_CSV_FIELDS)
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert len(parsed) == 1
    assert set(parsed[0].keys()) == set(tpb.THIRD_PARTY_CSV_FIELDS)
    assert "precondition" not in parsed[0]  # 非契约列不得写入 CSV
    assert tpb.validate_third_party_boundary_rows(parsed) == []


def test_third_party_cli_writes_csv(tmp_path):
    observations = tmp_path / "observations.json"
    observations.write_text(
        json.dumps({"observations": [
            _tp_obs("third_party_service_boundary",
                    {"third_party_unauthorized_data_flow_confirmed": True},
                    service_type="payment",
                    evidence_ref="evidence/raw/payment-flow.json",
                    precondition="observation only; no real payment triggered"),
        ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    out = tmp_path / "cloud" / "third-party-boundary.csv"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.third_party_boundary_review",
         "--observations", str(observations), "--out", str(out)],
        capture_output=True, text=True,
        encoding="utf-8",  # batch14_5: hermetic——子进程 UTF-8 中文输出，GBK locale 父进程解码崩溃(stdout=None)
        timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC), "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode == 0, result.stderr
    text = out.read_text(encoding="utf-8-sig")
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert len(parsed) == 1
    assert parsed[0]["boundary_status"] == "candidate"
    assert parsed[0]["service_type"] == "payment"
    assert tpb.validate_third_party_boundary_rows(parsed) == []


def test_third_party_cli_fail_closed_on_violations(tmp_path):
    observations = tmp_path / "bad.json"
    observations.write_text(
        json.dumps({"observations": [
            {"branch": "third_party_service_boundary", "service_type": "video",
             "attribution": "mine", "source": "s", "evidence": {}},
        ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    out = tmp_path / "out" / "third-party-boundary.csv"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.third_party_boundary_review",
         "--observations", str(observations), "--out", str(out)],
        capture_output=True, text=True,
        encoding="utf-8",  # batch14_5: hermetic——子进程 UTF-8 中文输出，GBK locale 父进程解码崩溃(stdout=None)
        timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC), "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    assert result.returncode == 2
    assert "VIOLATION" in result.stdout
    assert "nothing written" in result.stdout
    assert not out.exists()


def test_third_party_import_has_no_environment_side_effect():
    code = (
        "import os, sys; "
        "before = dict(os.environ); "
        f"sys.path.insert(0, r'{SRC}'); "
        "import authorized_assessment.miniapp.third_party_boundary_review; "
        "changed = {k: os.environ[k] for k in os.environ if before.get(k) != os.environ[k]}; "
        "removed = [k for k in before if k not in os.environ]; "
        "assert not changed and not removed, (changed, removed); "
        "print('IMPORT_CLEAN')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert "IMPORT_CLEAN" in result.stdout
