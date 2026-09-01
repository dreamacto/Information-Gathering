"""tests/test_package_integrity_update.py —— 小程序包完整性和更新信任复核域测试
（规格 6.3 1543 行指定文件名，Batch 11 batch11_1；batch11_2/3 共享断言面追加时按
batch10 共享文件先例整文件重跑）。

统一断言面（test_miniapp_auth_lifecycle.py 同构）：观察键→证据形态确定性映射、
形态/支持性永不升级、confirmed 分支一一对应不跨分支升级、status_hint 尊重人工
判定、8 状态/行校验负例、not_applicable 需 reason、版本不符/缺来源违例、三统计
概念分离与 branch_status 六值聚合、artifact 形状与 miniapp_storage_package_schema
契约键逐一相同、模块常量与契约零漂移、共享引擎中性别名单一实现、红线常量
（不做重打包/篡改/绕过 pinning/设备攻击）、无网络/并发/子进程 AST 结构锁、
导入期无环境副作用、CLI 产物契约形状。

纯离线：不发任何请求、不重打包/篡改包、不绕过 pinning、不攻击设备。
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from authorized_assessment.miniapp import package_integrity_update as piu  # noqa: E402
from authorized_assessment.miniapp import platform_login_exchange as ple  # noqa: E402
from authorized_assessment.triage import injection_candidates as ic  # noqa: E402

CONTRACT = json.loads(
    (ROOT / "contracts" / "miniapp_storage_package_schema.json").read_text(encoding="utf-8-sig")
)


def _obs(branch: str, evidence: dict, **extra) -> dict:
    payload = {
        "branch": branch,
        "applicability": "applicable",
        "evidence": evidence,
        "source": "material:pkg-copy/appid-main",
        "evidence_ref": "artifacts/package-inventory.csv:L12",
        "precondition": "operator-supplied package copy only; no repacking/tampering/pinning bypass",
        "reason": "observed in operator-supplied package copy",
    }
    payload.update(extra)
    return payload


CONFIRMED_MAP = {
    "package_version_inventory": "subpackage_version_divergence_confirmed",
    "manifest_resource_diff": "manifest_resource_divergence_confirmed",
    "update_endpoint_environment": "controllable_update_address_confirmed",
    "debug_switches": "debug_switch_active_confirmed",
    "source_map_exposure": "source_map_recovered_confirmed",
    "version_drift": "stale_version_active_confirmed",
    "trusted_update_config": "client_trusts_remote_update_confirmed",
}

FORM_EVIDENCE = {
    "package_version_labels_observed": True,
    "subpackage_version_mismatch_observed": True,
    "manifest_diff_clue_observed": True,
    "resource_diff_clue_observed": True,
    "update_address_observed": True,
    "environment_switch_marker_observed": True,
    "debug_flag_marker_observed": True,
    "debug_toggle_code_observed": True,
    "source_map_file_present_observed": True,
    "source_map_reference_observed": True,
    "stale_version_marker_observed": True,
    "version_drift_clue_observed": True,
    "remote_config_trust_clue_observed": True,
    "update_config_reference_observed": True,
}


def test_derive_evidence_kinds_maps_observation_keys():
    kinds = piu.derive_evidence_kinds(
        {"update_address_observed": True, "debug_flag_marker_observed": True, "unknown_key": True},
        piu.PACKAGE_INTEGRITY_OBSERVATION_EVIDENCE_MAP,
    )
    assert kinds == ["update_address_observed", "debug_flag_marker_observed"]
    assert piu.derive_evidence_kinds({}, piu.PACKAGE_INTEGRITY_OBSERVATION_EVIDENCE_MAP) == []


def test_observation_map_covers_evidence_enum():
    assert set(piu.PACKAGE_INTEGRITY_OBSERVATION_EVIDENCE_MAP.values()) == set(
        piu.PACKAGE_INTEGRITY_EVIDENCE_KINDS
    )


def test_form_observations_never_upgrade():
    for branch in piu.PACKAGE_INTEGRITY_BRANCHES:
        status = piu.grade_observation(
            branch,
            list(FORM_EVIDENCE),
            piu.PACKAGE_INTEGRITY_UPGRADE_RULES,
            piu.PACKAGE_INTEGRITY_EVIDENCE_KINDS,
            piu.PACKAGE_INTEGRITY_INSUFFICIENT_KINDS,
        )
        assert status == "signal", branch


def test_confirmed_kinds_upgrade_matching_branch_only():
    for branch, confirmed in CONFIRMED_MAP.items():
        status = piu.grade_observation(
            branch,
            [confirmed],
            piu.PACKAGE_INTEGRITY_UPGRADE_RULES,
            piu.PACKAGE_INTEGRITY_EVIDENCE_KINDS,
            piu.PACKAGE_INTEGRITY_INSUFFICIENT_KINDS,
        )
        assert status == "candidate", branch
    # 跨分支确认形态不升级：confirmed 形态属于另一分支
    cross = piu.grade_observation(
        "version_drift",
        ["client_trusts_remote_update_confirmed"],
        piu.PACKAGE_INTEGRITY_UPGRADE_RULES,
        piu.PACKAGE_INTEGRITY_EVIDENCE_KINDS,
        piu.PACKAGE_INTEGRITY_INSUFFICIENT_KINDS,
    )
    assert cross == "signal"


def test_status_hint_respected():
    assert piu.grade_observation(
        "debug_switches",
        [],
        piu.PACKAGE_INTEGRITY_UPGRADE_RULES,
        piu.PACKAGE_INTEGRITY_EVIDENCE_KINDS,
        piu.PACKAGE_INTEGRITY_INSUFFICIENT_KINDS,
        "needs_manual_validation",
    ) == "needs_manual_validation"
    # 非法 hint 不透传：回退到引擎判定
    assert piu.grade_observation(
        "debug_switches",
        [],
        piu.PACKAGE_INTEGRITY_UPGRADE_RULES,
        piu.PACKAGE_INTEGRITY_EVIDENCE_KINDS,
        piu.PACKAGE_INTEGRITY_INSUFFICIENT_KINDS,
        "unproven",
    ) != "unproven"


def test_candidate_row_validation_negatives():
    good = {
        "row_id": "row-0001",
        "branch": "source_map_exposure",
        "status": "candidate",
        "evidence_kinds": ["source_map_file_present_observed", "source_map_recovered_confirmed"],
        "source": "material:pkg-copy/appid-main",
        "evidence_ref": "artifacts/source-map.csv:L3",
        "precondition": "offline recovery from operator-supplied package copy",
        "reason": "source map recovered offline from package copy",
    }
    assert piu.validate_package_integrity_candidate(good) == []
    missing = {k: v for k, v in good.items() if k != "evidence_ref"}
    assert any("缺少必需字段" in v for v in piu.validate_package_integrity_candidate(missing))
    bad_status = {**good, "status": "unproven"}
    assert any("status 非法" in v for v in piu.validate_package_integrity_candidate(bad_status))
    bad_branch = {**good, "branch": "token_persistence"}
    assert any("branch 非法" in v for v in piu.validate_package_integrity_candidate(bad_branch))
    unknown_kind = {**good, "evidence_kinds": ["secret_validity_confirmed"]}
    assert any("未知形态" in v for v in piu.validate_package_integrity_candidate(unknown_kind))
    unmet = {**good, "evidence_kinds": ["source_map_file_present_observed"]}
    assert any("升级证据不满足" in v for v in piu.validate_package_integrity_candidate(unmet))
    no_evidence_ref = {**good, "evidence_ref": ""}
    assert any("evidence_ref 为空" in v for v in piu.validate_package_integrity_candidate(no_evidence_ref))


def test_screening_source_version_branch_violations():
    rows, summaries, violations = piu.screen_package_integrity_observations(
        [
            {"branch": "debug_switches", "applicability": "applicable", "evidence": {}},
            _obs("source_map_exposure", {"update_address_observed": True},
                 observation_schema_version="0.9"),
            _obs("unknown_branch", {}),
            _obs("source_map_exposure", {}, applicability="perhaps"),
        ]
    )
    # 缺来源与空证据的观察仍产出 signal 行（形态记录，不升级），非法分支/适用性被跳过
    assert [(r["branch"], r["status"]) for r in rows] == [
        ("debug_switches", "signal"),
        ("source_map_exposure", "signal"),
    ]
    text = "\n".join(violations)
    assert "缺少来源 source" in text
    assert "observation_schema_version='0.9'" in text
    assert "branch 非法 'unknown_branch'" in text
    assert "applicability 非法 'perhaps'" in text
    assert "evidence_kinds 不能为空" in text
    assert len(summaries) == len(piu.PACKAGE_INTEGRITY_BRANCHES)


def test_screening_rows_summaries_and_stats_separation():
    rows, summaries, violations = piu.screen_package_integrity_observations(
        [
            _obs("trusted_update_config",
                 {"remote_config_trust_clue_observed": True,
                  "client_trusts_remote_update_confirmed": True}),
            _obs("trusted_update_config", {"update_config_reference_observed": True}),
            _obs("version_drift", {},
                 applicability="not_applicable", reason="single version material only"),
        ]
    )
    assert violations == []
    assert [(r["row_id"], r["branch"], r["status"]) for r in rows] == [
        ("package_integrity_update_review-0001", "trusted_update_config", "candidate"),
        ("package_integrity_update_review-0002", "trusted_update_config", "signal"),
    ]
    by_branch = {s["branch"]: s for s in summaries}
    tc = by_branch["trusted_update_config"]
    assert set(tc) == set(piu.REVIEW_SUMMARY_FIELDS)
    assert tc["branch_status"] == "tested"
    assert tc["status_counts"]["candidate"] == 1
    assert tc["status_counts"]["signal"] == 1
    assert tc["tested_count"] == 1
    assert tc["applicability_counts"] == {"applicable": 2, "not_applicable": 0, "unknown": 0}
    assert by_branch["version_drift"]["branch_status"] == "not_applicable"
    assert by_branch["version_drift"]["status_counts"] == {
        s: 0 for s in ic.CANDIDATE_STATUS_VALUES
    }
    assert by_branch["version_drift"]["reason"] == "single version material only"
    # 三统计概念分离：status_counts 键集 = 8 状态；applicability_counts 键集 = 三值
    assert set(tc["status_counts"]) == set(ic.CANDIDATE_STATUS_VALUES)
    assert set(tc["applicability_counts"]) == set(ic.APPLICABILITY_COUNT_KEYS)


def test_not_applicable_without_reason_violation():
    rows, summaries, violations = piu.screen_package_integrity_observations(
        [_obs("debug_switches", {}, applicability="not_applicable", reason="")]
    )
    assert rows == []
    assert any("not_applicable" in v and "reason" in v for v in violations)


def test_summary_candidate_requires_source_and_precondition():
    rows, summaries, violations = piu.screen_package_integrity_observations(
        [
            {
                "branch": "source_map_exposure",
                "applicability": "applicable",
                "evidence": {"source_map_recovered_confirmed": True},
                "source": "",
            }
        ]
    )
    text = "\n".join(violations)
    assert any("source 为空" in v for v in violations)
    assert any("precondition 为空" in v for v in violations)
    assert rows[0]["status"] == "candidate"


def test_module_constants_match_contract():
    spec = CONTRACT["phases"]["package_integrity_update_review"]
    assert piu.PACKAGE_INTEGRITY_BRANCHES == tuple(spec["branches"])
    assert piu.STORAGE_PACKAGE_PHASES == tuple(CONTRACT["phases"].keys())
    assert piu.STORAGE_PACKAGE_REVIEW_ARTIFACTS == {
        phase: phase_spec["artifact"] for phase, phase_spec in CONTRACT["phases"].items()
    }
    assert piu.REVIEW_ROW_FIELDS == tuple(CONTRACT["artifact_fields"]["row_fields"])
    assert piu.REVIEW_SUMMARY_FIELDS == tuple(CONTRACT["artifact_fields"]["summary_fields"])
    assert piu.REVIEW_ARTIFACT_KEYS == tuple(CONTRACT["artifact_fields"]["artifact_keys"])
    assert piu.AUTHORIZATION_BASIS_VALUES == tuple(CONTRACT["authorization_basis_values"])
    assert piu.MINIAPP_STORAGE_PACKAGE_SCHEMA_VERSION == CONTRACT["schema_version"]
    assert piu.MINIAPP_STORAGE_PACKAGE_CONTRACT == CONTRACT["contract"]


def test_shared_engine_is_single_implementation():
    """共享引擎：通用实现单一来源 = batch10 auth 引擎；batch11 仅中性别名不复制。"""
    assert piu.screen_observations is ple.screen_auth_observations
    assert piu.grade_observation is ple.grade_auth_observation
    assert piu.validate_review_row is ple.validate_auth_review_row
    assert piu.validate_branch_summary is ple.validate_auth_branch_summary
    assert piu.derive_evidence_kinds is ple.derive_auth_evidence_kinds
    assert piu.derive_substatuses is ple.derive_substatuses
    assert piu.AUTHORIZATION_BASIS_VALUES == ple.AUTHORIZATION_BASIS_VALUES


def test_build_artifact_shape_matches_contract():
    rows, summaries, violations = piu.screen_package_integrity_observations(
        [
            _obs("update_endpoint_environment",
                 {"update_address_observed": True, "controllable_update_address_confirmed": True}),
        ]
    )
    artifact = piu.build_package_integrity_review_artifact(
        rows, summaries, violations, "operator_supplied_material", "2026-08-30T12:00:00+08:00"
    )
    assert tuple(sorted(artifact.keys())) == tuple(sorted(piu.REVIEW_ARTIFACT_KEYS))
    assert artifact["contract"] == "miniapp_storage_package_schema"
    assert artifact["phase"] == "package_integrity_update_review"
    assert artifact["observation_schema_version"] == "1.0"
    assert artifact["substatuses"]["update_endpoint_environment"] == "tested"
    assert artifact["authorization_basis"] == "operator_supplied_material"
    assert piu.validate_package_integrity_review_artifact(artifact) == []


def test_artifact_validation_negatives():
    rows, summaries, violations = piu.screen_package_integrity_observations([])
    artifact = piu.build_package_integrity_review_artifact(
        rows, summaries, violations, "operator_supplied_material", "2026-08-30T12:00:00+08:00"
    )
    bad_contract = {**artifact, "contract": "wrong"}
    assert any("contract" in v for v in piu.validate_package_integrity_review_artifact(bad_contract))
    bad_phase = {**artifact, "phase": "local_data_exposure"}
    assert any("phase" in v for v in piu.validate_package_integrity_review_artifact(bad_phase))
    bad_basis = {**artifact, "authorization_basis": "self_registered_account"}
    assert any("authorization_basis" in v for v in piu.validate_package_integrity_review_artifact(bad_basis))
    bad_substatuses = {**artifact, "substatuses": {"unknown_branch": "tested"}}
    text = "\n".join(piu.validate_package_integrity_review_artifact(bad_substatuses))
    assert "未知分支" in text
    missing = {k: v for k, v in artifact.items() if k != "rows"}
    assert any("缺少必需键 rows" in v for v in piu.validate_package_integrity_review_artifact(missing))


def test_redline_constants():
    assert "不做重打包" in piu.PACKAGE_NO_REPACKING_RULE
    assert "篡改" in piu.PACKAGE_NO_REPACKING_RULE
    assert "绕过 pinning" in piu.PACKAGE_NO_REPACKING_RULE
    assert "设备攻击" in piu.PACKAGE_NO_REPACKING_RULE
    # 红线在契约 red_lines 中留痕
    assert any("不做重打包" in line for line in CONTRACT["red_lines"])


def test_module_has_no_network_or_concurrency_imports():
    """AST 结构负例：模块不得导入网络/并发/子进程库（离线红线，batch8_6 模式）。"""
    source = Path(piu.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    banned_roots = {
        "requests", "urllib", "urllib3", "http", "httpx", "aiohttp", "socket", "ssl",
        "asyncio", "threading", "concurrent", "multiprocessing", "subprocess",
        "telnetlib", "ftplib",
    }
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    violations = [name for name in imported if name.split(".")[0] in banned_roots]
    assert violations == []


def test_import_has_no_environment_side_effect():
    """导入纪律：子进程全新导入模块前后 os.environ 不得变化（CLI 兜底仅 __main__）。"""
    code = (
        "import os, sys; "
        "before = dict(os.environ); "
        f"sys.path.insert(0, r'{SRC}'); "
        "import authorized_assessment.miniapp.package_integrity_update; "
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


def test_cli_writes_contract_shaped_artifact(tmp_path):
    """__main__ guard CLI：观察文件 → artifact JSON（纯文件到文件离线）。"""
    observations = tmp_path / "observations.json"
    observations.write_text(
        json.dumps({"observations": [
            _obs("manifest_resource_diff",
                 {"manifest_diff_clue_observed": True,
                  "manifest_resource_divergence_confirmed": True}),
        ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    out = tmp_path / "package" / "package-integrity-review.json"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.package_integrity_update",
         "--observations", str(observations), "--out", str(out),
         "--authorization-basis", "operator_supplied_material"],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )
    assert result.returncode == 0, result.stderr
    artifact = json.loads(out.read_text(encoding="utf-8-sig"))
    assert artifact["phase"] == "package_integrity_update_review"
    assert artifact["authorization_basis"] == "operator_supplied_material"
    assert artifact["rows"][0]["status"] == "candidate"
    assert artifact["substatuses"]["manifest_resource_diff"] == "tested"
