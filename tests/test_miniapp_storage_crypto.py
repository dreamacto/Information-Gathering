"""tests/test_miniapp_storage_crypto.py —— 小程序本地存储与密码学复核域测试
（规格 6.6 1621 行指定测试文件，Batch 11；两模块共享本文件，逐子项追加后整文件
实跑——batch10 共享文件先例）：
  - local_data_exposure（batch11_2）：本地数据暴露五分支；
  - crypto_and_secret_handling（batch11_3）：密码学与密钥处理四分支。

统一断言面（test_miniapp_auth_lifecycle.py 同构）：观察键→证据形态确定性映射、
形态/支持性永不升级、confirmed 分支一一对应不跨分支升级、status_hint 尊重人工
判定、8 状态/行校验负例、not_applicable 需 reason、版本不符/缺来源违例、三统计
概念分离与 branch_status 六值聚合、artifact 形状与 miniapp_storage_package_schema
契约键逐一相同、模块常量与契约零漂移、fan-in 引擎单一实现、红线常量、无网络/
并发/子进程 AST 结构锁、导入期无环境副作用、CLI 产物契约形状。

纯离线：不发任何请求、不读取凭证文件、不导出敏感数据原文。
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

from authorized_assessment.miniapp import crypto_secret_review as csr  # noqa: E402
from authorized_assessment.miniapp import local_data_exposure as lde  # noqa: E402
from authorized_assessment.miniapp import package_integrity_update as piu  # noqa: E402
from authorized_assessment.triage import injection_candidates as ic  # noqa: E402

CONTRACT = json.loads(
    (ROOT / "contracts" / "miniapp_storage_package_schema.json").read_text(encoding="utf-8-sig")
)


def _obs(branch: str, evidence: dict, **extra) -> dict:
    payload = {
        "branch": branch,
        "applicability": "applicable",
        "evidence": evidence,
        "source": "local_traffic:session-export",
        "evidence_ref": "evidence/storage/session-export.json:L18",
        "precondition": "operator-supplied authorization material or package copy only; "
        "no credential files, no sensitive value export",
        "reason": "observed in operator-supplied material",
    }
    payload.update(extra)
    return payload


# ---------------------------------------------------------------------------
# batch11_2：local_data_exposure
# ---------------------------------------------------------------------------

LOCAL_DATA_CONFIRMED_MAP = {
    "token_persistence": "token_survives_logout_confirmed",
    "logout_cleanup": "token_survives_logout_confirmed",
    "local_cache_database": "database_sensitive_rows_confirmed",
    "logs_clipboard_screenshots": "log_or_clipboard_leak_confirmed",
    "temp_files": "temp_file_sensitive_content_confirmed",
}

LOCAL_DATA_FORM_EVIDENCE = {
    "token_storage_key_observed": True,
    "token_value_persisted_observed": True,
    "logout_cleanup_code_observed": True,
    "residual_data_after_logout_observed": True,
    "cache_directory_clue_observed": True,
    "local_database_record_clue_observed": True,
    "log_sensitive_field_observed": True,
    "clipboard_write_marker_observed": True,
    "screenshot_capture_marker_observed": True,
    "temp_file_retention_clue_observed": True,
}


def test_local_data_constants_match_contract():
    spec = CONTRACT["phases"]["local_data_exposure"]
    assert lde.LOCAL_DATA_BRANCHES == tuple(spec["branches"])
    # fan-in 引擎（单一实现，不复制）；CLI choices 经引擎继承授权材料枚举
    assert lde.sp_engine is piu
    assert lde.sp_engine.AUTHORIZATION_BASIS_VALUES == piu.AUTHORIZATION_BASIS_VALUES


def test_local_data_observation_map_covers_evidence_enum():
    assert set(lde.LOCAL_DATA_OBSERVATION_EVIDENCE_MAP.values()) == set(
        lde.LOCAL_DATA_EVIDENCE_KINDS
    )


def test_local_data_form_observations_never_upgrade():
    for branch in lde.LOCAL_DATA_BRANCHES:
        status = lde.sp_engine.grade_observation(
            branch,
            list(LOCAL_DATA_FORM_EVIDENCE),
            lde.LOCAL_DATA_UPGRADE_RULES,
            lde.LOCAL_DATA_EVIDENCE_KINDS,
            lde.LOCAL_DATA_INSUFFICIENT_KINDS,
        )
        assert status == "signal", branch


def test_local_data_confirmed_kinds_upgrade_matching_branch_only():
    for branch, confirmed in LOCAL_DATA_CONFIRMED_MAP.items():
        status = lde.sp_engine.grade_observation(
            branch,
            [confirmed],
            lde.LOCAL_DATA_UPGRADE_RULES,
            lde.LOCAL_DATA_EVIDENCE_KINDS,
            lde.LOCAL_DATA_INSUFFICIENT_KINDS,
        )
        assert status == "candidate", branch
    # 跨分支确认形态不升级：confirmed 形态属于另一分支
    cross = lde.sp_engine.grade_observation(
        "temp_files",
        ["database_sensitive_rows_confirmed"],
        lde.LOCAL_DATA_UPGRADE_RULES,
        lde.LOCAL_DATA_EVIDENCE_KINDS,
        lde.LOCAL_DATA_INSUFFICIENT_KINDS,
    )
    assert cross == "signal"


def test_local_data_status_hint_respected():
    assert lde.sp_engine.grade_observation(
        "logout_cleanup",
        [],
        lde.LOCAL_DATA_UPGRADE_RULES,
        lde.LOCAL_DATA_EVIDENCE_KINDS,
        lde.LOCAL_DATA_INSUFFICIENT_KINDS,
        "needs_manual_validation",
    ) == "needs_manual_validation"
    assert lde.sp_engine.grade_observation(
        "logout_cleanup",
        [],
        lde.LOCAL_DATA_UPGRADE_RULES,
        lde.LOCAL_DATA_EVIDENCE_KINDS,
        lde.LOCAL_DATA_INSUFFICIENT_KINDS,
        "unproven",
    ) != "unproven"


def test_local_data_candidate_row_validation_negatives():
    good = {
        "row_id": "row-0001",
        "branch": "token_persistence",
        "status": "candidate",
        "evidence_kinds": ["token_value_persisted_observed", "token_survives_logout_confirmed"],
        "source": "local_traffic:session-export",
        "evidence_ref": "evidence/storage/session-export.json:L30",
        "precondition": "offline review only; no credential value copied",
        "reason": "token persists after logout in session export",
    }
    assert lde.validate_local_data_candidate(good) == []
    missing = {k: v for k, v in good.items() if k != "evidence_ref"}
    assert any("缺少必需字段" in v for v in lde.validate_local_data_candidate(missing))
    bad_status = {**good, "status": "unproven"}
    assert any("status 非法" in v for v in lde.validate_local_data_candidate(bad_status))
    bad_branch = {**good, "branch": "hardcoded_secrets"}
    assert any("branch 非法" in v for v in lde.validate_local_data_candidate(bad_branch))
    unknown_kind = {**good, "evidence_kinds": ["secret_validity_confirmed"]}
    assert any("未知形态" in v for v in lde.validate_local_data_candidate(unknown_kind))
    unmet = {**good, "evidence_kinds": ["token_value_persisted_observed"]}
    assert any("升级证据不满足" in v for v in lde.validate_local_data_candidate(unmet))
    no_evidence_ref = {**good, "evidence_ref": ""}
    assert any("evidence_ref 为空" in v for v in lde.validate_local_data_candidate(no_evidence_ref))


def test_local_data_screening_rows_summaries_and_stats_separation():
    rows, summaries, violations = lde.screen_local_data_observations(
        [
            _obs("logout_cleanup",
                 {"residual_data_after_logout_observed": True,
                  "token_survives_logout_confirmed": True}),
            _obs("temp_files", {"temp_file_retention_clue_observed": True}),
            _obs("local_cache_database", {},
                 applicability="not_applicable", reason="no cache material in scope"),
        ]
    )
    assert violations == []
    assert [(r["row_id"], r["branch"], r["status"]) for r in rows] == [
        ("local_data_exposure-0001", "logout_cleanup", "candidate"),
        ("local_data_exposure-0002", "temp_files", "signal"),
    ]
    by_branch = {s["branch"]: s for s in summaries}
    lc = by_branch["logout_cleanup"]
    assert set(lc) == set(piu.REVIEW_SUMMARY_FIELDS)
    assert lc["branch_status"] == "tested"
    assert lc["status_counts"]["candidate"] == 1
    assert lc["status_counts"]["signal"] == 0
    assert lc["tested_count"] == 1
    assert lc["applicability_counts"] == {"applicable": 1, "not_applicable": 0, "unknown": 0}
    # signal-only 分支：聚合为 inconclusive（无确定性结果）、tested_count 不含 signal
    tf = by_branch["temp_files"]
    assert tf["branch_status"] == "inconclusive"
    assert tf["status_counts"]["signal"] == 1
    assert tf["status_counts"]["candidate"] == 0
    assert tf["tested_count"] == 0
    assert by_branch["local_cache_database"]["branch_status"] == "not_applicable"
    assert by_branch["local_cache_database"]["status_counts"] == {
        s: 0 for s in ic.CANDIDATE_STATUS_VALUES
    }
    assert by_branch["local_cache_database"]["reason"] == "no cache material in scope"
    assert set(lc["status_counts"]) == set(ic.CANDIDATE_STATUS_VALUES)
    assert set(lc["applicability_counts"]) == set(ic.APPLICABILITY_COUNT_KEYS)


def test_local_data_not_applicable_without_reason_violation():
    rows, summaries, violations = lde.screen_local_data_observations(
        [_obs("temp_files", {}, applicability="not_applicable", reason="")]
    )
    assert rows == []
    assert any("not_applicable" in v and "reason" in v for v in violations)


def test_local_data_artifact_roundtrip_and_validation():
    rows, summaries, violations = lde.screen_local_data_observations(
        [
            _obs("token_persistence",
                 {"token_storage_key_observed": True, "token_survives_logout_confirmed": True}),
        ]
    )
    artifact = lde.build_local_data_review_artifact(
        rows, summaries, violations, "local_traffic", "2026-08-30T12:00:00+08:00"
    )
    assert tuple(sorted(artifact.keys())) == tuple(sorted(piu.REVIEW_ARTIFACT_KEYS))
    assert artifact["contract"] == "miniapp_storage_package_schema"
    assert artifact["phase"] == "local_data_exposure"
    assert artifact["observation_schema_version"] == "1.0"
    assert artifact["substatuses"]["token_persistence"] == "tested"
    assert artifact["authorization_basis"] == "local_traffic"
    assert lde.validate_local_data_review_artifact(artifact) == []
    # 行校验包装：candidate 行合法；跨分支 confirmed 形态在行级被拒
    assert lde.validate_local_data_candidate(rows[0]) == []
    bad = {**rows[0], "branch": "temp_files"}
    assert any("升级证据不满足" in v for v in lde.validate_local_data_candidate(bad))
    # artifact 校验负例
    bad_contract = {**artifact, "contract": "wrong"}
    assert any("contract" in v for v in lde.validate_local_data_review_artifact(bad_contract))
    bad_phase = {**artifact, "phase": "crypto_and_secret_handling"}
    assert any("phase" in v for v in lde.validate_local_data_review_artifact(bad_phase))
    bad_substatuses = {**artifact, "substatuses": {"unknown_branch": "tested"}}
    text = "\n".join(lde.validate_local_data_review_artifact(bad_substatuses))
    assert "未知分支" in text


def test_local_data_redline_constants():
    assert "不读取凭证文件" in lde.LOCAL_DATA_MATERIAL_RULE
    assert "敏感值不复制" in lde.LOCAL_DATA_MATERIAL_RULE
    # 凭证纪律在契约 red_lines 中留痕
    assert any("不复制到普通日志" in line for line in CONTRACT["red_lines"])


def test_local_data_module_has_no_network_or_concurrency_imports():
    """AST 结构负例：模块不得导入网络/并发/子进程库（离线红线，batch8_6 模式）。"""
    source = Path(lde.__file__).read_text(encoding="utf-8")
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


def test_local_data_import_has_no_environment_side_effect():
    """导入纪律：子进程全新导入模块前后 os.environ 不得变化（CLI 兜底仅 __main__）。"""
    code = (
        "import os, sys; "
        "before = dict(os.environ); "
        f"sys.path.insert(0, r'{SRC}'); "
        "import authorized_assessment.miniapp.local_data_exposure; "
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


def test_local_data_cli_writes_contract_shaped_artifact(tmp_path):
    """__main__ guard CLI：观察文件 → artifact JSON（纯文件到文件离线）。"""
    observations = tmp_path / "observations.json"
    observations.write_text(
        json.dumps({"observations": [
            _obs("logs_clipboard_screenshots",
                 {"log_sensitive_field_observed": True,
                  "log_or_clipboard_leak_confirmed": True}),
        ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    out = tmp_path / "storage" / "local-data-review.json"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.local_data_exposure",
         "--observations", str(observations), "--out", str(out),
         "--authorization-basis", "operator_supplied_material"],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )
    assert result.returncode == 0, result.stderr
    artifact = json.loads(out.read_text(encoding="utf-8-sig"))
    assert artifact["phase"] == "local_data_exposure"
    assert artifact["authorization_basis"] == "operator_supplied_material"
    assert artifact["rows"][0]["status"] == "candidate"
    assert artifact["substatuses"]["logs_clipboard_screenshots"] == "tested"


# ---------------------------------------------------------------------------
# batch11_3：crypto_and_secret_handling
# ---------------------------------------------------------------------------

CRYPTO_CONFIRMED_MAP = {
    "hardcoded_secrets": "secret_reachable_confirmed",
    "custom_crypto": "custom_crypto_bypassable_confirmed",
    "weak_random_key_derivation": "predictable_random_confirmed",
    "debug_config_env_keys": "env_key_accepted_confirmed",
}

CRYPTO_FORM_EVIDENCE = {
    "secret_like_string_observed": True,
    "secret_reference_marker_observed": True,
    "custom_crypto_code_observed": True,
    "custom_crypto_usage_marker_observed": True,
    "weak_random_call_observed": True,
    "key_derivation_marker_observed": True,
    "env_key_in_config_observed": True,
    "debug_config_key_clue_observed": True,
}


def test_crypto_secret_constants_match_contract():
    spec = CONTRACT["phases"]["crypto_and_secret_handling"]
    assert csr.CRYPTO_SECRET_BRANCHES == tuple(spec["branches"])
    # fan-in 引擎（单一实现，不复制）；CLI choices 经引擎继承授权材料枚举
    assert csr.sp_engine is piu
    assert csr.sp_engine.AUTHORIZATION_BASIS_VALUES == piu.AUTHORIZATION_BASIS_VALUES


def test_crypto_secret_observation_map_covers_evidence_enum():
    assert set(csr.CRYPTO_SECRET_OBSERVATION_EVIDENCE_MAP.values()) == set(
        csr.CRYPTO_SECRET_EVIDENCE_KINDS
    )


def test_crypto_secret_form_observations_never_upgrade():
    """secret_candidate 红线：未证实密钥字符串（及全部形态/支持性观察）永不升级。"""
    for branch in csr.CRYPTO_SECRET_BRANCHES:
        status = csr.sp_engine.grade_observation(
            branch,
            list(CRYPTO_FORM_EVIDENCE),
            csr.CRYPTO_SECRET_UPGRADE_RULES,
            csr.CRYPTO_SECRET_EVIDENCE_KINDS,
            csr.CRYPTO_SECRET_INSUFFICIENT_KINDS,
        )
        assert status == "signal", branch


def test_crypto_secret_confirmed_kinds_upgrade_matching_branch_only():
    for branch, confirmed in CRYPTO_CONFIRMED_MAP.items():
        status = csr.sp_engine.grade_observation(
            branch,
            [confirmed],
            csr.CRYPTO_SECRET_UPGRADE_RULES,
            csr.CRYPTO_SECRET_EVIDENCE_KINDS,
            csr.CRYPTO_SECRET_INSUFFICIENT_KINDS,
        )
        assert status == "candidate", branch
    # 跨分支确认形态不升级：confirmed 形态属于另一分支
    cross = csr.sp_engine.grade_observation(
        "hardcoded_secrets",
        ["env_key_accepted_confirmed"],
        csr.CRYPTO_SECRET_UPGRADE_RULES,
        csr.CRYPTO_SECRET_EVIDENCE_KINDS,
        csr.CRYPTO_SECRET_INSUFFICIENT_KINDS,
    )
    assert cross == "signal"


def test_crypto_secret_status_hint_respected():
    assert csr.sp_engine.grade_observation(
        "hardcoded_secrets",
        [],
        csr.CRYPTO_SECRET_UPGRADE_RULES,
        csr.CRYPTO_SECRET_EVIDENCE_KINDS,
        csr.CRYPTO_SECRET_INSUFFICIENT_KINDS,
        "needs_manual_validation",
    ) == "needs_manual_validation"
    assert csr.sp_engine.grade_observation(
        "hardcoded_secrets",
        [],
        csr.CRYPTO_SECRET_UPGRADE_RULES,
        csr.CRYPTO_SECRET_EVIDENCE_KINDS,
        csr.CRYPTO_SECRET_INSUFFICIENT_KINDS,
        "unproven",
    ) != "unproven"


def test_crypto_secret_candidate_row_validation_negatives():
    good = {
        "row_id": "row-0001",
        "branch": "hardcoded_secrets",
        "status": "candidate",
        "evidence_kinds": ["secret_like_string_observed", "secret_reachable_confirmed"],
        "source": "material:pkg-copy/appid-main",
        "evidence_ref": "artifacts/unpacked/appid/config.js:L42",
        "precondition": "offline review of existing read-only evidence; no key value copied",
        "reason": "hardcoded key confirmed server-accepted via prior evidence review",
    }
    assert csr.validate_crypto_secret_candidate(good) == []
    missing = {k: v for k, v in good.items() if k != "evidence_ref"}
    assert any("缺少必需字段" in v for v in csr.validate_crypto_secret_candidate(missing))
    bad_status = {**good, "status": "unproven"}
    assert any("status 非法" in v for v in csr.validate_crypto_secret_candidate(bad_status))
    bad_branch = {**good, "branch": "token_persistence"}
    assert any("branch 非法" in v for v in csr.validate_crypto_secret_candidate(bad_branch))
    unknown_kind = {**good, "evidence_kinds": ["token_survives_logout_confirmed"]}
    assert any("未知形态" in v for v in csr.validate_crypto_secret_candidate(unknown_kind))
    unmet = {**good, "evidence_kinds": ["secret_like_string_observed"]}
    assert any("升级证据不满足" in v for v in csr.validate_crypto_secret_candidate(unmet))
    no_evidence_ref = {**good, "evidence_ref": ""}
    assert any("evidence_ref 为空" in v for v in csr.validate_crypto_secret_candidate(no_evidence_ref))


def test_crypto_secret_screening_rows_summaries_and_stats_separation():
    rows, summaries, violations = csr.screen_crypto_secret_observations(
        [
            _obs("hardcoded_secrets",
                 {"secret_like_string_observed": True, "secret_reachable_confirmed": True}),
            _obs("weak_random_key_derivation", {"weak_random_call_observed": True}),
            _obs("custom_crypto", {},
                 applicability="not_applicable", reason="no custom crypto material in scope"),
        ]
    )
    assert violations == []
    assert [(r["row_id"], r["branch"], r["status"]) for r in rows] == [
        ("crypto_and_secret_handling-0001", "hardcoded_secrets", "candidate"),
        ("crypto_and_secret_handling-0002", "weak_random_key_derivation", "signal"),
    ]
    by_branch = {s["branch"]: s for s in summaries}
    hs = by_branch["hardcoded_secrets"]
    assert set(hs) == set(piu.REVIEW_SUMMARY_FIELDS)
    assert hs["branch_status"] == "tested"
    assert hs["status_counts"]["candidate"] == 1
    assert hs["status_counts"]["signal"] == 0
    assert hs["tested_count"] == 1
    assert hs["applicability_counts"] == {"applicable": 1, "not_applicable": 0, "unknown": 0}
    # signal-only 分支：聚合为 inconclusive（secret_candidate 线索不产生确定性结果）
    wk = by_branch["weak_random_key_derivation"]
    assert wk["branch_status"] == "inconclusive"
    assert wk["status_counts"]["signal"] == 1
    assert wk["tested_count"] == 0
    assert by_branch["custom_crypto"]["branch_status"] == "not_applicable"
    assert by_branch["custom_crypto"]["status_counts"] == {
        s: 0 for s in ic.CANDIDATE_STATUS_VALUES
    }
    assert by_branch["custom_crypto"]["reason"] == "no custom crypto material in scope"
    assert set(hs["status_counts"]) == set(ic.CANDIDATE_STATUS_VALUES)
    assert set(hs["applicability_counts"]) == set(ic.APPLICABILITY_COUNT_KEYS)


def test_crypto_secret_not_applicable_without_reason_violation():
    rows, summaries, violations = csr.screen_crypto_secret_observations(
        [_obs("debug_config_env_keys", {}, applicability="not_applicable", reason="")]
    )
    assert rows == []
    assert any("not_applicable" in v and "reason" in v for v in violations)


def test_crypto_secret_artifact_roundtrip_and_validation():
    rows, summaries, violations = csr.screen_crypto_secret_observations(
        [
            _obs("debug_config_env_keys",
                 {"env_key_in_config_observed": True, "env_key_accepted_confirmed": True}),
        ]
    )
    artifact = csr.build_crypto_secret_review_artifact(
        rows, summaries, violations, "local_traffic", "2026-08-30T12:00:00+08:00"
    )
    assert tuple(sorted(artifact.keys())) == tuple(sorted(piu.REVIEW_ARTIFACT_KEYS))
    assert artifact["contract"] == "miniapp_storage_package_schema"
    assert artifact["phase"] == "crypto_and_secret_handling"
    assert artifact["observation_schema_version"] == "1.0"
    assert artifact["substatuses"]["debug_config_env_keys"] == "tested"
    assert artifact["authorization_basis"] == "local_traffic"
    assert csr.validate_crypto_secret_review_artifact(artifact) == []
    # 行校验包装：candidate 行合法；跨分支 confirmed 形态在行级被拒
    assert csr.validate_crypto_secret_candidate(rows[0]) == []
    bad = {**rows[0], "branch": "hardcoded_secrets"}
    assert any("升级证据不满足" in v for v in csr.validate_crypto_secret_candidate(bad))
    # artifact 校验负例
    bad_contract = {**artifact, "contract": "wrong"}
    assert any("contract" in v for v in csr.validate_crypto_secret_review_artifact(bad_contract))
    bad_phase = {**artifact, "phase": "local_data_exposure"}
    assert any("phase" in v for v in csr.validate_crypto_secret_review_artifact(bad_phase))
    bad_substatuses = {**artifact, "substatuses": {"unknown_branch": "tested"}}
    text = "\n".join(csr.validate_crypto_secret_review_artifact(bad_substatuses))
    assert "未知分支" in text


def test_crypto_secret_redline_constants():
    # secret_candidate 红线：规格 1633 行原文语义 + 与契约 red_lines 互证
    assert "secret_candidate" in csr.SECRET_CANDIDATE_RED_LINE
    assert "无法证明有效性" in csr.SECRET_CANDIDATE_RED_LINE
    assert "不能直接称为密钥泄露漏洞" in csr.SECRET_CANDIDATE_RED_LINE
    assert any("secret_candidate" in line for line in CONTRACT["red_lines"])
    # 凭证纪律
    assert "不复制密钥/AppSecret 原文" in csr.CRYPTO_MATERIAL_RULE
    assert "不主动" in csr.CRYPTO_MATERIAL_RULE and "验证密钥有效性" in csr.CRYPTO_MATERIAL_RULE


def test_crypto_secret_module_has_no_network_or_concurrency_imports():
    """AST 结构负例：模块不得导入网络/并发/子进程库（离线红线，batch8_6 模式）。"""
    source = Path(csr.__file__).read_text(encoding="utf-8")
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


def test_crypto_secret_import_has_no_environment_side_effect():
    """导入纪律：子进程全新导入模块前后 os.environ 不得变化（CLI 兜底仅 __main__）。"""
    code = (
        "import os, sys; "
        "before = dict(os.environ); "
        f"sys.path.insert(0, r'{SRC}'); "
        "import authorized_assessment.miniapp.crypto_secret_review; "
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


def test_crypto_secret_cli_writes_contract_shaped_artifact(tmp_path):
    """__main__ guard CLI：观察文件 → artifact JSON（纯文件到文件离线）。"""
    observations = tmp_path / "observations.json"
    observations.write_text(
        json.dumps({"observations": [
            _obs("weak_random_key_derivation",
                 {"key_derivation_marker_observed": True,
                  "predictable_random_confirmed": True}),
        ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    out = tmp_path / "crypto" / "secret-review.json"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.crypto_secret_review",
         "--observations", str(observations), "--out", str(out),
         "--authorization-basis", "operator_supplied_material"],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )
    assert result.returncode == 0, result.stderr
    artifact = json.loads(out.read_text(encoding="utf-8-sig"))
    assert artifact["phase"] == "crypto_and_secret_handling"
    assert artifact["authorization_basis"] == "operator_supplied_material"
    assert artifact["rows"][0]["status"] == "candidate"
    assert artifact["substatuses"]["weak_random_key_derivation"] == "tested"
