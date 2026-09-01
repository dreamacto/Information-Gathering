"""tests/test_miniapp_auth_lifecycle.py —— 小程序认证三模块测试（规格 6.5，Batch 10）。

规格 6.5（1594 行）指定的单一测试文件，覆盖三个模块（逐子项追加，整文件实跑）：
  - platform_login_exchange（batch10_1）：平台登录交换五分支；
  - session_token_lifecycle（batch10_2）：token 生命周期五分支；
  - signature_replay_review（batch10_3）：签名重放四分支。

统一断言面：观察键→证据形态确定性映射、形态/支持性永不升级、confirmed 分支一一
对应不跨分支升级、status_hint 尊重人工判定、8 状态/行校验负例、not_applicable 需
reason、版本不符/缺来源违例、三统计概念分离与 branch_status 六值聚合、artifact
形状与 miniapp_auth_schema 契约键逐一相同、模块常量与契约零漂移、红线常量、
无网络/并发/子进程 AST 结构锁、导入期无环境副作用。

纯离线：不发任何请求、不创建/滥用登录凭证、不做写操作或并发验证。
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

from authorized_assessment.miniapp import platform_login_exchange as ple  # noqa: E402
from authorized_assessment.triage import injection_candidates as ic  # noqa: E402

CONTRACT = json.loads(
    (ROOT / "contracts" / "miniapp_auth_schema.json").read_text(encoding="utf-8-sig")
)


def _obs(branch: str, evidence: dict, **extra) -> dict:
    payload = {
        "branch": branch,
        "applicability": "applicable",
        "evidence": evidence,
        "source": "local_traffic:har-export",
        "evidence_ref": "evidence/auth/har.json:L10",
        "precondition": "operator-supplied authorization material only; no credential use",
        "reason": "observed in operator-supplied traffic export",
    }
    payload.update(extra)
    return payload


# ---------------------------------------------------------------------------
# batch10_1：platform_login_exchange
# ---------------------------------------------------------------------------

FORM_EVIDENCE = {
    "code_reuse_accepted_observed": True,
    "expired_code_accepted_observed": True,
    "appid_mismatch_observed": True,
    "session_key_client_visible_observed": True,
    "openid_as_authz_observed": True,
    "code_single_use_marker_observed": True,
    "code_ttl_marker_observed": True,
    "binding_check_marker_observed": True,
}


def test_derive_evidence_kinds_maps_observation_keys():
    kinds = ple.derive_auth_evidence_kinds(
        {"code_reuse_accepted_observed": True, "openid_as_authz_observed": True, "unknown_key": True},
        ple.PLATFORM_LOGIN_OBSERVATION_EVIDENCE_MAP,
    )
    assert kinds == ["code_reuse_accepted_observed", "openid_as_authz_observed"]
    assert ple.derive_auth_evidence_kinds({}, ple.PLATFORM_LOGIN_OBSERVATION_EVIDENCE_MAP) == []


def test_grade_form_and_supporting_observations_never_upgrade():
    for branch in ple.PLATFORM_LOGIN_BRANCHES:
        status = ple.grade_auth_observation(
            branch,
            list(FORM_EVIDENCE),
            ple.PLATFORM_LOGIN_UPGRADE_RULES,
            ple.PLATFORM_LOGIN_EVIDENCE_KINDS,
            ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        )
        assert status == "signal", branch


def test_grade_confirmed_kinds_upgrade_matching_branch_only():
    confirmed_map = {
        "login_code_one_time": "login_code_replay_confirmed",
        "login_code_expiry": "expired_code_exchange_confirmed",
        "appid_binding": "cross_appid_exchange_confirmed",
        "session_key_custody": "session_key_transmitted_confirmed",
        "openid_authorization_basis": "openid_authz_bypass_confirmed",
    }
    for branch, confirmed in confirmed_map.items():
        status = ple.grade_auth_observation(
            branch,
            ["code_reuse_accepted_observed", confirmed],
            ple.PLATFORM_LOGIN_UPGRADE_RULES,
            ple.PLATFORM_LOGIN_EVIDENCE_KINDS,
            ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        )
        assert status == "candidate", branch
    # 跨分支确认形态不升级：confirmed 形态属于另一分支
    cross = ple.grade_auth_observation(
        "session_key_custody",
        ["openid_authz_bypass_confirmed"],
        ple.PLATFORM_LOGIN_UPGRADE_RULES,
        ple.PLATFORM_LOGIN_EVIDENCE_KINDS,
        ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
    )
    assert cross == "signal"


def test_status_hint_respected():
    assert ple.grade_auth_observation(
        "appid_binding",
        [],
        ple.PLATFORM_LOGIN_UPGRADE_RULES,
        ple.PLATFORM_LOGIN_EVIDENCE_KINDS,
        ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        "needs_manual_validation",
    ) == "needs_manual_validation"
    # 非法 hint 不透传：回退到引擎判定
    assert ple.grade_auth_observation(
        "appid_binding",
        [],
        ple.PLATFORM_LOGIN_UPGRADE_RULES,
        ple.PLATFORM_LOGIN_EVIDENCE_KINDS,
        ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        "unproven",
    ) != "unproven"


def test_candidate_row_validation_negatives():
    good = {
        "row_id": "row-0001",
        "branch": "appid_binding",
        "status": "candidate",
        "evidence_kinds": ["appid_mismatch_observed", "cross_appid_exchange_confirmed"],
        "source": "local_traffic:har",
        "evidence_ref": "evidence/auth/har.json:L3",
        "precondition": "offline review only",
        "reason": "cross-appid exchange reproduced in captured traffic",
    }
    assert ple.validate_platform_login_candidate(good) == []
    missing = {k: v for k, v in good.items() if k != "evidence_ref"}
    assert any("缺少必需字段" in v for v in ple.validate_platform_login_candidate(missing))
    bad_status = {**good, "status": "unproven"}
    assert any("status 非法" in v for v in ple.validate_platform_login_candidate(bad_status))
    bad_branch = {**good, "branch": "token_rotation"}
    assert any("branch 非法" in v for v in ple.validate_platform_login_candidate(bad_branch))
    unknown_kind = {**good, "evidence_kinds": ["cross_tenant_confirmed"]}
    assert any("未知形态" in v for v in ple.validate_platform_login_candidate(unknown_kind))
    unmet = {**good, "evidence_kinds": ["appid_mismatch_observed"]}
    assert any("升级证据不满足" in v for v in ple.validate_platform_login_candidate(unmet))
    no_evidence_ref = {**good, "evidence_ref": ""}
    assert any("evidence_ref 为空" in v for v in ple.validate_platform_login_candidate(no_evidence_ref))


def test_screening_source_version_branch_violations():
    rows, summaries, violations = ple.screen_platform_login_observations(
        [
            {"branch": "login_code_one_time", "applicability": "applicable", "evidence": {}},
            _obs("appid_binding", {"code_reuse_accepted_observed": True},
                 observation_schema_version="0.9"),
            _obs("unknown_branch", {}),
            _obs("appid_binding", {}, applicability="perhaps"),
        ]
    )
    # 缺来源与空证据的观察仍产出 signal 行（形态记录，不升级），非法分支/适用性被跳过
    assert [(r["branch"], r["status"]) for r in rows] == [
        ("login_code_one_time", "signal"),
        ("appid_binding", "signal"),
    ]
    text = "\n".join(violations)
    assert "缺少来源 source" in text
    assert "observation_schema_version='0.9'" in text
    assert "branch 非法 'unknown_branch'" in text
    assert "applicability 非法 'perhaps'" in text
    assert "evidence_kinds 不能为空" in text
    assert len(summaries) == len(ple.PLATFORM_LOGIN_BRANCHES)


def test_screening_rows_summaries_and_stats_separation():
    rows, summaries, violations = ple.screen_platform_login_observations(
        [
            _obs("openid_authorization_basis",
                 {"openid_as_authz_observed": True, "openid_authz_bypass_confirmed": True}),
            _obs("openid_authorization_basis", {"openid_as_authz_observed": True}),
            _obs("login_code_one_time", {},
                 applicability="not_applicable", reason="no login flow in traffic"),
        ]
    )
    assert violations == []
    assert [(r["row_id"], r["branch"], r["status"]) for r in rows] == [
        ("platform_login_exchange-0001", "openid_authorization_basis", "candidate"),
        ("platform_login_exchange-0002", "openid_authorization_basis", "signal"),
    ]
    by_branch = {s["branch"]: s for s in summaries}
    oa = by_branch["openid_authorization_basis"]
    assert set(oa) == set(ple.AUTH_REVIEW_SUMMARY_FIELDS)
    assert oa["branch_status"] == "tested"
    assert oa["status_counts"]["candidate"] == 1
    assert oa["status_counts"]["signal"] == 1
    assert oa["tested_count"] == 1
    assert oa["applicability_counts"] == {"applicable": 2, "not_applicable": 0, "unknown": 0}
    assert by_branch["login_code_one_time"]["branch_status"] == "not_applicable"
    assert by_branch["login_code_one_time"]["status_counts"] == {
        s: 0 for s in ic.CANDIDATE_STATUS_VALUES
    }
    assert by_branch["login_code_one_time"]["reason"] == "no login flow in traffic"
    # 三统计概念分离：status_counts 键集 = 8 状态；applicability_counts 键集 = 三值
    assert set(oa["status_counts"]) == set(ic.CANDIDATE_STATUS_VALUES)
    assert set(oa["applicability_counts"]) == set(ic.APPLICABILITY_COUNT_KEYS)


def test_not_applicable_without_reason_violation():
    rows, summaries, violations = ple.screen_platform_login_observations(
        [_obs("session_key_custody", {}, applicability="not_applicable", reason="")]
    )
    assert rows == []
    assert any("not_applicable" in v and "reason" in v for v in violations)


def test_summary_candidate_requires_source_and_precondition():
    rows, summaries, violations = ple.screen_platform_login_observations(
        [
            {
                "branch": "openid_authorization_basis",
                "applicability": "applicable",
                "evidence": {"openid_authz_bypass_confirmed": True},
                "source": "",
            }
        ]
    )
    text = "\n".join(violations)
    assert any("source 为空" in v for v in violations)
    assert any("precondition 为空" in v for v in violations)
    assert rows[0]["status"] == "candidate"


def test_module_constants_match_contract():
    phases = CONTRACT["phases"]
    assert ple.PLATFORM_LOGIN_BRANCHES == tuple(phases["platform_login_exchange"]["branches"])
    assert ple.AUTH_REVIEW_ARTIFACTS == {
        phase: spec["artifact"] for phase, spec in phases.items()
    }
    assert ple.AUTH_PHASES == tuple(phases.keys())
    assert ple.AUTH_REVIEW_ROW_FIELDS == tuple(CONTRACT["artifact_fields"]["row_fields"])
    assert ple.AUTH_REVIEW_SUMMARY_FIELDS == tuple(CONTRACT["artifact_fields"]["summary_fields"])
    assert ple.AUTH_REVIEW_ARTIFACT_KEYS == tuple(CONTRACT["artifact_fields"]["artifact_keys"])
    assert ple.AUTHORIZATION_BASIS_VALUES == tuple(CONTRACT["authorization_basis_values"])
    assert ple.MINIAPP_AUTH_SCHEMA_VERSION == CONTRACT["schema_version"]
    assert ple.MINIAPP_AUTH_CONTRACT == CONTRACT["contract"]


def test_build_artifact_shape_matches_contract():
    rows, summaries, violations = ple.screen_platform_login_observations(
        [
            _obs("login_code_expiry",
                 {"expired_code_accepted_observed": True, "expired_code_exchange_confirmed": True}),
        ]
    )
    artifact = ple.build_platform_login_review_artifact(
        rows, summaries, violations, "operator_supplied_material", "2026-08-30T12:00:00+08:00"
    )
    assert tuple(sorted(artifact.keys())) == tuple(sorted(ple.AUTH_REVIEW_ARTIFACT_KEYS))
    assert artifact["contract"] == "miniapp_auth_schema"
    assert artifact["phase"] == "platform_login_exchange"
    assert artifact["observation_schema_version"] == "1.0"
    assert artifact["substatuses"]["login_code_expiry"] == "tested"
    assert artifact["authorization_basis"] == "operator_supplied_material"
    assert ple.validate_auth_review_artifact(
        artifact,
        "platform_login_exchange",
        ple.PLATFORM_LOGIN_BRANCHES,
        ple.PLATFORM_LOGIN_EVIDENCE_KINDS,
        ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        ple.PLATFORM_LOGIN_UPGRADE_RULES,
    ) == []


def test_artifact_validation_negatives():
    rows, summaries, violations = ple.screen_platform_login_observations([])
    artifact = ple.build_platform_login_review_artifact(
        rows, summaries, violations, "operator_supplied_material", "2026-08-30T12:00:00+08:00"
    )
    bad_contract = {**artifact, "contract": "wrong"}
    assert any("contract" in v for v in ple.validate_auth_review_artifact(
        bad_contract, "platform_login_exchange", ple.PLATFORM_LOGIN_BRANCHES,
        ple.PLATFORM_LOGIN_EVIDENCE_KINDS, ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        ple.PLATFORM_LOGIN_UPGRADE_RULES,
    ))
    bad_phase = {**artifact, "phase": "signature_replay"}
    assert any("phase" in v for v in ple.validate_auth_review_artifact(
        bad_phase, "platform_login_exchange", ple.PLATFORM_LOGIN_BRANCHES,
        ple.PLATFORM_LOGIN_EVIDENCE_KINDS, ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        ple.PLATFORM_LOGIN_UPGRADE_RULES,
    ))
    bad_basis = {**artifact, "authorization_basis": "self_registered_account"}
    assert any("authorization_basis" in v for v in ple.validate_auth_review_artifact(
        bad_basis, "platform_login_exchange", ple.PLATFORM_LOGIN_BRANCHES,
        ple.PLATFORM_LOGIN_EVIDENCE_KINDS, ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        ple.PLATFORM_LOGIN_UPGRADE_RULES,
    ))
    bad_substatuses = {**artifact, "substatuses": {"unknown_branch": "tested"}}
    text = "\n".join(ple.validate_auth_review_artifact(
        bad_substatuses, "platform_login_exchange", ple.PLATFORM_LOGIN_BRANCHES,
        ple.PLATFORM_LOGIN_EVIDENCE_KINDS, ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        ple.PLATFORM_LOGIN_UPGRADE_RULES,
    ))
    assert "未知分支" in text
    missing = {k: v for k, v in artifact.items() if k != "rows"}
    assert any("缺少必需键 rows" in v for v in ple.validate_auth_review_artifact(
        missing, "platform_login_exchange", ple.PLATFORM_LOGIN_BRANCHES,
        ple.PLATFORM_LOGIN_EVIDENCE_KINDS, ple.PLATFORM_LOGIN_INSUFFICIENT_KINDS,
        ple.PLATFORM_LOGIN_UPGRADE_RULES,
    ))


def test_redline_constants():
    assert "不自动创建或滥用登录凭证" in ple.NO_CREDENTIAL_CREATION_RULE
    assert "授权材料" in ple.NO_CREDENTIAL_CREATION_RULE
    assert "不是授权依据" in ple.OPENID_NOT_AUTHORIZATION_RULE
    assert "OpenID" in ple.OPENID_NOT_AUTHORIZATION_RULE


def test_module_has_no_network_or_concurrency_imports():
    """AST 结构负例：模块不得导入网络/并发/子进程库（离线红线，batch8_6 模式）。"""
    source = Path(ple.__file__).read_text(encoding="utf-8")
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
    """导入纪律：子进程全新导入模块前后 os.environ 不得变化（CLI 兑底仅 __main__）。"""
    code = (
        "import os, sys; "
        "before = dict(os.environ); "
        f"sys.path.insert(0, r'{SRC}'); "
        "import authorized_assessment.miniapp.platform_login_exchange; "
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
            _obs("login_code_one_time",
                 {"code_reuse_accepted_observed": True, "login_code_replay_confirmed": True}),
        ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    out = tmp_path / "auth" / "platform-login-review.json"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.platform_login_exchange",
         "--observations", str(observations), "--out", str(out),
         "--authorization-basis", "local_traffic"],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )
    assert result.returncode == 0, result.stderr
    artifact = json.loads(out.read_text(encoding="utf-8-sig"))
    assert artifact["phase"] == "platform_login_exchange"
    assert artifact["authorization_basis"] == "local_traffic"
    assert artifact["rows"][0]["status"] == "candidate"
    assert artifact["substatuses"]["login_code_one_time"] == "tested"


# ---------------------------------------------------------------------------
# batch10_2：session_token_lifecycle
# ---------------------------------------------------------------------------

from authorized_assessment.miniapp import session_token_lifecycle as stl  # noqa: E402


def test_session_token_constants_match_contract():
    spec = CONTRACT["phases"]["session_token_lifecycle"]
    assert stl.SESSION_TOKEN_BRANCHES == tuple(spec["branches"])
    # 共享引擎引用（单一实现，不复制）
    assert stl.auth_engine is ple


def test_session_token_observation_map_covers_evidence_enum():
    assert set(stl.SESSION_TOKEN_OBSERVATION_EVIDENCE_MAP.values()) == set(
        stl.SESSION_TOKEN_EVIDENCE_KINDS
    )


SESSION_TOKEN_CONFIRMED_MAP = {
    "token_rotation": "stale_token_after_rotation_confirmed",
    "token_revocation_logout": "revoked_token_usable_confirmed",
    "multi_device_login": "uncontrolled_device_session_confirmed",
    "stale_token_new_api": "stale_token_privilege_confirmed",
    "device_user_tenant_binding": "cross_tenant_token_use_confirmed",
}

SESSION_TOKEN_FORM_EVIDENCE = {
    "token_reuse_after_refresh_observed": True,
    "logout_token_accepted_observed": True,
    "concurrent_session_clue_observed": True,
    "stale_token_accepted_observed": True,
    "binding_absent_observed": True,
    "rotation_marker_observed": True,
    "revocation_endpoint_marker_observed": True,
    "device_list_marker_observed": True,
    "binding_marker_observed": True,
}


def test_session_token_form_observations_never_upgrade():
    for branch in stl.SESSION_TOKEN_BRANCHES:
        status = stl.auth_engine.grade_auth_observation(
            branch,
            list(SESSION_TOKEN_FORM_EVIDENCE),
            stl.SESSION_TOKEN_UPGRADE_RULES,
            stl.SESSION_TOKEN_EVIDENCE_KINDS,
            stl.SESSION_TOKEN_INSUFFICIENT_KINDS,
        )
        assert status == "signal", branch


def test_session_token_confirmed_kinds_upgrade_matching_branch_only():
    for branch, confirmed in SESSION_TOKEN_CONFIRMED_MAP.items():
        status = stl.auth_engine.grade_auth_observation(
            branch,
            [confirmed],
            stl.SESSION_TOKEN_UPGRADE_RULES,
            stl.SESSION_TOKEN_EVIDENCE_KINDS,
            stl.SESSION_TOKEN_INSUFFICIENT_KINDS,
        )
        assert status == "candidate", branch
    cross = stl.auth_engine.grade_auth_observation(
        "token_rotation",
        ["cross_tenant_token_use_confirmed"],
        stl.SESSION_TOKEN_UPGRADE_RULES,
        stl.SESSION_TOKEN_EVIDENCE_KINDS,
        stl.SESSION_TOKEN_INSUFFICIENT_KINDS,
    )
    assert cross == "signal"


def test_session_token_screening_and_artifact_roundtrip():
    rows, summaries, violations = stl.screen_session_token_observations(
        [
            _obs_token("token_revocation_logout",
                       {"logout_token_accepted_observed": True,
                        "revoked_token_usable_confirmed": True}),
            _obs_token("multi_device_login", {},
                       applicability="not_applicable", reason="no device list material"),
            _obs_token("multi_device_login", {},
                       applicability="not_applicable", reason=""),
        ]
    )
    assert [(r["branch"], r["status"]) for r in rows] == [
        ("token_revocation_logout", "candidate"),
    ]
    text = "\n".join(violations)
    assert "not_applicable 但 reason 为空" in text
    by_branch = {s["branch"]: s for s in summaries}
    assert by_branch["token_revocation_logout"]["branch_status"] == "tested"
    assert by_branch["multi_device_login"]["branch_status"] == "not_applicable"
    artifact = stl.build_session_token_review_artifact(
        rows, summaries, violations, "operator_supplied_material", "2026-08-30T12:00:00+08:00"
    )
    assert tuple(sorted(artifact.keys())) == tuple(sorted(ple.AUTH_REVIEW_ARTIFACT_KEYS))
    assert artifact["phase"] == "session_token_lifecycle"
    assert stl.validate_session_token_review_artifact(artifact) == []
    # 行校验包装：candidate 行合法；跨分支 confirmed 形态在行级被拒
    assert stl.validate_session_token_candidate(rows[0]) == []
    bad = {**rows[0], "branch": "token_rotation"}
    assert any("升级证据不满足" in v for v in stl.validate_session_token_candidate(bad))


def _obs_token(branch: str, evidence: dict, **extra) -> dict:
    payload = {
        "branch": branch,
        "applicability": "applicable",
        "evidence": evidence,
        "source": "local_traffic:session-export",
        "evidence_ref": "evidence/auth/session-export.json:L22",
        "precondition": "operator-supplied authorization material only; no auto login/renewal",
        "reason": "observed in operator-supplied session export",
    }
    payload.update(extra)
    return payload


def test_session_token_redline_constants():
    assert "不自动登录" in stl.TOKEN_REVIEW_MATERIAL_RULE
    assert "授权材料" in stl.TOKEN_REVIEW_MATERIAL_RULE
    assert "写操作" in stl.NO_TOKEN_WRITE_REPLAY_RULE and "审批门" in stl.NO_TOKEN_WRITE_REPLAY_RULE


def test_session_token_cli_writes_contract_shaped_artifact(tmp_path):
    observations = tmp_path / "observations.json"
    observations.write_text(
        json.dumps({"observations": [
            _obs_token("stale_token_new_api",
                       {"stale_token_accepted_observed": True,
                        "stale_token_privilege_confirmed": True}),
        ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    out = tmp_path / "auth" / "session-lifecycle-review.json"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.session_token_lifecycle",
         "--observations", str(observations), "--out", str(out),
         "--authorization-basis", "local_traffic"],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )
    assert result.returncode == 0, result.stderr
    artifact = json.loads(out.read_text(encoding="utf-8-sig"))
    assert artifact["phase"] == "session_token_lifecycle"
    assert artifact["substatuses"]["stale_token_new_api"] == "tested"
    assert artifact["rows"][0]["status"] == "candidate"


# ---------------------------------------------------------------------------
# batch10_3：signature_replay_review
# ---------------------------------------------------------------------------

from authorized_assessment.miniapp import signature_replay_review as srr  # noqa: E402


def _obs_sig(branch: str, evidence: dict, **extra) -> dict:
    payload = {
        "branch": branch,
        "applicability": "applicable",
        "evidence": evidence,
        "source": "local_traffic:signed-request-export",
        "evidence_ref": "evidence/auth/signed-requests.json:L8",
        "precondition": "operator-supplied authorization material only; offline review, "
        "no request replay (write/concurrency validation is approval-gated)",
        "reason": "observed in operator-supplied signed request export",
    }
    payload.update(extra)
    return payload


def test_signature_replay_constants_match_contract():
    spec = CONTRACT["phases"]["signature_replay"]
    assert srr.SIGNATURE_REPLAY_BRANCHES == tuple(spec["branches"])
    # 扇形导入方向：两域模块都引用同一共享引擎，且互不 import
    assert srr.auth_engine is ple and stl.auth_engine is ple


def test_signature_replay_observation_map_covers_evidence_enum():
    assert set(srr.SIGNATURE_REPLAY_OBSERVATION_EVIDENCE_MAP.values()) == set(
        srr.SIGNATURE_REPLAY_EVIDENCE_KINDS
    )


SIGNATURE_CONFIRMED_MAP = {
    "nonce_timestamp": "same_nonce_accepted_confirmed",
    "signature_canonicalization": "signature_malleability_confirmed",
    "replay_window": "signature_replay_impact_confirmed",
    "binding_scope": "signature_cross_context_confirmed",
}

SIGNATURE_FORM_EVIDENCE = {
    "nonce_missing_observed": True,
    "canonicalization_ambiguous_observed": True,
    "replay_accepted_observed": True,
    "signature_binding_absent_observed": True,
    "timestamp_window_marker_observed": True,
    "signature_field_marker_observed": True,
    "replay_cache_marker_observed": True,
    "signature_binding_marker_observed": True,
}


def test_signature_replay_form_observations_never_upgrade():
    for branch in srr.SIGNATURE_REPLAY_BRANCHES:
        status = srr.auth_engine.grade_auth_observation(
            branch,
            list(SIGNATURE_FORM_EVIDENCE),
            srr.SIGNATURE_REPLAY_UPGRADE_RULES,
            srr.SIGNATURE_REPLAY_EVIDENCE_KINDS,
            srr.SIGNATURE_REPLAY_INSUFFICIENT_KINDS,
        )
        assert status == "signal", branch


def test_signature_replay_confirmed_kinds_upgrade_matching_branch_only():
    for branch, confirmed in SIGNATURE_CONFIRMED_MAP.items():
        status = srr.auth_engine.grade_auth_observation(
            branch,
            [confirmed],
            srr.SIGNATURE_REPLAY_UPGRADE_RULES,
            srr.SIGNATURE_REPLAY_EVIDENCE_KINDS,
            srr.SIGNATURE_REPLAY_INSUFFICIENT_KINDS,
        )
        assert status == "candidate", branch
    cross = srr.auth_engine.grade_auth_observation(
        "replay_window",
        ["same_nonce_accepted_confirmed"],
        srr.SIGNATURE_REPLAY_UPGRADE_RULES,
        srr.SIGNATURE_REPLAY_EVIDENCE_KINDS,
        srr.SIGNATURE_REPLAY_INSUFFICIENT_KINDS,
    )
    assert cross == "signal"


def test_signature_replay_screening_and_artifact_roundtrip():
    rows, summaries, violations = srr.screen_signature_replay_observations(
        [
            _obs_sig("nonce_timestamp",
                     {"nonce_missing_observed": True, "same_nonce_accepted_confirmed": True}),
            _obs_sig("binding_scope", {},
                     applicability="not_applicable",
                     reason="signing material not bound to tenant context in scope"),
            _obs_sig("binding_scope", {},
                     applicability="not_applicable", reason=""),
        ]
    )
    assert [(r["branch"], r["status"]) for r in rows] == [
        ("nonce_timestamp", "candidate"),
    ]
    text = "\n".join(violations)
    assert "not_applicable 但 reason 为空" in text
    by_branch = {s["branch"]: s for s in summaries}
    assert by_branch["nonce_timestamp"]["branch_status"] == "tested"
    assert by_branch["binding_scope"]["branch_status"] == "not_applicable"
    artifact = srr.build_signature_replay_review_artifact(
        rows, summaries, violations, "local_traffic", "2026-08-30T12:00:00+08:00"
    )
    assert tuple(sorted(artifact.keys())) == tuple(sorted(ple.AUTH_REVIEW_ARTIFACT_KEYS))
    assert artifact["phase"] == "signature_replay"
    assert srr.validate_signature_replay_review_artifact(artifact) == []
    assert srr.validate_signature_replay_candidate(rows[0]) == []
    bad = {**rows[0], "branch": "replay_window"}
    assert any("升级证据不满足" in v for v in srr.validate_signature_replay_candidate(bad))


def test_signature_replay_redline_constants():
    assert "不自动重放任何请求" in srr.SIGNATURE_REPLAY_OFFLINE_RULE
    assert "审批门" in srr.SIGNATURE_REPLAY_OFFLINE_RULE
    assert "授权材料" in srr.SIGNATURE_REPLAY_MATERIAL_RULE
    assert "不自动创建或滥用登录凭证" in srr.SIGNATURE_REPLAY_MATERIAL_RULE


def test_signature_replay_cli_writes_contract_shaped_artifact(tmp_path):
    observations = tmp_path / "observations.json"
    observations.write_text(
        json.dumps({"observations": [
            _obs_sig("replay_window",
                     {"replay_accepted_observed": True,
                      "signature_replay_impact_confirmed": True}),
        ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    out = tmp_path / "auth" / "signature-replay-review.json"
    result = subprocess.run(
        [sys.executable, "-m", "authorized_assessment.miniapp.signature_replay_review",
         "--observations", str(observations), "--out", str(out),
         "--authorization-basis", "operator_supplied_material"],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )
    assert result.returncode == 0, result.stderr
    artifact = json.loads(out.read_text(encoding="utf-8-sig"))
    assert artifact["phase"] == "signature_replay"
    assert artifact["authorization_basis"] == "operator_supplied_material"
    assert artifact["substatuses"]["replay_window"] == "tested"
    assert artifact["rows"][0]["status"] == "candidate"


# ---------------------------------------------------------------------------
# 三模块总检（契约三方零漂移 + AST 锁 + 导入纪律）
# ---------------------------------------------------------------------------

def test_three_modules_contract_lock():
    """branches/artifact 路径/共享形状常量：三模块 ↔ miniapp_auth_schema 三方零漂移。"""
    assert ple.PLATFORM_LOGIN_BRANCHES == tuple(
        CONTRACT["phases"]["platform_login_exchange"]["branches"])
    assert stl.SESSION_TOKEN_BRANCHES == tuple(
        CONTRACT["phases"]["session_token_lifecycle"]["branches"])
    assert srr.SIGNATURE_REPLAY_BRANCHES == tuple(
        CONTRACT["phases"]["signature_replay"]["branches"])
    for module in (stl, srr):
        # 薄域模块：共享形状常量单一来源 = platform_login_exchange 引擎
        assert module.auth_engine is ple
    assert ple.AUTH_PHASES == tuple(CONTRACT["phases"].keys())
    assert ple.AUTH_REVIEW_ARTIFACTS == {
        phase: spec["artifact"] for phase, spec in CONTRACT["phases"].items()
    }
    assert ple.AUTH_REVIEW_ROW_FIELDS == tuple(CONTRACT["artifact_fields"]["row_fields"])
    assert ple.AUTH_REVIEW_SUMMARY_FIELDS == tuple(CONTRACT["artifact_fields"]["summary_fields"])
    assert ple.AUTH_REVIEW_ARTIFACT_KEYS == tuple(CONTRACT["artifact_fields"]["artifact_keys"])
    assert ple.AUTHORIZATION_BASIS_VALUES == tuple(CONTRACT["authorization_basis_values"])
    assert ple.MINIAPP_AUTH_CONTRACT == "miniapp_auth_schema"
    assert ple.MINIAPP_AUTH_SCHEMA_VERSION == "1.0"


def test_three_modules_no_network_or_concurrency_imports():
    """AST 结构负例：三模块均不得导入网络/并发/子进程库（离线红线，batch8_6 模式）。"""
    banned_roots = {
        "requests", "urllib", "urllib3", "http", "httpx", "aiohttp", "socket", "ssl",
        "asyncio", "threading", "concurrent", "multiprocessing", "subprocess",
        "telnetlib", "ftplib",
    }
    for module in (ple, stl, srr):
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported += [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        violations = [name for name in imported if name.split(".")[0] in banned_roots]
        assert violations == [], (module.__name__, violations)


def test_three_modules_import_has_no_environment_side_effect():
    """导入纪律：三模块全新导入前后 os.environ 不得变化（CLI 兜底仅 __main__ guard）。"""
    for module_name in (
        "authorized_assessment.miniapp.platform_login_exchange",
        "authorized_assessment.miniapp.session_token_lifecycle",
        "authorized_assessment.miniapp.signature_replay_review",
    ):
        code = (
            "import os, sys; "
            "before = dict(os.environ); "
            f"sys.path.insert(0, r'{SRC}'); "
            f"import {module_name}; "
            "changed = {k: os.environ[k] for k in os.environ if before.get(k) != os.environ[k]}; "
            "removed = [k for k in before if k not in os.environ]; "
            "assert not changed and not removed, (changed, removed); "
            "print('IMPORT_CLEAN')"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, (module_name, result.stderr)
        assert "IMPORT_CLEAN" in result.stdout
