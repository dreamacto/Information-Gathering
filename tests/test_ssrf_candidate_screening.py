"""tests/test_ssrf_candidate_screening.py —— SSRF 候选筛选测试（Batch 6 / 规格 5.4 + 13.2）。

覆盖：
  - 词表加载（同源 wordlists/ssrf_params.txt；缺失回退内置核心子集，fail-soft）；
  - 观察键 → 证据形态确定性映射；升级规则（OOB 回调命中 / 时间差分+服务端发起 /
    响应内容注入+服务端发起）；
  - 13.2 负例：仅参数名命中不算漏洞、POST 表单只做静态候选不自动探测、
    不在分析面且无更强证据不产候选；
  - 汇总行复用 validate_category_summary（categories=("ssrf",)）通过契约校验；
  - OOB token manifest：公共 OAST 域拒绝（规格红线）、hit 无 approval_ref 拒绝、
    token 重复、status 非法。
"""
from __future__ import annotations

from pathlib import Path

from authorized_assessment.triage import injection_candidates as ic
from authorized_assessment.triage import ssrf_candidate_screening as ss

ROOT = Path(__file__).resolve().parents[1]


def _observation(**overrides: object) -> dict:
    obs = {
        "endpoint": "/api/fetch-avatar",
        "http_method": "GET",
        "input_location": "query",
        "parameter_name": "image",
        "applicability": "applicable",
        "evidence": {"server_fetch_evidence_observed": True, "timing_differential_observed": True},
        "evidence_ref": "runs/demo/evidence/ssrf/timing.json",
        "reason": "图片拉取参数时间差分",
        "precondition": "OOB/内网验证均为审批门；先人工确认参数进入服务端请求",
    }
    obs.update(overrides)
    return obs


def test_load_param_wordlist_same_source_as_root_triage():
    words = ss.load_param_wordlist()
    assert len(words) >= 30
    assert "url" in {w.lower() for w in words}


def test_load_param_wordlist_missing_file_falls_back(tmp_path):
    words = ss.load_param_wordlist(tmp_path / "no_such_wordlist.txt")
    assert words == ss.DEFAULT_SSRF_PARAMS


def test_derive_ssrf_evidence_kinds_deterministic():
    kinds = ss.derive_ssrf_evidence_kinds(
        {"oob_callback_hit_confirmed": True, "param_name_matched": True}
    )
    assert kinds == ["oob_callback_hit", "param_name_match"]


def test_grade_requires_branch_evidence():
    assert ss.grade_ssrf_observation(["oob_callback_hit"]) == "candidate"
    assert (
        ss.grade_ssrf_observation(["timing_differential", "server_fetch_evidence"])
        == "candidate"
    )
    assert ss.grade_ssrf_observation(["param_name_match"]) == "signal"
    assert ss.grade_ssrf_observation([]) == "signal"


def test_param_name_match_alone_never_upgrades():
    rows, summary, violations = ss.screen_ssrf_observations(
        [_observation(evidence={"param_name_matched": True}, evidence_ref="")]
    )
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert summary["status_counts"]["candidate"] == 0


def test_timing_plus_fetch_evidence_upgrades():
    rows, summary, violations = ss.screen_ssrf_observations([_observation()])
    assert violations == []
    assert rows[0]["status"] == "candidate"
    assert "param_name_match" in rows[0]["evidence_kinds"]
    assert summary["category"] == "ssrf"
    assert summary["status_counts"]["candidate"] == 1
    assert summary["tested_count"] == 1
    assert ss.validate_ssrf_candidate(rows[0]) == []
    assert ic.validate_category_summary(summary, categories=("ssrf",)) == []


def test_post_form_params_stay_static_candidates():
    obs = _observation(
        http_method="POST",
        parameter_name="webhook",
        evidence={"server_fetch_evidence_observed": True, "timing_differential_observed": True},
    )
    rows, summary, violations = ss.screen_ssrf_observations([obs])
    assert violations == []
    assert "post_form_static_only" in rows[0]["evidence_kinds"]
    # post_form_static_only 不足证据，但分支证据（时间差分+服务端发起）已满足 → 仍 candidate；
    # 关键红线是筛选层不发探测值——由 status 保持 candidate 而非自动验证体现。
    assert rows[0]["status"] == "candidate"
    assert summary["status_counts"]["candidate"] == 1


def test_post_only_signal_without_branch_evidence():
    obs = _observation(http_method="POST", parameter_name="webhook", evidence={})
    rows, _, violations = ss.screen_ssrf_observations([obs])
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert "post_form_static_only" in rows[0]["evidence_kinds"]


def test_out_of_surface_param_without_strong_evidence_not_candidate():
    obs = _observation(
        parameter_name="username",
        evidence={"param_name_matched": True},
        evidence_ref="",
    )
    rows, summary, violations = ss.screen_ssrf_observations([obs])
    assert violations == []
    assert rows == []
    assert summary["status_counts"]["candidate"] == 0


def test_not_applicable_kept_in_summary_count():
    obs = {
        "applicability": "not_applicable",
        "reason": "目标无 URL/callback/webhook 类参数入口",
    }
    rows, summary, violations = ss.screen_ssrf_observations([obs])
    assert violations == []
    assert rows == []
    assert summary["category_status"] == "not_applicable"
    assert summary["applicability_counts"]["not_applicable"] == 1


def test_unknown_applicability_and_invalid_inputs():
    rows, summary, violations = ss.screen_ssrf_observations(
        [_observation(applicability="unknown", evidence={})]
    )
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert summary["applicability_counts"]["unknown"] == 1
    _, _, violations = ss.screen_ssrf_observations(["bad"])  # type: ignore[list-item]
    assert any("必须是键值映射" in v for v in violations)
    _, _, violations = ss.screen_ssrf_observations([_observation(applicability="maybe")])
    assert any("applicability 非法" in v for v in violations)


def test_candidate_missing_evidence_ref_is_violation():
    obs = _observation(evidence_ref="")
    _, _, violations = ss.screen_ssrf_observations([obs])
    assert any("evidence_ref 为空" in v for v in violations)


def test_validate_ssrf_candidate_rejects_unknown_kinds_and_status():
    violations = ss.validate_ssrf_candidate(
        {"candidate_id": "ssrf-x", "status": "candidate", "evidence_kinds": ["ghost"], "source": "s"}
    )
    assert any("未知形态" in v for v in violations)
    violations = ss.validate_ssrf_candidate(
        {"candidate_id": "ssrf-x", "status": "vulnerable", "evidence_kinds": [], "source": "s"}
    )
    assert any("status 非法" in v for v in violations)


# ---------------------------------------------------------------------------
# OOB token manifest（审批门产物）
# ---------------------------------------------------------------------------

def test_oob_token_entry_valid():
    entry, violations = ss.build_oob_token_entry(
        token="aabbccddeeff",
        callback_host="127.0.0.1:8899",
        issued_at="2026-08-29T22:00:00+08:00",
    )
    assert violations == []
    assert entry["status"] == "issued"


def test_oob_public_oast_hosts_rejected():
    for host in ("oast.pro", "x.burpcollaborator.net", "webhook.site"):
        _, violations = ss.build_oob_token_entry(
            token="aabbccddeeff", callback_host=host, issued_at="2026-08-29T22:00:00+08:00"
        )
        assert any("公共 OAST" in v for v in violations), host


def test_oob_hit_requires_approval_ref():
    _, violations = ss.build_oob_token_entry(
        token="aabbccddeeff",
        callback_host="127.0.0.1:8899",
        issued_at="2026-08-29T22:00:00+08:00",
        status="hit",
    )
    assert any("approval_ref 为空" in v for v in violations)
    entry, violations = ss.build_oob_token_entry(
        token="aabbccddeeff",
        callback_host="127.0.0.1:8899",
        issued_at="2026-08-29T22:00:00+08:00",
        status="hit",
        approval_ref="APPROVAL-2026-08-29-01",
    )
    assert violations == []


def test_oob_token_entry_invalid_status_and_empty_token():
    _, violations = ss.build_oob_token_entry(
        token="", callback_host="127.0.0.1:8899", issued_at="x", status="pending"
    )
    assert any("token 不能为空" in v for v in violations)
    assert any("status 非法" in v for v in violations)


def test_oob_token_manifest_validation():
    manifest = {
        "tokens": [
            {
                "token": "aabbccddeeff",
                "callback_host": "127.0.0.1:8899",
                "issued_at": "2026-08-29T22:00:00+08:00",
                "status": "issued",
            },
            {
                "token": "aabbccddeeff",
                "callback_host": "127.0.0.1:8899",
                "issued_at": "2026-08-29T22:01:00+08:00",
                "status": "issued",
            },
        ]
    }
    violations = ss.validate_oob_token_manifest(manifest)
    assert any("token 重复" in v for v in violations)
    violations = ss.validate_oob_token_manifest(
        {"tokens": [{"token": "ff", "callback_host": "oast.fun", "issued_at": "x"}]}
    )
    assert any("公共 OAST" in v for v in violations)
    violations = ss.validate_oob_token_manifest({"tokens": "bad"})
    assert any("tokens 必须为列表" in v for v in violations)
