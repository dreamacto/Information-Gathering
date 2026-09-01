"""tests/test_single_candidate_xss_validation.py —— batch16_2 专属测试。

正例：可执行上下文反射 / DOM sink 到达 → candidate（四要素回指齐全）。
规格 13.2 负例：反射但不可执行、WAF、超时错误、未筛选候选、param 错配、
证据索引缺失。plan 负例：未筛选 URL 拒绝、crawl/blind/update 禁入、
unavailable 工具 fail-closed。敏感数据过滤例 + 幂等例 + confirmed 禁止。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from authorized_assessment.triage import injection_candidates as ic  # noqa: E402
from authorized_assessment.triage import single_candidate_xss_validation as sxv  # noqa: E402

SCREENED = {
    "url": "https://target.example.com/search?q=INJ",
    "param": "q",
    "source_key_sha256": "a" * 64,
    "candidate_priority": "P1",
    "score": 7,
}


# ---------- plan ----------

def test_plan_requires_screened_candidate_marker():
    plan, violations = sxv.build_xsstrike_plan({"url": "https://x.example.com/?q=1", "param": "q"})
    assert plan["executable"] is False
    assert any("已筛选候选标记" in v for v in violations)


def test_plan_single_target_single_param_and_forbidden_flags_absent():
    plan, violations = sxv.build_xsstrike_plan(dict(SCREENED))
    assert violations == []
    assert plan["single_target"] and plan["single_param"]
    assert plan["no_crawl"] and plan["no_blind"] and plan["no_update"]
    flags = [a for a in plan["args"] if a.startswith("-")]
    assert set(flags) <= set(sxv.PLAN_ALLOWED_FLAGS)
    assert "--crawl" not in plan["args"] and "--blind" not in plan["args"] and "--update" not in plan["args"]


def test_plan_unregistered_tool_fail_closed():
    plan, _v = sxv.build_xsstrike_plan(
        dict(SCREENED), registry_path=PROJECT_ROOT / "tools" / "tool_registry.json"
    )
    # batch16_6 起 xsstrike 已显式登记 unavailable（未下载）；核心不变量 executable=false 不变
    assert plan["tool_status"] == "unavailable"
    assert plan["executable"] is False


def test_plan_active_tool_executable(tmp_path):
    binary = tmp_path / "xsstrike"
    binary.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    reg = tmp_path / "tool_registry.json"
    reg.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "tools": [
                    {
                        "tool_id": "xsstrike",
                        "display_name": "XSStrike",
                        "path": str(binary),
                        "version": "3.1.2",
                        "status": "active",
                        "runtime": "python",
                        "dependencies": [],
                        "known_limitations": "单候选验证；不爬站不用 OOB 不自更新",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    plan, violations = sxv.build_xsstrike_plan(dict(SCREENED), registry_path=reg, root=tmp_path)
    assert violations == []
    assert plan["executable"] is True
    assert plan["args"][plan["args"].index("-u") + 1] == SCREENED["url"]


@pytest.mark.parametrize(
    "candidate",
    [
        {"url": "https://x.example.com/?q=1"},
        {"param": "q", "source_key_sha256": "a"},
        {"url": "https://x.example.com/?q=1&q2=2", "param": "q,q2", "score": 1},
    ],
)
def test_plan_rejects_incomplete_candidates(candidate):
    _plan, violations = sxv.build_xsstrike_plan(candidate)
    assert violations


# ---------- ingest：正例 ----------

def _result(**overrides) -> dict:
    row = {
        "url": SCREENED["url"],
        "param": "q",
        "status": 200,
        "reflected": True,
        "executable_context": False,
        "dom_sink_hit": False,
        "waf_block": False,
        "error": "",
        "context": "html_body",
        "evidence_ref": "artifacts/xss/xsstrike-0001.txt",
    }
    row.update(overrides)
    return row


def test_executable_context_reflection_is_candidate():
    rows, summary, violations = sxv.ingest_xsstrike_results(
        [_result(executable_context=True, context="html_attribute")]
    )
    assert violations == []
    assert rows[0]["status"] == "candidate"
    assert rows[0]["evidence_kinds"] == ["payload_reflected_in_executable_context"]
    assert rows[0]["browser_context"] == "html_attribute"
    assert summary["category_status"] == "tested"


def test_dom_sink_reached_is_candidate():
    rows, _, violations = sxv.ingest_xsstrike_results(
        [_result(reflected=False, dom_sink_hit=True, context="dom_sink")]
    )
    assert violations == []
    assert rows[0]["status"] == "candidate"
    assert rows[0]["evidence_kinds"] == ["dom_sink_reached"]


# ---------- ingest：规格 13.2 负例 ----------

def test_reflection_without_executability_is_signal():
    rows, _, violations = sxv.ingest_xsstrike_results([_result()])
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert rows[0]["evidence_kinds"] == ["reflected_not_executable"]
    assert "不可执行" in rows[0]["reason"]


def test_no_reflection_at_all_is_signal():
    rows, _s, violations = sxv.ingest_xsstrike_results([_result(reflected=False)])
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert rows[0]["evidence_kinds"] == []


def test_waf_and_error_are_negative():
    rows, _, violations = sxv.ingest_xsstrike_results(
        [_result(waf_block=True, reflected=False),
         _result(param="page", url="https://target.example.com/list?page=X", error="timeout", reflected=False)]
    )
    assert violations == []
    assert all(r["status"] == "signal" for r in rows)
    assert "waf_block" in rows[0]["evidence_kinds"]
    assert "error_or_timeout" in rows[1]["evidence_kinds"]


def test_candidate_without_evidence_ref_downgrades():
    rows, _, violations = sxv.ingest_xsstrike_results([_result(executable_context=True, evidence_ref="")])
    assert rows[0]["status"] == "signal"
    assert any("evidence_ref" in v for v in violations)


def test_duplicate_url_param_marked_duplicate():
    rows, _s, violations = sxv.ingest_xsstrike_results([_result(), _result()])
    assert violations == []
    assert rows[0]["status"] == "signal" and rows[1]["status"] == "duplicate"


def test_credential_like_key_rejected():
    rows, _s, violations = sxv.ingest_xsstrike_results([_result(cookie="abc")])
    assert any("credential" in v.lower() for v in violations)


def test_sensitive_excerpt_rejected():
    rows, _s, violations = sxv.ingest_xsstrike_results(
        [_result(console_excerpt="Set-Cookie: session=abc123; Authorization: Bearer tok999")]
    )
    assert any("敏感值" in v for v in violations)
    blob = json.dumps(rows, ensure_ascii=False)
    assert "abc123" not in blob and "tok999" not in blob


def test_invalid_context_and_missing_fields():
    _rows, _s, violations = sxv.ingest_xsstrike_results(
        [_result(context="weird"), {"url": "https://x.example.com/?q=1"}, "not-a-dict"]
    )
    assert any("context 非法" in v for v in violations)
    assert any("缺少 url 或 param" in v for v in violations)
    assert any("必须是键值映射" in v for v in violations)


def test_confirmed_never_produced_and_rejected_by_validator():
    rows, _s, _v = sxv.ingest_xsstrike_results([_result(executable_context=True)])
    assert all(r["status"] != "confirmed" for r in rows)
    violations = sxv.validate_xss_validation_candidate({**rows[0], "status": "confirmed"}, label="neg")
    assert any("confirmed 永不由单候选验证" in v for v in violations)


def test_candidate_with_negative_kind_rejected_by_validator():
    row = {
        "candidate_id": "xssvalid-0001",
        "status": "candidate",
        "evidence_kinds": ["payload_reflected_in_executable_context", "reflected_not_executable"],
        "url": SCREENED["url"],
        "param": "q",
        "http_status": 200,
        "browser_context": "html_attribute",
        "evidence_ref": "x.txt",
    }
    violations = sxv.validate_xss_validation_candidate(row, label="neg")
    assert any("负例证据形态" in v for v in violations)


def test_ingest_is_idempotent():
    results = [_result(), _result(executable_context=True, context="js_string"), _result(error="dns")]
    first = sxv.ingest_xsstrike_results(results)
    second = sxv.ingest_xsstrike_results(results)
    assert first == second


def test_summary_reuses_single_engine():
    _rows, summary, violations = sxv.ingest_xsstrike_results([_result(executable_context=True)])
    assert violations == []
    assert set(summary["status_counts"]) == set(ic.CANDIDATE_STATUS_VALUES)
    assert summary["tested_count"] == sum(summary["status_counts"][s] for s in ic.DEFINITIVE_RESULT_STATUSES)
