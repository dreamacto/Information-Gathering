"""tests/test_ffuf_directory_candidates.py —— batch16_1 专属测试。

正例：基线差分+语义命中 → candidate；registry active → 计划 executable。
规格 13.2 负例：通用 200 soft-404、登录页、WAF/403/429、超时和 DNS 错误、
无基线 fail-closed、200 ≠ 敏感资源。plan 负例：多目标/非 http/自带 FUZZ/shell
元字符/低 delay/词表缺失/未登记与 unavailable 工具。敏感数据过滤例 + 幂等例。
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

from authorized_assessment.triage import ffuf_directory_candidates as fdc  # noqa: E402
from authorized_assessment.triage import injection_candidates as ic  # noqa: E402

WILDCARD_BASELINE = {"status": 200, "length": 5120, "words": 700, "lines": 120}


def _result(fuzz: str, **overrides) -> dict:
    row = {
        "url": f"https://target.example.com/{fuzz}",
        "input": {"FUZZ": fuzz},
        "status": 200,
        "length": 800,
        "words": 90,
        "lines": 20,
        "content-type": "text/html",
        "resultfile": f"ffuf_{fuzz}.json",
    }
    row.update(overrides)
    return row


def _write_registry(tmp_path: Path, status: str, with_binary: bool = True) -> Path:
    binary = tmp_path / "ffuf.exe"
    if with_binary:
        binary.write_bytes(b"stub")
    entry = {
        "tool_id": "ffuf",
        "display_name": "ffuf",
        "path": str(binary) if with_binary else str(tmp_path / "missing" / "ffuf.exe"),
        "version": "2.1.0",
        "status": status,
        "runtime": "native",
        "dependencies": [],
        "known_limitations": "受控目录候选；200 不等于敏感资源存在",
    }
    reg_path = tmp_path / "tool_registry.json"
    reg_path.write_text(json.dumps({"schema_version": "1.0", "tools": [entry]}), encoding="utf-8")
    return reg_path


# ---------- plan ----------

def test_plan_unregistered_tool_is_fail_closed():
    plan, violations = fdc.build_ffuf_plan(
        "https://target.example.com", output_path="out.json", registry_path=PROJECT_ROOT / "tools" / "tool_registry.json"
    )
    # batch16_6 起 ffuf 已显式登记 unavailable（未下载）；核心不变量 executable=false 不变
    assert plan["tool_status"] == "unavailable"
    assert plan["executable"] is False
    assert plan["recursion"] is False and plan["threads"] == 1
    assert plan["delay_seconds"] >= fdc.FFUF_MIN_DELAY_SECONDS
    assert "-recursion" not in plan["args"]
    assert violations == []


def test_plan_active_tool_and_full_args(tmp_path):
    reg = _write_registry(tmp_path, "active")
    out = tmp_path / "ffuf-out.json"
    plan, violations = fdc.build_ffuf_plan(
        "https://target.example.com/",
        output_path=out,
        registry_path=reg,
        root=tmp_path,
        wordlist_path=PROJECT_ROOT / "wordlists" / "ffuf_dirs_small.txt",
    )
    assert violations == []
    assert plan["executable"] is True
    assert plan["single_target"] is True and plan["recursion"] is False
    assert plan["args"][plan["args"].index("-t") + 1] == "1"
    assert plan["args"][plan["args"].index("-of") + 1] == "json"
    assert plan["args"][plan["args"].index("-delay") + 1] == "2"
    assert plan["wordlist"].endswith("ffuf_dirs_small.txt") and plan["wordlist_size"] >= 30


def test_plan_unavailable_tool_not_executable(tmp_path):
    reg = _write_registry(tmp_path, "unavailable")
    plan, _ = fdc.build_ffuf_plan(
        "https://target.example.com", output_path="o.json", registry_path=reg, root=tmp_path
    )
    assert plan["executable"] is False
    assert "unavailable" in plan["reason"]


@pytest.mark.parametrize(
    "target",
    [
        "https://a.example.com https://b.example.com",
        "ftp://target.example.com",
        "https://target.example.com/FUZZ",
        "https://target.example.com?a=1&b=2;rm",
        "file:///C:/Windows",
        "",
    ],
)
def test_plan_rejects_bad_targets(tmp_path, target):
    plan, violations = fdc.build_ffuf_plan(
        target, output_path=tmp_path / "o.json", registry_path=tmp_path / "nope.json"
    )
    assert violations
    assert plan["executable"] is False


def test_plan_rejects_low_delay_and_missing_wordlist(tmp_path):
    plan, violations = fdc.build_ffuf_plan(
        "https://target.example.com",
        output_path=tmp_path / "o.json",
        registry_path=tmp_path / "nope.json",
        wordlist_path=tmp_path / "missing.txt",
        delay_seconds=0.5,
    )
    assert any("ROE 下限" in v for v in violations)
    assert any("固定词表不存在" in v for v in violations)
    assert plan["delay_seconds"] == fdc.FFUF_MIN_DELAY_SECONDS
    assert plan["executable"] is False


def test_wordlist_file_matches_builtin_fallback():
    path = PROJECT_ROOT / "wordlists" / "ffuf_dirs_small.txt"
    words = tuple(w for w in path.read_text(encoding="utf-8").split() if w.strip())
    assert words == fdc.DEFAULT_FUZZ_DIRS
    assert len(words) == len(set(words))


# ---------- ingest：正例 ----------

def test_candidate_requires_baseline_and_semantics():
    rows, summary, violations = fdc.ingest_ffuf_results(
        [_result("backup")], dict(WILDCARD_BASELINE)
    )
    assert violations == []
    assert rows[0]["status"] == "candidate"
    assert rows[0]["evidence_kinds"] == ["baseline_differential", "semantic_sensitive_name"]
    assert summary["category_status"] == "tested"
    assert summary["status_counts"]["candidate"] == 1


# ---------- ingest：规格 13.2 负例 ----------

def test_generic_200_soft404_stays_signal():
    rows, _, violations = fdc.ingest_ffuf_results(
        [_result("admin", length=5120, words=700, lines=120)], dict(WILDCARD_BASELINE)
    )
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert "wildcard_soft404" in rows[0]["evidence_kinds"]
    assert "soft-404" in rows[0]["reason"]


def test_waf_403_and_429_are_negative():
    rows, _, violations = fdc.ingest_ffuf_results(
        [_result("admin", status=403), _result("backup", status=429)], dict(WILDCARD_BASELINE)
    )
    assert violations == []
    assert all(r["status"] == "signal" for r in rows)
    assert all("waf_or_rate_block" in r["evidence_kinds"] for r in rows)


def test_timeout_and_dns_errors_are_negative():
    rows, _, violations = fdc.ingest_ffuf_results(
        [_result("admin", status=0, error="timeout"),
         _result("backup", status=0, error="no such host")],
        dict(WILDCARD_BASELINE),
    )
    assert violations == []
    assert all(r["status"] == "signal" for r in rows)
    assert all("timeout_or_dns_error" in r["evidence_kinds"] for r in rows)


def test_no_baseline_fail_closed_all_signal():
    rows, summary, violations = fdc.ingest_ffuf_results([_result("backup"), _result("admin")])
    assert violations == []
    assert all(r["status"] == "signal" for r in rows)
    assert all(r["baseline_available"] is False for r in rows)
    assert summary["category_status"] == "inconclusive"


def test_differential_without_semantics_is_signal():
    rows, _s, violations = fdc.ingest_ffuf_results([_result("zzz-random")], dict(WILDCARD_BASELINE))
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert rows[0]["evidence_kinds"] == ["baseline_differential"]


def test_semantics_without_baseline_is_signal():
    rows, _s, violations = fdc.ingest_ffuf_results([_result("backup")])
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert rows[0]["evidence_kinds"] == ["semantic_sensitive_name"]


def test_login_page_path_is_negative():
    rows, _, violations = fdc.ingest_ffuf_results([_result("login")], dict(WILDCARD_BASELINE))
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert "login_page_path" in rows[0]["evidence_kinds"]


def test_body_false_positive_blocks_candidate():
    login_body = "<html><title>Login</title><form action='/login'><input name=password><input name=username>"
    rows, _, violations = fdc.ingest_ffuf_results(
        [_result("backup", text=login_body)], dict(WILDCARD_BASELINE)
    )
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert "body_false_positive_pattern" in rows[0]["evidence_kinds"]
    validator_violations = fdc.validate_ffuf_candidate(
        {**rows[0], "status": "candidate", "evidence_kinds": ["baseline_differential", "semantic_sensitive_name", "body_false_positive_pattern"]},
        label="neg",
    )
    assert any("负例证据形态" in v for v in validator_violations)


def test_duplicate_url_marked_duplicate():
    rows, _s, violations = fdc.ingest_ffuf_results(
        [_result("backup"), _result("backup")], dict(WILDCARD_BASELINE)
    )
    assert violations == []
    assert rows[0]["status"] == "candidate"
    assert rows[1]["status"] == "duplicate"


# ---------- ingest：输入缺失 / 非法 schema / 敏感数据 / 幂等 ----------

def test_invalid_rows_recorded_as_violations():
    rows, _s, violations = fdc.ingest_ffuf_results(
        ["not-a-dict", {"status": 200, "input": {"FUZZ": ""}}, {"url": "https://x.example.com/a"}]
    )
    assert rows and rows[-1]["url"] == "https://x.example.com/a"
    assert any("必须是键值映射" in v for v in violations)
    assert any("缺少 url 与 input.FUZZ" in v for v in violations)


def test_confirmed_never_produced_and_rejected_by_validator():
    rows, _s, _v = fdc.ingest_ffuf_results([_result("backup")], dict(WILDCARD_BASELINE))
    assert all(r["status"] != "confirmed" for r in rows)
    violations = fdc.validate_ffuf_candidate({**rows[0], "status": "confirmed"}, label="neg")
    assert any("confirmed 永不由 ffuf ingest 产生" in v for v in violations)


def test_candidate_without_evidence_ref_rejected():
    row = {
        "candidate_id": "ffufdir-0001",
        "status": "candidate",
        "evidence_kinds": ["baseline_differential", "semantic_sensitive_name"],
        "url": "https://t.example.com/backup",
        "evidence_ref": "",
    }
    assert any("evidence_ref 为空" in v for v in fdc.validate_ffuf_candidate(row, label="neg"))


def test_sensitive_body_content_not_copied_to_rows():
    leak = "Set-Cookie: session=abc123; Authorization: Bearer tok999 password=secret42"
    rows, _s, violations = fdc.ingest_ffuf_results([_result("backup", text=leak)], dict(WILDCARD_BASELINE))
    assert violations == []
    blob = json.dumps(rows, ensure_ascii=False)
    assert "abc123" not in blob and "tok999" not in blob and "secret42" not in blob


def test_ingest_is_idempotent():
    results = [_result("backup"), _result("admin"), _result("zzz-random")]
    first = fdc.ingest_ffuf_results(results, dict(WILDCARD_BASELINE))
    second = fdc.ingest_ffuf_results(results, dict(WILDCARD_BASELINE))
    assert first == second


def test_summary_reuses_single_engine():
    _rows, summary, violations = fdc.ingest_ffuf_results([_result("backup")], dict(WILDCARD_BASELINE))
    assert violations == []
    assert set(summary["status_counts"]) == set(ic.CANDIDATE_STATUS_VALUES)
    assert summary["tested_count"] == sum(
        summary["status_counts"][s] for s in ic.DEFINITIVE_RESULT_STATUSES
    )
