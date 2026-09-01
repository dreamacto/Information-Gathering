"""tests/test_passive_subdomain_candidates.py —— batch16_3 专属测试。

正例：scope 后缀命中 → in_scope；CT 缓存导入行处理。
规格 7.2 负例：未命中 scope → confirmation_required（不直接纳入扫描）；
scope 缺失 fail-closed 全 confirmation_required；confirmation_required 不进
dnsx 清单；-active/-w 禁入计划；未登记工具 fail-closed；非法域名拒绝。
幂等 + 去重 + 非法行。
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from authorized_assessment.discovery import passive_subdomain_candidates as psc  # noqa: E402

SCOPE = ["example.com", "authorized-target.cn"]


# ---------- plan：subfinder ----------

def test_subfinder_plan_passive_minimal_flags():
    plan, violations = psc.plan_subfinder(
        "example.com", output_path="subfinder-out.txt",
        registry_path=PROJECT_ROOT / "tools" / "tool_registry.json",
    )
    assert violations == []
    assert plan["passive_only"] is True and plan["single_domain"] is True
    # batch16_6 起 subfinder 已显式登记 unavailable（未下载）
    assert plan["tool_status"] == "unavailable"
    assert plan["executable"] is False
    for flag in psc.SUBFINDER_FORBIDDEN_FLAGS:
        assert flag not in plan["args"]
    assert plan["args"][plan["args"].index("-d") + 1] == "example.com"


def test_subfinder_plan_forbidden_flags_never_present(tmp_path):
    plan, _v = psc.plan_subfinder("example.com", output_path=tmp_path / "o.txt")
    assert not any(str(a).lower() in ("-active", "--active") for a in plan["args"])


def test_subfinder_plan_rejects_bad_domain():
    for domain in ("", "https://example.com/x", "a b.example.com", "exa mple.com", ".."):
        _plan, violations = psc.plan_subfinder(domain, output_path="o.txt")
        assert violations, f"domain={domain!r} 应被拒绝"


def test_subfinder_plan_active_tool(tmp_path):
    binary = tmp_path / "subfinder.exe"
    binary.write_bytes(b"stub")
    reg = tmp_path / "tool_registry.json"
    import json

    reg.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "tools": [
                    {
                        "tool_id": "subfinder",
                        "display_name": "subfinder",
                        "path": str(binary),
                        "version": "2.6.7",
                        "status": "active",
                        "runtime": "native",
                        "dependencies": [],
                        "known_limitations": "仅被动模式；-active 禁用",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    plan, violations = psc.plan_subfinder(
        "Example.COM.", output_path=tmp_path / "o.txt", registry_path=reg, root=tmp_path
    )
    assert violations == []
    assert plan["executable"] is True
    assert plan["domain"] == "example.com"  # 归一化：去尾点、小写


# ---------- plan：dnsx ----------

def test_dnsx_plan_known_candidate_list_mode(tmp_path):
    candidates = tmp_path / "known.txt"
    candidates.write_text("a.example.com\nb.example.com\n\n", encoding="utf-8")
    plan, violations = psc.plan_dnsx(
        candidates, output_path=tmp_path / "dnsx-out.txt",
        registry_path=PROJECT_ROOT / "tools" / "tool_registry.json",
    )
    assert violations == []
    assert plan["mode"] == "known_candidate_resolution"
    assert plan["candidate_count"] == 2
    assert plan["args"][plan["args"].index("-l") + 1] == str(candidates)
    for flag in psc.DNSX_FORBIDDEN_FLAGS:
        assert flag not in plan["args"]


def test_dnsx_plan_rejects_invalid_lines_and_missing_file(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("a.example.com\nnot a domain\nhttps://x.com\n", encoding="utf-8")
    _plan, violations = psc.plan_dnsx(bad, output_path=tmp_path / "o.txt")
    assert len(violations) >= 2
    _plan2, violations2 = psc.plan_dnsx(tmp_path / "missing.txt", output_path=tmp_path / "o.txt")
    assert any("不存在" in v for v in violations2)


# ---------- ingest：scope 门控 ----------

def _results() -> list[dict]:
    return [
        {"host": "app.example.com", "source": "crtsh"},
        {"host": "api.example.com", "source": "ct_cache_import"},
        {"host": "unrelated-other.net", "source": "hackertarget"},
        {"host": "app.example.com", "source": "crtsh"},
    ]


def test_scope_match_deterministic():
    assert psc.scope_match("app.example.com", SCOPE)
    assert psc.scope_match("example.com", SCOPE)
    assert psc.scope_match("EXAMPLE.com.", SCOPE)
    assert not psc.scope_match("evilexample.com", SCOPE)
    assert not psc.scope_match("example.com.evil.io", SCOPE)
    assert not psc.scope_match("unrelated-other.net", SCOPE)


def test_ingest_dispositions_in_scope_and_confirmation_required():
    rows, summary, violations = psc.ingest_passive_results(_results(), SCOPE)
    assert violations == []
    assert rows[0]["disposition"] == "in_scope"
    assert rows[1]["disposition"] == "in_scope"
    assert rows[2]["disposition"] == "confirmation_required"
    assert "所有权确认" in rows[2]["reason"]
    assert rows[3]["disposition"] == "duplicate"
    assert summary["disposition_counts"]["in_scope"] == 2
    assert summary["disposition_counts"]["confirmation_required"] == 1


def test_missing_scope_fail_closed_all_confirmation_required():
    rows, summary, _v = psc.ingest_passive_results(_results()[:3], None)
    assert all(r["disposition"] == "confirmation_required" for r in rows)
    assert summary["scope_provided"] is False
    rows2, _s2, _v2 = psc.ingest_passive_results(_results()[:3], [])
    assert all(r["disposition"] == "confirmation_required" for r in rows2)


def test_evil_suffix_do_not_match_scope():
    rows, _s, _v = psc.ingest_passive_results(
        [{"host": "evilexample.com", "source": "ct"}, {"host": "example.com.evil.io", "source": "ct"}],
        SCOPE,
    )
    assert all(r["disposition"] == "confirmation_required" for r in rows)


def test_invalid_rows_recorded():
    _rows, _s, violations = psc.ingest_passive_results(
        ["not-a-dict", {"source": "ct"}, {"host": "bad host", "source": "ct"}], SCOPE
    )
    assert any("必须是键值映射" in v for v in violations)
    assert any("缺少 host" in v for v in violations)
    assert any("非法字符" in v for v in violations)


# ---------- filter：confirmation_required 不进解析清单 ----------

def test_filter_only_in_scope_hosts_pass():
    rows, _s, _v = psc.ingest_passive_results(_results(), SCOPE)
    allowed, notes = psc.filter_known_candidates(rows)
    assert allowed == ["api.example.com", "app.example.com"]
    assert notes and "2 行非 in_scope" in notes[0]


def test_filter_empty_input():
    allowed, notes = psc.filter_known_candidates([])
    assert allowed == [] and notes == []


# ---------- 幂等 ----------

def test_ingest_is_idempotent():
    first = psc.ingest_passive_results(_results(), SCOPE)
    second = psc.ingest_passive_results(_results(), SCOPE)
    assert first == second
