"""tests/test_static_analysis_signals.py —— batch16_4 专属测试。

正例：semgrep --json 命中 → sink/source/path/上下文 signal 行。
规格 13.2 负例：静态命中不可升 candidate/confirmed（只有静态 sink、无可达链路）；
plan 负例：auto/p//r//registry/http(s) 远程规则拒绝、本地路径不存在、工具未登记。
敏感数据过滤例（摘录敏感值丢弃、凭证键拒绝）+ 幂等 + 去重 + errors 进违例。
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from authorized_assessment.analysis import static_analysis_signals as sas  # noqa: E402


def _hit(check_id: str = "js.hardcoded-eval", path: str = "app/js/api.js", line: int = 42, **extra_overrides) -> dict:
    extra = {
        "message": "Detected eval() usage",
        "severity": "WARNING",
        "lines": "  eval(userInput);",
    }
    extra.update(extra_overrides)
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 5},
        "end": {"line": line, "col": 20},
        "extra": extra,
    }


# ---------- plan ----------

def test_plan_local_rules_and_metrics_off():
    rules = PROJECT_ROOT / "wordlists"  # 任一本地目录形态
    plan, violations = sas.build_semgrep_plan(
        PROJECT_ROOT, rules, output_path="semgrep-out.json",
        registry_path=PROJECT_ROOT / "tools" / "tool_registry.json",
    )
    assert violations == []
    assert plan["metrics_off"] is True and plan["rules_local_only"] is True
    assert "--metrics=off" in plan["args"] and "--json" in plan["args"]
    assert plan["args"][plan["args"].index("--config") + 1] == str(rules)
    assert plan["executable"] is False  # 真实 registry 未登记 semgrep


def test_plan_rejects_remote_rule_sources(tmp_path):
    for config in ("auto", "p/owasp-top-ten", "r/java", "registry", "https://x.example.com/rules.yml"):
        _plan, violations = sas.build_semgrep_plan(
            PROJECT_ROOT, config, output_path=tmp_path / "o.json"
        )
        assert any("禁用来源" in v or "本地路径" in v for v in violations), f"config={config!r}"


def test_plan_rejects_missing_rules_or_source(tmp_path):
    _plan, violations = sas.build_semgrep_plan(
        PROJECT_ROOT, tmp_path / "no-such-rules", output_path=tmp_path / "o.json"
    )
    assert any("不存在" in v for v in violations)
    _plan2, violations2 = sas.build_semgrep_plan(
        tmp_path / "no-such-src", tmp_path / "rules", output_path=tmp_path / "o.json"
    )
    assert any("不存在" in v for v in violations2)


# ---------- ingest：正例 ----------

def test_hit_becomes_signal_with_location_and_context():
    payload = {"results": [_hit()], "errors": []}
    rows, summary, violations = sas.ingest_semgrep_results(
        payload, evidence_ref="runs/x/semgrep-out.json"
    )
    assert violations == []
    assert rows[0]["status"] == "signal"
    assert rows[0]["check_id"] == "js.hardcoded-eval"
    assert rows[0]["path"] == "app/js/api.js" and rows[0]["start_line"] == 42
    assert rows[0]["context"] == "  eval(userInput);"
    assert rows[0]["evidence_ref"] == "runs/x/semgrep-out.json"
    assert "可触达" in rows[0]["reason"]
    assert summary["category_status"] == "inconclusive"  # 全 signal 无 definitive


# ---------- ingest：规格 13.2 负例 ----------

def test_static_hit_never_candidate_or_confirmed():
    rows, _s, _v = sas.ingest_semgrep_results({"results": [_hit()], "errors": []})
    assert all(r["status"] == "signal" for r in rows)
    for bad in ("candidate", "confirmed"):
        violations = sas.validate_static_signal({**rows[0], "status": bad}, label="neg")
        assert any("不能自动变成漏洞" in v for v in violations)


def test_duplicate_hits_marked_duplicate():
    payload = {"results": [_hit(), _hit()], "errors": []}
    rows, _s, violations = sas.ingest_semgrep_results(payload)
    assert violations == []
    assert rows[0]["status"] == "signal" and rows[1]["status"] == "duplicate"


def test_errors_listed_as_violations():
    payload = {"results": [], "errors": [{"message": "parse error in rule"}]}
    _rows, _s, violations = sas.ingest_semgrep_results(payload)
    assert any("parse error" in str(v) for v in violations)


def test_unlocatable_hits_rejected():
    payload = {"results": [{"check_id": "", "path": "", "start": {}}], "errors": []}
    _rows, _s, violations = sas.ingest_semgrep_results(payload)
    assert any("缺少 check_id/path/start.line" in v for v in violations)


def test_non_dict_input_rejected():
    rows, summary, violations = sas.ingest_semgrep_results(42)
    assert rows == [] and summary == {}
    assert any("必须是 JSON object" in v for v in violations)


# ---------- 敏感数据过滤 ----------

def test_excerpt_with_secret_is_dropped():
    payload = {"results": [_hit(lines='  const c = new AWS.Config({secretKey: "abcd"});')], "errors": []}
    rows, _s, violations = sas.ingest_semgrep_results(payload)
    assert rows[0]["context"] == ""
    assert any("敏感值" in v for v in violations)


def test_credential_like_keys_rejected():
    payload = {"results": [_hit(password_field="x")], "errors": []}
    _rows, _s, violations = sas.ingest_semgrep_results(payload)
    assert any("credential" in v.lower() for v in violations)


# ---------- 幂等 ----------

def test_ingest_is_idempotent():
    payload = {"results": [_hit(), _hit("python.pyyaml-load", path="a.py", line=7)], "errors": []}
    first = sas.ingest_semgrep_results(payload, evidence_ref="e.json")
    second = sas.ingest_semgrep_results(payload, evidence_ref="e.json")
    assert first == second
