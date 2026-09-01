"""tool_strategy.json ssrf_candidate_screening 策略条目测试（batch6_2，规格 5.4 SSRF 小节 + 7.1）。

沿用 batch5_2（tests/test_application_mapping_strategy.py）模式：
  - phases.ssrf_candidate_screening 条目存在且结构完整（primary/backup/backup_mode/notes）；
  - 引用名通过 registry 交叉校验（整份 tool_strategy.json 真实 registry 下零违例）；
  - notes 文档契约：分析面词表、六状态、10 字段汇总、artifacts/ssrf/ 产物路径、
    POST 不自动探测、不使用公共 OAST、OOB/内网/写入均为审批门；
  - AGENT_MANIFEST.md 由生成器再生后含 ssrf_candidate_screening 渲染段。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from authorized_assessment.tools import registry

ROOT = Path(__file__).resolve().parents[1]
STRATEGY_PATH = ROOT / "tool_strategy.json"
MANIFEST_PATH = ROOT / "AGENT_MANIFEST.md"


@pytest.fixture(scope="module")
def strategy() -> dict:
    return json.loads(STRATEGY_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def reg() -> dict:
    return json.loads((ROOT / "tools" / "tool_registry.json").read_text(encoding="utf-8"))


def test_ssrf_entry_exists_and_complete(strategy: dict) -> None:
    entry = strategy["phases"]["ssrf_candidate_screening"]
    for field in ("primary", "backup", "backup_mode", "notes"):
        assert isinstance(entry.get(field), str) and entry[field].strip(), f"missing {field}"


def test_all_strategy_references_pass_registry_crosscheck(strategy: dict, reg: dict) -> None:
    violations = registry.check_tool_strategy_references(reg, strategy, ROOT)
    assert violations == []


def test_ssrf_backup_references_existing_root_script(strategy: dict) -> None:
    """backup 复用根目录 ssrf_triage.py（既有探测器，不重复造轮子）。"""
    entry = strategy["phases"]["ssrf_candidate_screening"]
    assert "ssrf_triage.py" in entry["backup"].lower()
    assert (ROOT / "ssrf_triage.py").is_file()


def test_ssrf_notes_document_contract(strategy: dict) -> None:
    notes = strategy["phases"]["ssrf_candidate_screening"]["notes"].lower()
    for token in (
        "artifacts/ssrf/",
        "ssrf_candidates.jsonl",
        "ssrf_review_queue.csv",
        "oob_token_manifest.json",
        "wordlists/ssrf_params.txt",
        "not_applicable",
        "post",
        "oob",
        "public oast",
        "approval",
    ):
        assert token in notes, f"notes missing contract token {token!r}"


def test_manifest_renders_ssrf_phase() -> None:
    text = MANIFEST_PATH.read_text(encoding="utf-8")
    assert "### ssrf_candidate_screening" in text
    assert "artifacts/ssrf/" in text


# ---------------------------------------------------------------------------
# batch6_4 决定⑥：input_testing orchestration_only 条目
# ---------------------------------------------------------------------------

def test_input_testing_entry_exists_and_complete(strategy: dict) -> None:
    entry = strategy["phases"]["input_testing"]
    for field in ("primary", "backup", "backup_mode", "notes"):
        assert isinstance(entry.get(field), str) and entry[field].strip(), f"missing {field}"


def test_input_testing_is_orchestration_only(strategy: dict) -> None:
    """primary/backup 必须是编排形态（manual_orchestration_only），不引用具体探测工具。"""
    entry = strategy["phases"]["input_testing"]
    assert entry["primary"].strip() == "manual_orchestration_only"
    assert entry["backup"].strip() == "manual_orchestration_only"
    assert "orchestration_only" in entry["backup_mode"]
    for probe_tool in ("sqli_triage", "xss_candidate_triage", "ssrf_triage", "sqlmap"):
        assert probe_tool.lower() not in entry["primary"].lower()
        assert probe_tool.lower() not in entry["backup"].lower()


def test_input_testing_notes_document_contract(strategy: dict) -> None:
    notes = strategy["phases"]["input_testing"]["notes"].lower()
    for token in (
        "orchestration-only",
        "injection_candidate_screening",
        "parser_deserialization_screening",
        "ssrf_candidate_screening",
        "file_path_candidate_screening",
        "browser_boundary_review",
        "artifacts/input-testing/",
        "artifacts/ssrf/",
        "audit_input_testing",
        "never proof of a vulnerability",
    ):
        assert token in notes, f"notes missing contract token {token!r}"
    assert "must not re-execute" in notes


def test_manifest_renders_input_testing_phase() -> None:
    text = MANIFEST_PATH.read_text(encoding="utf-8")
    assert "### input_testing" in text
    assert "manual_orchestration_only" in text
