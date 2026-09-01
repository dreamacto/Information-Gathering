"""tool_strategy.json application_mapping 策略条目测试（batch5_2，实施规格 5.1/5.2 + 7.1）。

锁定：
  - phases.application_mapping 条目存在且结构完整（primary/backup/backup_mode/notes）；
  - primary/backup 引用名通过 registry 交叉校验形态（内部前缀/根脚本/已登记 tool_id），
    整份 tool_strategy.json 在真实 registry 下零违例（rebuild_tool_inventory.py --check
    同口径，直接调用 registry.check_tool_strategy_references）；
  - notes 文档契约：五子阶段、六状态、7 字段行、artifacts/application-map/ 产物路径、
    适用性优先规则全部写明（策略条目是该阶段的唯一事实源，文档缺失 = 下个会话丢上下文）；
  - AGENT_MANIFEST.md 由生成器再生后含 application_mapping 渲染段。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from authorized_assessment.tools import registry  # noqa: E402

STRATEGY_PATH = ROOT / "tool_strategy.json"
REGISTRY_PATH = ROOT / "tools" / "tool_registry.json"
MANIFEST_PATH = ROOT / "AGENT_MANIFEST.md"

SUBPHASES = (
    "graphql_mapping",
    "websocket_mapping",
    "file_surface_mapping",
    "auth_surface_mapping",
    "webhook_mapping",
)


@pytest.fixture(scope="module")
def strategy() -> dict:
    return json.loads(STRATEGY_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def reg() -> dict:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def test_application_mapping_entry_exists_and_complete(strategy: dict) -> None:
    entry = strategy["phases"]["application_mapping"]
    for field in ("primary", "backup", "backup_mode", "notes"):
        assert isinstance(entry.get(field), str) and entry[field].strip(), f"missing {field}"


def test_all_strategy_references_pass_registry_crosscheck(strategy: dict, reg: dict) -> None:
    """与 rebuild_tool_inventory.py --check 同口径：真实 registry 下零违例。"""
    violations = registry.check_tool_strategy_references(reg, strategy, ROOT)
    assert violations == []


def test_application_mapping_primary_is_internal_reference_form(strategy: dict) -> None:
    """primary 为编排内人工/AI 动作形态（manual_ 前缀），不伪装成外部可执行工具。"""
    entry = strategy["phases"]["application_mapping"]
    assert entry["primary"].lower().startswith(registry.INTERNAL_REFERENCE_PREFIXES)


def test_application_mapping_backup_references_root_script(strategy: dict) -> None:
    """backup 复用 crawl_api_js 既有根脚本组合（api_discovery.py），不引入新工具。"""
    entry = strategy["phases"]["application_mapping"]
    assert "api_discovery.py" in entry["backup"].lower()
    assert (ROOT / "api_discovery.py").is_file()


def test_application_mapping_notes_document_subphase_contract(strategy: dict) -> None:
    notes = strategy["phases"]["application_mapping"]["notes"].lower()
    for subphase in SUBPHASES:
        assert subphase in notes, f"notes missing subphase {subphase}"
    for token in (
        "artifacts/application-map/",
        "graphql-manifest.json",
        "websocket-inventory.csv",
        "file-surface-inventory.csv",
        "auth-surface-inventory.csv",
        "webhook-inventory.csv",
        "phase_status.json",
        "substatuses",
        "applicability first",
        "not_applicable",
    ):
        assert token in notes, f"notes missing contract token {token!r}"


def test_manifest_renders_application_mapping_phase() -> None:
    """AGENT_MANIFEST.md 由 gen_agent_manifest.py 再生（batch5_2 执行时重跑），含新 phase。"""
    text = MANIFEST_PATH.read_text(encoding="utf-8")
    assert "### application_mapping" in text
    assert "manual_browser_or_proxy" in text
    assert "artifacts/application-map/" in text
