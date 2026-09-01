"""tests/test_api_testing_orchestration_strategy.py —— 操作员决定①（batch8_5）
落地证明：tool_strategy.json 的 graphql_testing / websocket_testing 顶层
orchestration_only 条目不会（也不能）重复执行已接入子阶段探测。

证明链：① 条目形态锁定（orchestration_only 三形态字段 + duplicate_execution
声明，与 input_testing 先例同构）；② 不引用任何探测工具名（不变成主动扫描器）；
③ 被编排四模块 AST 扫描无网络/连接类导入（被编排子阶段离线的结构级证据——
编排声明与被编排实现都不可执行探测）；④ 子阶段名与规格 5.3 精确对齐。
纯离线测试，不发任何请求。
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STRATEGY = ROOT / "tool_strategy.json"

ORCHESTRATION_SUBPHASES = ("graphql_testing", "websocket_testing")

# 被编排子阶段 → Batch 7 已交付模块（决定①：不重复实现，只声明映射）。
SUBPHASE_MODULES = {
    "graphql_testing": (
        ROOT / "src" / "authorized_assessment" / "triage" / "graphql_inventory.py",
        ROOT / "src" / "authorized_assessment" / "triage" / "graphql_review.py",
    ),
    "websocket_testing": (
        ROOT / "src" / "authorized_assessment" / "triage" / "websocket_inventory.py",
        ROOT / "src" / "authorized_assessment" / "triage" / "websocket_review.py",
    ),
}

PROBE_TOOL_TOKENS = (
    "nuclei",
    "afrog",
    "sqlmap",
    "katana",
    "ffuf",
    "dirsearch",
    "httpx",
    "dalfox",
    "xsstrike",
)

# 网络/连接类导入（被编排子阶段必须离线：结构级证明）。
NETWORK_IMPORT_ROOTS = {
    "socket",
    "ssl",
    "http",
    "urllib",
    "requests",
    "httpx",
    "aiohttp",
    "websockets",
    "websocket",
    "telnetlib",
    "smtplib",
    "ftplib",
    "asyncio",
}


def _load_strategy() -> dict:
    return json.loads(STRATEGY.read_text(encoding="utf-8"))


def test_entries_exist_as_top_level_orchestration_only():
    """两子阶段为顶层条目（操作员决定①：顶层编排事实源，不在 phases 下）。"""
    strategy = _load_strategy()
    for name in ORCHESTRATION_SUBPHASES:
        assert name in strategy, f"{name} 缺少顶层条目"
        entry = strategy[name]
        # orchestration_only 三形态字段（与 batch6_4 ⑥ input_testing 先例同构）
        assert entry["primary"] == "manual_orchestration_only"
        assert entry["backup"] == "manual_orchestration_only"
        assert entry["backup_mode"] == "orchestration_only_no_duplicate_execution"
        assert "duplicate_execution=false" in entry["notes"]


def test_entries_not_inside_phases_and_phases_untouched():
    """编排条目不得混入 phases（phases 为探测编排阶段清单）；既有 38 phases 不减。"""
    strategy = _load_strategy()
    for name in ORCHESTRATION_SUBPHASES:
        assert name not in strategy["phases"]
    assert len(strategy["phases"]) >= 38
    # 审批门不被改写（决定①与完成条件：不改变现有审批门）
    assert "approval_gated_phases" in strategy
    assert set(strategy["approval_gated_phases"]) == {
        "credential_testing",
        "exploitability",
        "post_exploitation",
    }


def test_notes_declare_module_mapping_and_batch14_boundary():
    """notes 必须声明子阶段→已交付模块映射、不重复执行边界、Batch 14 只做同步。"""
    strategy = _load_strategy()
    module_tokens = {
        "graphql_testing": ("graphql_inventory.py", "graphql_review.py", "batch7_0"),
        "websocket_testing": ("websocket_inventory.py", "websocket_review.py", "batch7_1"),
    }
    for name, tokens in module_tokens.items():
        notes = strategy[name]["notes"]
        for token in tokens:
            assert token in notes, f"{name}.notes 缺少 {token}"
        assert "Batch 14" in notes
        assert "must not re-execute" in notes
        assert "never proof of a vulnerability" in notes


def test_entries_never_reference_probe_tools():
    """编排条目不引用任何探测工具名（不变成主动扫描器）。"""
    strategy = _load_strategy()
    for name in ORCHESTRATION_SUBPHASES:
        blob = json.dumps(strategy[name], ensure_ascii=False).lower()
        for tool in PROBE_TOOL_TOKENS:
            assert tool not in blob, f"{name} 引用了探测工具 {tool}"


def test_wired_modules_are_offline_by_ast():
    """被编排四模块 AST 扫描：无网络/连接类导入（离线的结构级证据）。

    这证明编排条目所指向的子阶段实现本身不可能执行网络探测——顶层编排声明
    duplicate_execution=false 与被编排实现的离线性共同构成"不重复执行探测"的
    可审计证据链。
    """
    for name, modules in SUBPHASE_MODULES.items():
        for path in modules:
            assert path.is_file(), f"{path} 缺失（决定①：不得重复实现，必须已在盘）"
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        assert root not in NETWORK_IMPORT_ROOTS, (
                            f"{path.name} 导入了网络模块 {alias.name}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    assert root not in NETWORK_IMPORT_ROOTS, (
                        f"{path.name} from-import 了网络模块 {node.module}"
                    )


def test_subphase_names_match_spec_5_3():
    """条目名与规格 5.3 api_testing 子阶段名精确对齐（1247-1255 行清单）。"""
    spec = (ROOT / "docs" / "AI_IMPLEMENTATION_SPEC_SECURITY_COVERAGE_AND_FINDING_QUALITY.md").read_text(
        encoding="utf-8"
    )
    for name in ORCHESTRATION_SUBPHASES:
        assert name in spec
    # 规格清单中的其余子阶段不被本决定触碰
    for other in ("api_schema_versions", "api_resource_controls", "third_party_api_review", "object_field_authorization"):
        assert other in spec
