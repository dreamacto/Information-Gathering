"""tests/test_miniapp_auth_strategy.py —— tool_strategy.json 三个 xcx 认证 phase
条目锁定（batch10_4，实施规格 6.5 + 6.2 认证拆分）。

证明链（test_api_testing_orchestration_strategy.py 同构）：
  ① 三条目形态锁定（primary/backup/backup_mode 四字段 + 阶段名与
     miniapp_auth_schema.phases 精确对齐）；
  ② primary 引用 manual_ 前缀逻辑名（registry INTERNAL_REFERENCE_PREFIXES 放行
     形态），不引用任何探测工具名（不变成主动扫描器）；
  ③ notes 红线关键词锁定（离线复核/授权材料来源/不自动创建或滥用登录凭证/
     signature_replay 不自动重放+写操作与并发验证归审批门/confirmed 五门/
     duplicate_execution=false）；
  ④ artifact 路径与契约一致；
  ⑤ 被编排三模块 AST 离线证明（无网络/连接类导入——编排声明与被编排实现都
     不可执行探测）。

纯离线测试，不发任何请求。
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STRATEGY = ROOT / "tool_strategy.json"
CONTRACT = json.loads(
    (ROOT / "contracts" / "miniapp_auth_schema.json").read_text(encoding="utf-8-sig")
)

AUTH_PHASES = ("platform_login_exchange", "session_token_lifecycle", "signature_replay")

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
    "ShiroAttack2",
    "SpringBoot-Scan",
    "hydra",
)

REQUIRED_NOTE_MARKERS = {
    "platform_login_exchange": (
        "Spec 6.5",
        "login_code_one_time",
        "openid_authorization_basis",
        "operator-supplied authorization material or local traffic",
        "never auto-create or abuse login credentials",
        "OpenID/AppID are not authorization",
        "miniapp_auth_schema",
        "five finding gates",
        "duplicate_execution=false",
    ),
    "session_token_lifecycle": (
        "Spec 6.5",
        "token_rotation",
        "device_user_tenant_binding",
        "operator-supplied authorization material or local traffic",
        "no automatic login",
        "approval-gated",
        "miniapp_auth_schema",
        "five finding gates",
        "duplicate_execution=false",
    ),
    "signature_replay": (
        "Spec 6.5",
        "nonce_timestamp",
        "binding_scope",
        "Never auto-replays any request",
        "approval-gated",
        "operator-supplied authorization material or local traffic",
        "miniapp_auth_schema",
        "five finding gates",
        "duplicate_execution=false",
    ),
}

# 网络/连接类导入（被编排模块必须离线：结构级证明）。
NETWORK_IMPORT_ROOTS = {
    "socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp",
    "websockets", "websocket", "telnetlib", "smtplib", "ftplib",
    "asyncio", "threading", "concurrent", "multiprocessing", "subprocess",
}

STRATEGY_MODULES = {
    "platform_login_exchange": (
        ROOT / "src" / "authorized_assessment" / "miniapp" / "platform_login_exchange.py",
    ),
    "session_token_lifecycle": (
        ROOT / "src" / "authorized_assessment" / "miniapp" / "session_token_lifecycle.py",
    ),
    "signature_replay": (
        ROOT / "src" / "authorized_assessment" / "miniapp" / "signature_replay_review.py",
    ),
}


def _strategy() -> dict:
    return json.loads(STRATEGY.read_text(encoding="utf-8-sig"))


def test_three_auth_phase_entries_present_and_aligned():
    strategy = _strategy()
    for phase in AUTH_PHASES:
        entry = strategy["phases"].get(phase)
        assert isinstance(entry, dict), phase
        assert phase in CONTRACT["phases"], phase
        for field in ("primary", "backup", "backup_mode", "notes"):
            assert str(entry.get(field, "")).strip(), (phase, field)


def test_primary_uses_manual_prefix_and_no_probe_tools():
    strategy = _strategy()
    for phase in AUTH_PHASES:
        entry = strategy["phases"][phase]
        assert entry["primary"].startswith("manual_"), (
            "primary 必须是 manual_ 前缀逻辑名（registry 放行形态）"
        )
        assert entry["backup"] == "manual_review"
        for token in PROBE_TOOL_TOKENS:
            assert token.lower() not in entry["primary"].lower(), (phase, token)
            assert token.lower() not in entry["backup"].lower(), (phase, token)


def test_notes_carry_redline_markers():
    strategy = _strategy()
    for phase, markers in REQUIRED_NOTE_MARKERS.items():
        notes = strategy["phases"][phase]["notes"]
        for marker in markers:
            assert marker in notes, (phase, marker)


def test_notes_artifact_paths_match_contract():
    strategy = _strategy()
    for phase, spec in CONTRACT["phases"].items():
        assert spec["artifact"] in strategy["phases"][phase]["notes"], phase
        module_name = STRATEGY_MODULES[phase][0].name
        module_ref = f"src/authorized_assessment/miniapp/{module_name}"
        assert module_ref in strategy["phases"][phase]["notes"], phase


def test_orchestrated_modules_are_offline_by_ast():
    """被编排三模块 AST 扫描：无网络/连接/并发/子进程类导入。"""
    for phase, modules in STRATEGY_MODULES.items():
        for module_path in modules:
            tree = ast.parse(module_path.read_text(encoding="utf-8"))
            imported: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported += [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.append(node.module)
            violations = [
                name for name in imported if name.split(".")[0] in NETWORK_IMPORT_ROOTS
            ]
            assert violations == [], (phase, module_path.name, violations)
