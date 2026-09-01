"""tests/test_miniapp_storage_strategy.py —— tool_strategy.json 三个 xcx 存储/包
完整性 phase 条目锁定（batch11_4，实施规格 6.3/6.6 + 6.2 拆分）。

证明链（test_miniapp_auth_strategy.py 同构）：
  ① 三条目形态锁定（primary/backup/backup_mode 四字段 + 阶段名与
     miniapp_storage_package_schema.phases 精确对齐）；
  ② primary 引用 manual_ 前缀逻辑名（registry INTERNAL_REFERENCE_PREFIXES 放行
     形态），不引用任何探测工具名（不变成主动扫描器）；
  ③ notes 红线关键词锁定（离线复核/材料来源/不做重打包篡改绕过 pinning/
     不读取凭证文件不导出敏感值/secret_candidate 红线/confirmed 五门/
     duplicate_execution=false）；
  ④ artifact 路径与契约一致 + 模块引用在 notes 留痕；
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
    (ROOT / "contracts" / "miniapp_storage_package_schema.json").read_text(encoding="utf-8-sig")
)

STORAGE_PACKAGE_PHASES = (
    "package_integrity_update_review",
    "local_data_exposure",
    "crypto_and_secret_handling",
)

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
    "package_integrity_update_review": (
        "Spec 6.3",
        "package_version_inventory",
        "trusted_update_config",
        "operator-supplied package copies",
        "never repacks, tampers with, bypasses pinning, or attacks the device",
        "operator-supplied authorization material or local traffic",
        "miniapp_storage_package_schema",
        "five finding gates",
        "duplicate_execution=false",
    ),
    "local_data_exposure": (
        "Spec 6.6",
        "token_persistence",
        "temp_files",
        "no credential files are read",
        "no sensitive values are copied",
        "miniapp_storage_package_schema",
        "five finding gates",
        "duplicate_execution=false",
    ),
    "crypto_and_secret_handling": (
        "Spec 6.6",
        "hardcoded_secrets",
        "debug_config_env_keys",
        "secret_candidate red line",
        "never a key-leak finding",
        "No key validity probing",
        "no credential files",
        "miniapp_storage_package_schema",
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
    "package_integrity_update_review": (
        ROOT / "src" / "authorized_assessment" / "miniapp" / "package_integrity_update.py",
    ),
    "local_data_exposure": (
        ROOT / "src" / "authorized_assessment" / "miniapp" / "local_data_exposure.py",
    ),
    "crypto_and_secret_handling": (
        ROOT / "src" / "authorized_assessment" / "miniapp" / "crypto_secret_review.py",
    ),
}


def _strategy() -> dict:
    return json.loads(STRATEGY.read_text(encoding="utf-8-sig"))


def test_three_storage_package_phase_entries_present_and_aligned():
    strategy = _strategy()
    for phase in STORAGE_PACKAGE_PHASES:
        entry = strategy["phases"].get(phase)
        assert isinstance(entry, dict), phase
        assert phase in CONTRACT["phases"], phase
        for field in ("primary", "backup", "backup_mode", "notes"):
            assert str(entry.get(field, "")).strip(), (phase, field)


def test_primary_uses_manual_prefix_and_no_probe_tools():
    strategy = _strategy()
    for phase in STORAGE_PACKAGE_PHASES:
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
