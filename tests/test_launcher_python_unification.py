"""tests/test_launcher_python_unification.py —— Batch 4 / 规格 7.4 launcher 与 Python 统一。

覆盖：
  - 4 个主 launcher 的 Python 选择顺序统一：项目 .venv → 天狐（登记兼容运行时）→
    codex（外部兼容回退）→ PATH python；
  - 一键完整流程 launcher 括号平衡（规格点名的孤立 `)` 不得回归）；
  - 并行分批 launcher 无 PROJECT_PY 死代码残留；
  - 保守 launcher 的 --subdomain-concurrency 明确标注 DNS 专项预算；
  - gov_exercise_config.json 并发预算分项（dns/http/cross_host）与 python_fallbacks；
  - collect_runtime_inventory 记录的 python 与 launcher 实际启动解释器一致（.venv 首位）。
"""
from __future__ import annotations

import json
from pathlib import Path

from authorized_assessment.runtime.runtime_inventory import enrich_runtime_inventory
from exercise_runtime import BASE_DIR, collect_runtime_inventory

ROOT = Path(__file__).resolve().parents[1]
LAUNCHERS = ROOT / "launchers"

MAIN_LAUNCHERS = [
    LAUNCHERS / "一键完整流程_含弱口令.bat",
    LAUNCHERS / "一键已有子域名后流程_含弱口令.bat",
    LAUNCHERS / "一键保守全流程_尽量多信息_避WAF.bat",
    LAUNCHERS / "一键并行分批流程.bat",
]

EXPECTED_ORDER = [
    r'set "PY=%PROJECT%\.venv\Scripts\python.exe"',
    "天狐渗透工具箱-社区版V3.0",
    "codex-runtimes",
    'set "PY=python"',
]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _py_block(text: str) -> str:
    """Python 选择段落：从 PROJECT 行到 Using Python 行。"""
    start = text.index('set "PROJECT=')
    end = text.index("echo Using Python")
    return text[start:end]


def test_all_main_launchers_use_unified_python_order():
    for path in MAIN_LAUNCHERS:
        block = _py_block(_text(path))
        positions = [block.index(marker) for marker in EXPECTED_ORDER]
        assert positions == sorted(positions), f"{path.name}: Python 选择顺序偏离统一顺序（venv→天狐→codex→PATH）"


def test_full_workflow_launcher_has_balanced_parens():
    """规格 7.4 点名的孤立 `)` 已删除；整文件无未闭合/多余括号。"""
    text = _text(MAIN_LAUNCHERS[0])
    depth = 0
    line = 1
    for ch in text:
        if ch == "\n":
            line += 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            assert depth >= 0, f"line {line}: 出现未配对的孤立 )"
    assert depth == 0, "括号不闭合"


def test_parallel_launcher_has_no_project_py_dead_code():
    text = _text(MAIN_LAUNCHERS[3])
    assert "PROJECT_PY" not in text
    assert "统一 Python 选择顺序" in text


def test_conservative_launcher_marks_dns_budget():
    text = _text(MAIN_LAUNCHERS[2])
    marker = text.index("\n  --subdomain-concurrency 6 ^")
    rem_start = text.rindex("\nrem ", 0, marker)
    between = text[rem_start + 1 : marker].strip().splitlines()
    assert between[0].startswith("rem ") and "DNS 专项预算" in between[0]
    assert all(not line.strip() for line in between[1:])  # rem 与参数行之间只有空行


def test_config_declares_concurrency_budgets_and_python_fallbacks():
    config = json.loads((ROOT / "gov_exercise_config.json").read_text(encoding="utf-8"))
    budgets = config["rate_control"]["concurrency_budgets"]
    for key in ("dns_queries", "http_hosts", "cross_host_workers", "note"):
        assert key in budgets, f"concurrency_budgets 缺 {key}"
    assert "DNS" in budgets["note"]
    fallbacks = config["python_fallbacks"]
    assert [item["name"] for item in fallbacks] == ["project_venv", "tianhu_compat"]
    assert fallbacks[0]["path"].endswith(".venv/Scripts/python.exe")


def test_inventory_python_matches_launcher_interpreter():
    """runtime_inventory 记录的 python 必须是 .venv（launcher 实际启动解释器）。"""
    config = json.loads((ROOT / "gov_exercise_config.json").read_text(encoding="utf-8"))
    inventory = collect_runtime_inventory(config)
    venv_python = BASE_DIR / ".venv" / "Scripts" / "python.exe"
    assert inventory["python"] == str(venv_python)
    enriched = enrich_runtime_inventory(inventory)
    assert enriched["python_path"] == str(venv_python)
    # 兼容键保留（batch4_3 契约）
    for key in ("checked_at", "base_dir", "tianhu_base", "python", "java", "tools"):
        assert key in enriched
