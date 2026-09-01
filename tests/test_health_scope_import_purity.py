# -*- coding: utf-8 -*-
"""tests/test_health_scope_import_purity.py —— batch14_2：health_scope_import
模块导入期零全局副作用（batch8_8 test_subdomain_import_purity 先例同型）。

背景（Batch 12/13 交接均点名的遗留项）：health_scope_import.py 模块顶层曾执行
sys.stdout.reconfigure(...)，被导入时（含 pytest 收集 test_healthcare_profile）
改变全局流编码，违反"导入期不改 os.environ/locale/stdout 编码"纪律。
修复（batch14_2）：顶层 reconfigure 删除；输出编码兑底移入
_configure_cli_output_encoding() helper，仅 __main__ guard 调用。

双层防回归：① AST 结构层——模块顶层（__main__ guard 之外）不得含环境写入与
全局流重配置调用；② 行为层——导入前后 os.environ 快照逐键相等 + sys.stdout/
sys.stderr 编码不变 + 进程内调用 main()（--help 短路）同样不改环境。纯离线测试。
"""
from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "health_scope_import.py"

BANNED_ENV_TARGETS = {"os.environ", "environ"}


def _toplevel_nodes():
    """模块顶层节点（排除 `if __name__ == "__main__":` guard——guard 仅 CLI 入口执行）。"""
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    result = []
    for node in tree.body:
        if isinstance(node, ast.If):
            test = node.test
            is_main_guard = (
                (isinstance(test, ast.Compare) and getattr(test.left, "id", "") == "__name__")
                or getattr(test, "id", "") == "__name__"
            )
            if is_main_guard:
                continue
        result.append(node)
    return result


def _call_root_name(node: ast.AST) -> str:
    """取 Call 的根调用者名：sys.stdout.reconfigure() → 'sys.stdout'；
    os.environ.setdefault() → 'os.environ'；foo() → 'foo'。"""
    func = node.func
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def test_no_toplevel_env_mutation_or_stream_reconfigure():
    """AST 结构层：模块作用域不得有 os.environ 写入 / reconfigure 调用。

    函数/类定义体内的调用合法（_configure_cli_output_encoding helper 体内、
    main 内）——本测试只锁模块作用域语句（含顶层 if/for/try 块）。
    """
    for node in _toplevel_nodes():
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue  # 函数/类体内的调用不属于模块作用域
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                root = _call_root_name(sub)
                if root in BANNED_ENV_TARGETS:
                    assert sub.func.attr not in ("setdefault", "update", "pop"), (
                        f"模块作用域发现环境写入: {root}.{sub.func.attr}"
                    )
                if (
                    "stdout.reconfigure" in root
                    or "stderr.reconfigure" in root
                    or sub.func.attr == "reconfigure"
                ):
                    assert False, f"模块作用域发现全局流重配置: {root}()"


def test_runtime_boundary_helper_only_called_in_main_guard():
    """运行时边界存在：_configure_cli_output_encoding 仅在 __main__ guard 内调用
    （main() 进程内调用也不得改变全局环境——batch8_8 复验发现的残余根因形态，
    本模块直接对齐）。
    """
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    helpers = [
        n.name
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_configure_cli_output_encoding"
    ]
    assert helpers, "缺少 _configure_cli_output_encoding 运行时边界函数"
    # main() 内不得再调用（进程内调用 main 的测试不得被改环境）
    main_defs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"]
    assert main_defs, "缺少 main() 入口"
    calls_in_main = [
        n
        for n in ast.walk(main_defs[0])
        if isinstance(n, ast.Call) and _call_root_name(n) == "_configure_cli_output_encoding"
    ]
    assert not calls_in_main, "main() 仍在调用 _configure_cli_output_encoding（应移至 __main__ guard）"
    # guard 内必须调用（直接 CLI 运行仍获得编码兑底）
    guard_found = False
    call_in_guard = False
    for node in tree.body:
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and getattr(
            node.test.left, "id", ""
        ) == "__name__":
            guard_found = True
            call_in_guard = any(
                isinstance(n, ast.Call) and _call_root_name(n) == "_configure_cli_output_encoding"
                for n in ast.walk(node)
            )
    assert guard_found, "缺少 __main__ guard"
    assert call_in_guard, "__main__ guard 未调用 _configure_cli_output_encoding（CLI 场景失去兑底）"


def test_import_has_no_environment_side_effect():
    """行为层：导入模块前后 os.environ 快照逐键相等、sys.stdout/sys.stderr 编码
    不变；进程内调用 main()（--help 短路）同样不得改环境。"""
    before = dict(os.environ)
    stdout_encoding_before = getattr(sys.stdout, "encoding", None)
    stderr_encoding_before = getattr(sys.stderr, "encoding", None)
    import health_scope_import as hsi

    assert dict(os.environ) == before, "导入期修改了 os.environ"
    assert getattr(sys.stdout, "encoding", None) == stdout_encoding_before
    assert getattr(sys.stderr, "encoding", None) == stderr_encoding_before
    # 既有消费方接口仍可导入（tests/test_healthcare_profile.py 依赖）
    assert callable(hsi._category) and callable(hsi._is_private_host) and callable(hsi._normalize_url)
    # 进程内 main() 调用也不改环境（--help 短路；SystemExit 为预期）
    argv_backup = sys.argv
    sys.argv = ["health_scope_import.py", "--help"]
    try:
        try:
            hsi.main()
        except SystemExit:
            pass
    finally:
        sys.argv = argv_backup
    assert dict(os.environ) == before, "进程内 main() 调用修改了 os.environ"
    assert getattr(sys.stdout, "encoding", None) == stdout_encoding_before
    assert getattr(sys.stderr, "encoding", None) == stderr_encoding_before
