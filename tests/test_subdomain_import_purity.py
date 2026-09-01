"""tests/test_subdomain_import_purity.py —— 操作员决定③（batch8_5）防回归：
subdomain_bruteforce_controlled 模块导入期零全局副作用。

背景（batch8_0 第 4 条根因链）：模块导入期曾执行 sys.stdout/stderr.reconfigure
与 os.environ.setdefault(PYTHONUTF8/PYTHONIOENCODING)，导致后续子进程继承 UTF-8
输出而 GBK locale 父进程读取线程解码崩溃（stdout=None）。操作员决定③：消除导入
期环境变更（根治），输出编码由运行时边界（main）显式处理；不得只保留
"PYTHONUTF8=1 才能通过"的人工约定。

双层防回归：① AST 结构层——模块顶层（__main__ guard 之外）不得含环境写入与
全局流重配置调用；② 行为层——导入前后 os.environ 快照逐键相等 + sys.stdout
编码不变。纯离线测试。
"""
from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "subdomain_bruteforce_controlled.py"

BANNED_TOPLEVEL_CALLS = {"reconfigure"}
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

    函数/类定义体内的调用合法（如 _configure_cli_output_encoding helper、
    main 内的运行时边界）——本测试只锁模块作用域语句（含顶层 if/for/try 块）。
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


def test_runtime_boundary_has_encoding_helper_called_in_main_guard():
    """运行时边界存在：_configure_cli_output_encoding 仅在 __main__ guard 内调用
    （main() 进程内调用也不得改变全局环境——batch8_8 复验时发现的残余根因）。
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
    """行为层：导入模块前后 os.environ 快照逐键相等、sys.stdout 编码不变；
    进程内调用 main() 同样不得改环境（guard 外零环境写入）。"""
    before = dict(os.environ)
    stdout_encoding_before = getattr(sys.stdout, "encoding", None)
    stderr_encoding_before = getattr(sys.stderr, "encoding", None)
    import subdomain_bruteforce_controlled as controlled

    assert dict(os.environ) == before, "导入期修改了 os.environ"
    assert getattr(sys.stdout, "encoding", None) == stdout_encoding_before
    assert getattr(sys.stderr, "encoding", None) == stderr_encoding_before
    # 进程内 main() 调用也不改环境（需要合法 argv；用 --help 短路）
    argv_backup = sys.argv
    sys.argv = ["subdomain_bruteforce_controlled.py", "--help"]
    try:
        try:
            controlled.main()
        except SystemExit:
            pass
    finally:
        sys.argv = argv_backup
    assert dict(os.environ) == before, "进程内 main() 调用修改了 os.environ"
    assert getattr(sys.stdout, "encoding", None) == stdout_encoding_before


def test_split_wildcard_results_still_importable_and_working():
    """既有消费方（test_subdomain_wildcard 等）行为不变。"""
    from subdomain_bruteforce_controlled import split_wildcard_results

    kept, dropped = split_wildcard_results(
        {"api.example.cn": {"1.2.3.4"}, "mail.example.cn": {"9.9.9.9"}},
        {"example.cn": ["1.2.3.4"]},
    )
    assert kept == ["mail.example.cn"]
    assert dropped == ["api.example.cn"]
