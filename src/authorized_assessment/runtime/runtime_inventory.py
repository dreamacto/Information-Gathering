"""runtime_inventory 七个最小字段探针（实施规格 7.4；Batch 4）。

每次 run 的 runtime_inventory.json 至少记录 RUNTIME_INVENTORY_MIN_FIELDS 十字段。
探针只访问本地解释器与 PATH（零目标网络）；探针失败记 None（unknown），
不伪造 False——"不可判定"与"确认缺失"必须区分。
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Callable

# 规格 7.4 逐一对应，顺序即契约顺序；实现常量漂移由 tests/test_runtime_inventory.py 锁定。
RUNTIME_INVENTORY_MIN_FIELDS = (
    "python_path",
    "python_version",
    "requests_version",
    "urllib3_version",
    "pytest_available",
    "docx_available",
    "playwright_available",
    "crypto_available",
    "node_available",
    "java_available",
)

# 单次 -c 探针源码：任一模块导入失败记 null，不让单模块炸掉整个探针。
PROBE_SOURCE = (
    "import json, sys\n"
    "out = {'python_version': sys.version.split()[0]}\n"
    "for m in ('requests', 'urllib3', 'pytest', 'docx', 'playwright', 'cryptography', 'Crypto'):\n"
    "    try:\n"
    "        mod = __import__(m)\n"
    "        out[m] = getattr(mod, '__version__', None) or 'present'\n"
    "    except Exception:\n"
    "        out[m] = None\n"
    "print(json.dumps(out))\n"
)

Runner = Callable[[list[str], int], tuple[int, str]]

_PROBED_MODULES = ("requests", "urllib3", "pytest", "docx", "playwright", "cryptography", "Crypto")


def _default_runner(command: list[str], timeout: int) -> tuple[int, str]:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        shell=False,
    )
    return completed.returncode, completed.stdout


def _unknown_python_fields() -> dict:
    return {
        "python_version": None,
        "requests_version": None,
        "urllib3_version": None,
        "pytest_available": None,
        "docx_available": None,
        "playwright_available": None,
        "crypto_available": None,
    }


def probe_python(
    python_path: str | None,
    runner: Runner | None = None,
    timeout: int = 30,
) -> dict:
    """对选中解释器执行一次探针；返回 7 个 python 派生字段。

    python_path 为空 → 全 None 且不启动子进程；
    探针失败（非零返回、输出不可解析、异常）→ 全 None。
    """
    fields = _unknown_python_fields()
    if not python_path or not str(python_path).strip():
        return fields
    runner = runner or _default_runner
    command = [str(python_path), "-c", PROBE_SOURCE]
    try:
        returncode, stdout = runner(command, timeout)
    except Exception:  # noqa: BLE001 - 探针失败必须降级为 unknown，不外逃
        return fields
    if returncode != 0:
        return fields
    try:
        payload = json.loads(stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return fields
    if not isinstance(payload, dict):
        return fields
    fields["python_version"] = payload.get("python_version") or None
    fields["requests_version"] = payload.get("requests") or None
    fields["urllib3_version"] = payload.get("urllib3") or None
    fields["pytest_available"] = payload.get("pytest") is not None
    fields["docx_available"] = payload.get("docx") is not None
    fields["playwright_available"] = payload.get("playwright") is not None
    fields["crypto_available"] = (
        payload.get("cryptography") is not None or payload.get("Crypto") is not None
    )
    return fields


def probe_external(
    java_path: str | None,
    which_fn: Callable[[str], str | None] | None = None,
) -> dict:
    """node/java 可用性：PATH which + 已解析 java 路径存在性。"""
    which_fn = which_fn or shutil.which
    node = which_fn("node")
    java = which_fn("java")
    java_found = java is not None
    if not java_found and java_path and Path(str(java_path)).is_absolute():
        java_found = Path(str(java_path)).is_file()
    return {"node_available": node is not None, "java_available": java_found}


def enrich_runtime_inventory(
    base: dict,
    runner: Runner | None = None,
    which_fn: Callable[[str], str | None] | None = None,
) -> dict:
    """在既有 collect_runtime_inventory 输出上增补 7.4 十字段；保留全部兼容键；不改输入。

    python_path 取 base["python"]（find_runnable_executable 已验证可运行）；
    java 可用性同时看 base["java"]（绝对路径存在性）与 PATH。
    """
    enriched = dict(base)
    python_path = base.get("python")
    fields = probe_python(python_path if isinstance(python_path, str) else None, runner=runner)
    fields.update(probe_external(base.get("java"), which_fn=which_fn))
    enriched["python_path"] = python_path
    enriched.update(fields)
    for field in RUNTIME_INVENTORY_MIN_FIELDS:
        enriched.setdefault(field, None)
    return enriched


def missing_min_fields(inventory: dict) -> list[str]:
    """runtime_inventory.json 相对 7.4 最小字段的缺失清单（供 run_health/审计复用）。"""
    if not isinstance(inventory, dict):
        return list(RUNTIME_INVENTORY_MIN_FIELDS)
    return [field for field in RUNTIME_INVENTORY_MIN_FIELDS if field not in inventory]
