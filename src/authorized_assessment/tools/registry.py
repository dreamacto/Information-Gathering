"""轻量工具 registry：契约常量与离线校验函数（实施规格 7.1；主规范第十节）。

只回答"工具在哪里、是什么版本、当前能不能调用"。status 只表示本地路径可解析性，
不表示授权状态；速率/并发/只读模式/queue-only/审批门/证据输出由 ROE.md、
policy_engine.py、tool_strategy.json 与阶段代码统一控制，不在 registry 重复登记
（FORBIDDEN_CONTROL_FIELDS）。纯 stdlib、零网络、只读幂等。
"""
from __future__ import annotations

import json
from pathlib import Path

REGISTRY_SCHEMA_VERSION = "1.0"

TOOL_REQUIRED_FIELDS = (
    "tool_id",
    "display_name",
    "path",
    "version",
    "status",
    "runtime",
    "dependencies",
    "known_limitations",
)
TOOL_OPTIONAL_FIELDS = (
    "source_url",
    "release_date",
    "sha256",
    "notes",
    "config_key",
    "checked_at",
)
FORBIDDEN_CONTROL_FIELDS = (
    "scope_controls",
    "rate_controls",
    "concurrency_controls",
    "read_only_mode",
    "queue_only_mode",
    "approval_required",
    "evidence_output",
    "auto_update_disabled",
)
STATUS_VALUES = ("active", "unavailable", "hold", "retired")

# tool_strategy.json 中属于内部编排/人工动作的引用形态（不要求登记 registry）。
# 规格只禁止"伪装成可执行工具的逻辑候选名"；runner_*/manual_* 等是编排器自身
# 阶段或人工步骤，不是工具。
INTERNAL_REFERENCE_PREFIXES = (
    "runner_",
    "manual_",
    "mature_tool_",
    "custom_scripts_",
    "specialized_mature_tool_",
    "result_prioritizer_",
    "none_",
)

_TOOL_STRING_FIELDS = ("tool_id", "display_name", "path", "version", "status", "runtime", "known_limitations")


def resolve_tool_path(path: str, root: Path) -> Path:
    """path 为绝对路径按原样解析；相对路径按项目根解析。"""
    candidate = Path(str(path or ""))
    if candidate.is_absolute():
        return candidate
    return Path(root) / candidate


def load_registry(path: Path) -> tuple[dict | None, str | None]:
    """读取 registry JSON；返回 (data, error)。"""
    registry_path = Path(path)
    if not registry_path.is_file():
        return None, f"missing registry file: {registry_path}"
    try:
        data = json.loads(registry_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, f"unparseable registry file {registry_path.name}: {exc}"
    if not isinstance(data, dict):
        return None, f"registry file {registry_path.name} is not a JSON object"
    return data, None


def validate_registry(data: object) -> list[str]:
    """结构校验：字段集、类型、status 枚举、tool_id 唯一性、控制字段禁入。"""
    violations: list[str] = []
    if not isinstance(data, dict):
        return ["tool_registry: 根对象必须是 JSON object"]
    if data.get("schema_version") != REGISTRY_SCHEMA_VERSION:
        violations.append(
            f"tool_registry.schema_version drift: {data.get('schema_version')!r} != {REGISTRY_SCHEMA_VERSION!r}"
        )
    tools = data.get("tools")
    if not isinstance(tools, list) or not tools:
        return violations + ["tool_registry.tools missing or empty"]
    allowed_fields = set(TOOL_REQUIRED_FIELDS) | set(TOOL_OPTIONAL_FIELDS)
    seen_ids: set[str] = set()
    for index, entry in enumerate(tools):
        label = f"tool_registry.tools[{index}]"
        if not isinstance(entry, dict):
            violations.append(f"{label}: 条目必须是 JSON object")
            continue
        for field in TOOL_REQUIRED_FIELDS:
            if field not in entry:
                violations.append(f"{label}: 缺少必需字段 {field}")
        for field in FORBIDDEN_CONTROL_FIELDS:
            if field in entry:
                violations.append(f"{label}: 禁止登记行为控制字段 {field}（由 ROE/policy_engine/tool_strategy 统一控制）")
        for field in sorted(set(entry) - allowed_fields):
            violations.append(f"{label}: 未登记字段 {field}（轻量模式只允许契约内字段）")
        tool_id = entry.get("tool_id")
        if not isinstance(tool_id, str) or not tool_id.strip():
            violations.append(f"{label}: tool_id 必须是非空字符串")
        elif tool_id in seen_ids:
            violations.append(f"{label}: tool_id 重复: {tool_id}")
        else:
            seen_ids.add(tool_id)
        for field in _TOOL_STRING_FIELDS:
            value = entry.get(field)
            if field in entry and not isinstance(value, str):
                violations.append(f"{label}.{field}: 必须是字符串，得到 {type(value).__name__}")
        if "status" in entry and entry.get("status") not in STATUS_VALUES:
            violations.append(
                f"{label}.status 非法: {entry.get('status')!r}（允许值 {list(STATUS_VALUES)}；conditional 不是合法工具状态）"
            )
        if "dependencies" in entry:
            deps = entry.get("dependencies")
            if not isinstance(deps, list) or not all(isinstance(item, str) for item in deps):
                violations.append(f"{label}.dependencies: 必须是字符串数组")
    return violations


def check_status_consistency(data: object, root: Path) -> list[str]:
    """status↔path 一致性（fail-closed）：active 条目的 path 必须真实存在。"""
    violations: list[str] = []
    if not isinstance(data, dict):
        return ["tool_registry: 根对象必须是 JSON object"]
    tools = data.get("tools")
    if not isinstance(tools, list):
        return ["tool_registry.tools missing"]
    for index, entry in enumerate(tools):
        if not isinstance(entry, dict):
            continue
        tool_id = str(entry.get("tool_id") or f"tools[{index}]")
        status = entry.get("status")
        if status != "active":
            continue
        resolved = resolve_tool_path(str(entry.get("path") or ""), root)
        if not str(entry.get("path") or "").strip() or not resolved.exists():
            violations.append(
                f"tool_registry[{tool_id}]: status=active 但路径不可解析（fail-closed）: {entry.get('path')!r}"
            )
    return violations


def check_config_coverage(data: object, config: object) -> list[str]:
    """gov_exercise_config.tools 每键必须有且仅有一个 config_key 等于它的条目（契约不变量第 8 条）。"""
    if not isinstance(data, dict) or not isinstance(config, dict):
        return ["tool_registry/config: 输入必须是 JSON object"]
    entries = data.get("tools")
    if not isinstance(entries, list):
        return ["tool_registry.tools missing"]
    config_tools = config.get("tools")
    if not isinstance(config_tools, dict):
        return ["gov_exercise_config.tools missing"]
    config_keys = [entry.get("config_key") for entry in entries if isinstance(entry, dict)]
    violations: list[str] = []
    for key in config_tools:
        count = config_keys.count(key)
        if count != 1:
            violations.append(
                f"config 工具 {key!r} 在 registry 中登记数={count}（必须恰为 1；"
                "候选表与 registry 漂移）"
            )
    return violations


def check_tool_strategy_references(data: object, strategy: object, root: Path) -> list[str]:
    """tool_strategy.json 逻辑工具名交叉校验（实施规格 7.1 + 13.2 负例）。

    规则：
      - 内部引用形态（INTERNAL_REFERENCE_PREFIXES）与根目录 .py 脚本名 → 放行；
      - 引用串未命中任何 registry tool_id 且未命中根脚本 → 违例（registry 中
        不存在的逻辑工具名，不得静默放行）；
      - 引用串整串等于某 tool_id 且其 status=unavailable → 违例（不得假装可调用）。
    """
    violations: list[str] = []
    if not isinstance(data, dict) or not isinstance(strategy, dict):
        return ["tool_registry/tool_strategy: 输入必须是 JSON object"]
    tool_status = {
        str(entry.get("tool_id")): str(entry.get("status"))
        for entry in data.get("tools", [])
        if isinstance(entry, dict) and entry.get("tool_id")
    }
    if not tool_status:
        return ["tool_registry.tools missing or empty"]
    try:
        root_scripts = {path.name.lower() for path in Path(root).glob("*.py")}
    except OSError:
        root_scripts = set()
    for section in ("phases", "approval_gated_phases"):
        mapping = strategy.get(section)
        if not isinstance(mapping, dict):
            violations.append(f"tool_strategy.{section} missing or not an object")
            continue
        for phase, meta in mapping.items():
            if not isinstance(meta, dict):
                continue
            for role in ("primary", "backup"):
                ref = meta.get(role)
                if not isinstance(ref, str) or not ref.strip():
                    continue
                low = ref.strip().lower()
                if low.startswith(INTERNAL_REFERENCE_PREFIXES):
                    continue
                if any(script in low for script in root_scripts):
                    continue
                registered_hits = [tid for tid in tool_status if tid.lower() in low]
                if not registered_hits:
                    violations.append(
                        f"tool_strategy.{section}.{phase}.{role}: 逻辑工具名 {ref!r} 未登记于工具 registry"
                        "（规格 7.1/13.2：不存在的逻辑工具名必须显式标记，不得伪装可执行）"
                    )
                    continue
                for tid in registered_hits:
                    if low == tid.lower() and tool_status[tid] == "unavailable":
                        violations.append(
                            f"tool_strategy.{section}.{phase}.{role}: 精确引用 unavailable 工具 {tid!r}"
                            "（规格 7.1：只能引用状态不是 unavailable 的 tool_id）"
                        )
    return violations


def get_tool(data: object, tool_id: str) -> dict | None:
    """Read-only lookup for a registered tool by exact tool_id."""
    if not isinstance(data, dict) or not isinstance(tool_id, str):
        return None
    for entry in data.get("tools", []):
        if isinstance(entry, dict) and entry.get("tool_id") == tool_id:
            return dict(entry)
    return None


def list_available_tools(data: object) -> tuple[dict, ...]:
    """Return active/hold tool metadata without applying execution policy."""
    if not isinstance(data, dict):
        return ()
    return tuple(
        dict(entry)
        for entry in data.get("tools", [])
        if isinstance(entry, dict) and entry.get("status") in {"active", "hold"}
    )
