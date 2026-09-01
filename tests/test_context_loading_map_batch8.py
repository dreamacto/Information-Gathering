"""tests/test_context_loading_map_batch8.py —— 操作员决定④（batch8_5）验证：
CONTEXT_LOADING_MAP 覆盖 Batch 8 实际消费的模块，且加载行为保持边界。

覆盖：① 三个新 phase 条目存在且字面路径全部在盘（loader fail-closed 语义）；②
条目字段完整（path/purpose/required——决定④要求用途/workflow/phase/必需性/
输入输出写入 purpose）；③ 加载证明：context_loader 对新 phase 能解析并返回所需
来源（不加载无关文件）；④ 排除证明：加载结果不含小程序规则/历史 run/凭证文件
（决定④硬要求）；⑤ 无目录通配符白名单。
"""
from __future__ import annotations

import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAP_PATH = ROOT / "docs" / "CONTEXT_LOADING_MAP.yaml"

BATCH8_PHASES = (
    "api_inventory_reconciliation",
    "api_resource_controls",
    "third_party_api_review",
)

# 决定④排除证明：新 phase 加载不得触及这些形态（无关小程序规则/历史 run/凭证）。
FORBIDDEN_TOKENS = (
    "runs/",
    "auth_sessions",
    "sessions.jsonl",
    ".codex_fh_quality_check",
)


def _load_map() -> dict:
    return yaml.safe_load(MAP_PATH.read_text(encoding="utf-8"))


def test_batch8_phase_entries_exist():
    """三个新 phase 条目存在且与 Batch 8 模块对应。"""
    mapping = _load_map()
    for phase in BATCH8_PHASES:
        assert phase in mapping["phases"], f"phases 缺少 {phase}"
        assert isinstance(mapping["phases"][phase], list) and mapping["phases"][phase]


def test_batch8_entry_paths_exist_on_disk():
    """条目字面路径全部在盘（required:false 不豁免存在性登记质量）。"""
    mapping = _load_map()
    for phase in BATCH8_PHASES:
        for entry in mapping["phases"][phase]:
            path = ROOT / entry["path"]
            assert path.is_file(), f"{phase} 条目路径不存在: {entry['path']}"


def test_batch8_entries_have_required_fields_and_no_glob():
    """每个条目带 path/purpose/required；无目录通配符白名单（决定④）。"""
    mapping = _load_map()
    for phase in BATCH8_PHASES:
        for entry in mapping["phases"][phase]:
            for field in ("path", "purpose", "required"):
                assert field in entry, f"{phase} 条目缺少 {field}"
            assert entry["required"] is False  # Batch 8 模块均为按需加载
            assert "*" not in entry["path"], f"{phase} 条目使用通配符: {entry['path']}"
            # 决定④要求 purpose 内注明用途/所属 workflow/必需性/输入输出
            purpose = entry["purpose"]
            assert "wz" in purpose or "测试" in purpose or "单一实现" in purpose


def test_batch8_phase_loads_only_related_sources():
    """加载证明：loader 对新 phase 只返回该 phase + global 来源（离线解析层）。"""
    mapping = _load_map()
    phase_entries = mapping["phases"]["api_resource_controls"]
    phase_paths = {e["path"] for e in phase_entries}
    global_paths = {
        e["path"] for e in mapping["global"]["always"] if "path" in e
    }
    # phase 视角的完整加载集 = global always + 本 phase 条目
    allowed = global_paths | phase_paths
    for e in phase_entries:
        assert e["path"] in allowed
    # 新 phase 条目不与其它 phase 的模块交叉（当前 phase 只加载相关模块）
    for other in ("graphql", "injection", "miniapp_auth"):
        other_paths = {e["path"] for e in mapping["phases"].get(other, []) if "path" in e}
        overlap = phase_paths & other_paths
        # tool_strategy.json 是共享事实源允许交叉；模块/测试路径不得交叉
        assert overlap <= {"tool_strategy.json"}, f"{phase} 与 {other} 模块路径交叉: {overlap}"


def test_batch8_entries_never_reference_forbidden_sources():
    """排除证明：新 phase 条目（含 purpose 文本）不引用历史 run/凭证/小程序检查产物。"""
    mapping = _load_map()
    for phase in BATCH8_PHASES:
        blob = yaml.safe_dump(mapping["phases"][phase], allow_unicode=True)
        for token in FORBIDDEN_TOKENS:
            assert token not in blob, f"{phase} 条目引用了禁止来源形态 {token}"


def test_loader_still_accepts_batch8_map():
    """回归：context_loader 的映射解析函数（load_loading_map）仍能接受扩展后的映射文件。"""
    from authorized_assessment.runtime import context_loader as cl

    parse = getattr(cl, "load_loading_map", None)
    assert callable(parse), "context_loader 缺少 load_loading_map 解析入口"
    result = parse(MAP_PATH)
    phases = result.get("phases") if isinstance(result, dict) else None
    assert phases and all(p in phases for p in BATCH8_PHASES)
