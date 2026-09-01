"""Contract tests for rule precedence and the context snapshot schema.

These tests keep three artifacts in sync with implementation spec sections 3.2
and 3.8:

- contracts/rule_precedence.json (machine-readable precedence)
- docs/RULE_PRECEDENCE.md (human-readable counterpart)
- contracts/context_snapshot_schema.json (context snapshot contract)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRECEDENCE_JSON = ROOT / "contracts" / "rule_precedence.json"
PRECEDENCE_DOC = ROOT / "docs" / "RULE_PRECEDENCE.md"
SNAPSHOT_SCHEMA = ROOT / "contracts" / "context_snapshot_schema.json"

EXPECTED_LEVELS = [
    "系统/开发者指令",
    "AGENTS.md",
    "ROE.md 与当前授权证据",
    "当前 engagement scope、approval 和 stop 状态",
    "当前 workflow Skill（fh/wz/xcx 等）",
    "当前 phase contract/schema",
    "gov_exercise_config.json",
    "tool_strategy.json 与 tool registry",
    "prompts 和实施规格",
    "当前 run 的历史派生结果与 knowledge_base",
    "外部方法学资料",
]

EXPECTED_CONFLICT_RULES = [
    "高层规则覆盖低层规则",
    "历史 run、知识库和外部资料不能覆盖当前授权、scope、审批和停止条件",
    "冲突不得由 AI 静默选择，必须写入 context_conflicts",
    "当前 scope 不明确时只能进入 confirmation_required 或 blocked，不能继续主动测试",
]

EXPECTED_SNAPSHOT_FIELDS = [
    "task_type",
    "workflow",
    "phase",
    "engagement_id",
    "loaded_sources",
    "source_hashes",
    "policy_digest",
    "current_facts",
    "historical_inputs",
    "excluded_sources",
    "context_conflicts",
    "created_at",
]

EXPECTED_LOADED_SOURCE_FIELDS = ["path", "purpose", "sha256", "loaded_at", "required"]
EXPECTED_HISTORICAL_CLASSIFICATIONS = ["historical_fact", "derived_pattern", "stale_reference"]


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_precedence(doc) -> list[str]:
    """Structural validator for the rule precedence contract (test-local)."""
    errors: list[str] = []
    if doc.get("schema_version") != "1.0":
        errors.append("schema_version must be '1.0'")
    levels = doc.get("levels")
    if not isinstance(levels, list) or len(levels) != 11:
        errors.append(f"levels must contain exactly 11 entries, got {len(levels) if isinstance(levels, list) else type(levels)}")
        return errors
    names = []
    for idx, level in enumerate(levels, start=1):
        if not isinstance(level, dict):
            errors.append(f"level {idx} is not an object")
            continue
        if level.get("rank") != idx:
            errors.append(f"level {idx} has wrong rank {level.get('rank')!r}")
        if not level.get("id") or not isinstance(level.get("id"), str):
            errors.append(f"level {idx} missing string id")
        names.append(level.get("name_zh"))
    if names != EXPECTED_LEVELS:
        errors.append(f"level names/order drift: {names!r}")
    conflict = doc.get("conflict_handling")
    if not isinstance(conflict, dict):
        errors.append("conflict_handling must be an object")
    else:
        if conflict.get("override_direction") != "higher_rank_overrides_lower_rank":
            errors.append("conflict_handling.override_direction drift")
        if conflict.get("conflict_record") != "context_conflicts":
            errors.append("conflict_handling.conflict_record must be context_conflicts")
        if conflict.get("rules") != EXPECTED_CONFLICT_RULES:
            errors.append("conflict_handling.rules drift")
    if doc.get("unclear_scope_states") != ["confirmation_required", "blocked"]:
        errors.append("unclear_scope_states drift")
    return errors


def test_precedence_levels_exact_order_and_names():
    doc = _load_json(PRECEDENCE_JSON)
    assert _validate_precedence(doc) == []


def test_precedence_ids_are_unique_snake_case():
    doc = _load_json(PRECEDENCE_JSON)
    ids = [level["id"] for level in doc["levels"]]
    assert len(ids) == len(set(ids))
    for level_id in ids:
        assert re.fullmatch(r"[a-z0-9_]+", level_id), level_id


def test_precedence_document_matches_contract():
    doc_text = PRECEDENCE_DOC.read_text(encoding="utf-8").replace("`", "")
    doc = _load_json(PRECEDENCE_JSON)
    # Every level name appears in the human-readable doc, in order.
    positions = [doc_text.index(name) for name in EXPECTED_LEVELS]
    assert positions == sorted(positions)
    assert "contracts/rule_precedence.json" in doc_text
    for rule in EXPECTED_CONFLICT_RULES:
        assert rule in doc_text, rule
    # Negative: a renamed level must break the sync test, proving drift detection.
    mutated = json.loads(json.dumps(doc, ensure_ascii=False))
    mutated["levels"][0]["name_zh"] = "被篡改的名称"
    assert _validate_precedence(mutated), "mutated contract must produce errors"


def test_precedence_negative_missing_level_and_wrong_order():
    doc = _load_json(PRECEDENCE_JSON)
    minus_one = json.loads(json.dumps(doc, ensure_ascii=False))
    minus_one["levels"] = minus_one["levels"][:-1]
    assert any("exactly 11" in err for err in _validate_precedence(minus_one))

    reordered = json.loads(json.dumps(doc, ensure_ascii=False))
    reordered["levels"][0], reordered["levels"][1] = reordered["levels"][1], reordered["levels"][0]
    errors = _validate_precedence(reordered)
    assert any("wrong rank" in err for err in errors)
    assert any("drift" in err for err in errors)


def test_precedence_negative_weakened_conflict_rules():
    doc = _load_json(PRECEDENCE_JSON)
    weakened = json.loads(json.dumps(doc, ensure_ascii=False))
    weakened["conflict_handling"]["rules"] = EXPECTED_CONFLICT_RULES[:2]
    assert any("rules drift" in err for err in _validate_precedence(weakened))

    bad_states = json.loads(json.dumps(doc, ensure_ascii=False))
    bad_states["unclear_scope_states"] = ["blocked"]
    assert any("unclear_scope_states" in err for err in _validate_precedence(bad_states))


def test_snapshot_schema_required_fields_match_spec():
    schema = _load_json(SNAPSHOT_SCHEMA)
    assert schema["type"] == "object"
    assert sorted(schema["required"]) == sorted(EXPECTED_SNAPSHOT_FIELDS)
    for field in EXPECTED_SNAPSHOT_FIELDS:
        assert field in schema["properties"], field


def test_snapshot_schema_item_contracts():
    schema = _load_json(SNAPSHOT_SCHEMA)
    loaded_items = schema["properties"]["loaded_sources"]["items"]
    assert sorted(loaded_items["required"]) == sorted(EXPECTED_LOADED_SOURCE_FIELDS)
    historical_items = schema["properties"]["historical_inputs"]["items"]
    assert historical_items["properties"]["classification"]["enum"] == EXPECTED_HISTORICAL_CLASSIFICATIONS
    excluded_items = schema["properties"]["excluded_sources"]["items"]
    assert sorted(excluded_items["required"]) == ["path", "reason"]
    # Credential-discipline guard: excluded reason vocabulary must cover credentials.
    assert "credential_file" in excluded_items["properties"]["reason"]["enum"]
