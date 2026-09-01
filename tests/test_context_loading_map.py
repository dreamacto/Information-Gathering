"""Contract tests for docs/CONTEXT_LOADING_MAP.yaml (implementation spec 3.5).

These validate structure and on-disk truthfulness of the loading whitelist.
Runtime resolution behavior is covered by the context loader tests.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = ROOT / "docs" / "CONTEXT_LOADING_MAP.yaml"

REQUIRED_GLOBAL_ALWAYS = ["AGENTS.md", "ROE.md", "runtime/policy_snapshot.json"]
REQUIRED_WORKFLOWS = ["fh", "wz", "xcx"]
REQUIRED_PHASES = ["api_inventory_reconciliation", "api_resource_controls", "third_party_api_review", "graphql", "injection", "miniapp_auth", "miniapp_storage_package", "miniapp_reconciliation", "miniapp_cloud", "miniapp_webview", "directory_candidates", "xss_single_candidate_validation", "passive_subdomain_discovery", "static_analysis_whitebox", "sbom_inventory"]
HISTORY_TASK_TYPES = ["review", "planning", "precision_analysis"]
REQUIRED_NEVER_LOAD_PATTERNS = [
    "runs/*/reports/*draft*",
    ".codex_fh_quality_check/stale_output/*",
    "runs/*/auth_sessions.local.json",
    "runs/*/sessions.jsonl",
]


def _load_map():
    return yaml.safe_load(MAP_PATH.read_text(encoding="utf-8"))


def _iter_entries(doc):
    """Yield every leaf entry dict in the map (tolerates mutated docs)."""
    for entry in (doc.get("global") or {}).get("always", []) + (doc.get("global") or {}).get("on_conflict", []):
        yield "global", entry
    for workflow, entries in (doc.get("workflows") or {}).items():
        for entry in entries:
            yield f"workflow:{workflow}", entry
    for phase, entries in (doc.get("phases") or {}).items():
        for entry in entries:
            yield f"phase:{phase}", entry


def _validate_map(doc) -> list[str]:
    errors: list[str] = []
    if doc.get("schema_version") != "1.0":
        errors.append("schema_version must be '1.0'")
    for section_name in ("global", "workflows", "phases", "historical_data"):
        if section_name not in doc:
            errors.append(f"missing section: {section_name}")
    for section, entry in _iter_entries(doc):
        label = entry.get("path") or entry.get("symbol")
        if not label:
            errors.append(f"{section}: entry without path/symbol: {entry}")
        if not entry.get("purpose"):
            errors.append(f"{section}: {label} missing purpose")
        if "required" not in entry:
            errors.append(f"{section}: {label} missing required flag")
        elif entry["required"] is True and "symbol" not in entry:
            candidate = ROOT / entry["path"]
            if not candidate.exists():
                errors.append(f"{section}: required path missing on disk: {entry['path']}")
    return errors


def test_map_structure_and_required_flags():
    doc = _load_map()
    assert _validate_map(doc) == []


def test_map_global_always_whitelist():
    doc = _load_map()
    entries = doc["global"]["always"]
    paths = [entry["path"] for entry in entries]
    assert paths == REQUIRED_GLOBAL_ALWAYS
    # AGENTS.md / ROE.md / policy_snapshot.json 全部必需（快照由 batch0_2 生成器产出）。
    assert [entry["required"] for entry in entries] == [True, True, True]


def test_map_policy_snapshot_required_and_on_disk():
    doc = _load_map()
    entry = next(e for e in doc["global"]["always"] if e["path"] == "runtime/policy_snapshot.json")
    assert entry["required"] is True
    assert (ROOT / "runtime" / "policy_snapshot.json").is_file()


def test_map_workflows_and_phases_present():
    doc = _load_map()
    assert sorted(doc["workflows"]) == sorted(REQUIRED_WORKFLOWS)
    for workflow in REQUIRED_WORKFLOWS:
        first = doc["workflows"][workflow][0]
        assert first["path"].endswith("SKILL.md") and first["required"] is True
    assert sorted(doc["phases"]) == sorted(REQUIRED_PHASES)


def test_map_future_files_are_explicitly_optional():
    doc = _load_map()
    optional_future = [
        "contracts/graphql_schema.json",
        "contracts/injection_candidate_schema.json",
        "contracts/miniapp_auth_schema.json",
        "contracts/miniapp_storage_package_schema.json",
        "contracts/miniapp_reconciliation_schema.json",
        "contracts/miniapp_cloud_schema.json",
        "contracts/miniapp_webview_schema.json",
        "docs/implementation_specs/02_finding_definition_and_severity.md",
    ]
    all_entries = [entry for _, entry in _iter_entries(doc)]
    for path in optional_future:
        matches = [e for e in all_entries if e.get("path") == path]
        assert matches, f"future contract not registered: {path}"
        assert matches[0]["required"] is False, path


def test_map_historical_data_gate():
    doc = _load_map()
    history = doc["historical_data"]
    assert history["only_when"] == HISTORY_TASK_TYPES
    for pattern in REQUIRED_NEVER_LOAD_PATTERNS:
        assert pattern in history["never_load_as_current_fact"], pattern


def test_map_negative_missing_section():
    doc = _load_map()
    mutated = dict(doc)
    mutated.pop("workflows")
    errors = _validate_map(mutated)
    assert errors  # structural validator must reject, not silently pass


def test_map_negative_required_flag_pointing_to_missing_file():
    doc = _load_map()
    mutated = yaml.safe_load(yaml.safe_dump(doc, allow_unicode=True))
    # miniapp_auth_schema.json 已随 Batch 10 落地存在——改用指向不存在路径验证
    # 校验器逻辑（required: true + 磁盘缺失 → 违例）
    mutated["phases"]["miniapp_auth"][1]["path"] = "contracts/does_not_exist_schema.json"
    mutated["phases"]["miniapp_auth"][1]["required"] = True
    errors = _validate_map(mutated)
    assert any("required path missing" in err for err in errors)


def test_map_negative_entry_without_required_flag():
    doc = _load_map()
    mutated = yaml.safe_load(yaml.safe_dump(doc, allow_unicode=True))
    del mutated["global"]["always"][0]["required"]
    errors = _validate_map(mutated)
    assert any("missing required flag" in err for err in errors)
