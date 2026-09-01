"""tests/test_tool_registry.py —— 轻量工具 registry 三件套测试（Batch 4 / 规格 7.1 + 13.2）。

覆盖：
  - 真实 tools/tool_registry.json：结构校验、status↔path 一致性、tool_strategy 交叉校验零违例；
  - 契约↔实现常量无漂移；
  - config 工具候选表 ↔ registry config_key 全覆盖；
  - 负例（13.2）：registry 中不存在的逻辑工具名、精确引用 unavailable 工具、
    缺字段/非法 status/重复 tool_id/未登记字段/行为控制字段禁入/active 假路径。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from authorized_assessment.tools import registry as tool_registry

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "tools" / "tool_registry.json"
CONTRACT_PATH = ROOT / "contracts" / "tool_capability_schema.json"
STRATEGY_PATH = ROOT / "tool_strategy.json"
CONFIG_PATH = ROOT / "gov_exercise_config.json"


def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _entry(**overrides: object) -> dict:
    base = {
        "tool_id": "sample_tool",
        "display_name": "Sample Tool",
        "path": "",
        "version": "",
        "status": "unavailable",
        "runtime": "native",
        "dependencies": [],
        "known_limitations": "测试条目",
    }
    base.update(overrides)
    return base


# ---------- 真实数据（主验收） ----------


def test_real_registry_loads_and_validates_clean():
    data = _load(REGISTRY_PATH)
    assert tool_registry.validate_registry(data) == []
    assert tool_registry.check_status_consistency(data, ROOT) == []


def test_real_registry_tool_strategy_cross_check_clean():
    violations = tool_registry.check_tool_strategy_references(
        _load(REGISTRY_PATH), _load(STRATEGY_PATH), ROOT
    )
    assert violations == []


def test_contract_matches_module_constants():
    contract = _load(CONTRACT_PATH)
    assert tuple(contract["tool_required_fields"]) == tool_registry.TOOL_REQUIRED_FIELDS
    assert tuple(contract["tool_optional_fields"]) == tool_registry.TOOL_OPTIONAL_FIELDS
    assert tuple(contract["forbidden_control_fields"]) == tool_registry.FORBIDDEN_CONTROL_FIELDS
    assert tuple(contract["status_values"]) == tool_registry.STATUS_VALUES
    assert contract["schema_version"] == tool_registry.REGISTRY_SCHEMA_VERSION
    assert contract["tool_required_fields"] and contract["forbidden_control_fields"]


def test_real_registry_covers_all_config_tool_keys():
    """gov_exercise_config.json tools 每个键必须有且仅有一个 config_key 等于它的条目。"""
    violations = tool_registry.check_config_coverage(_load(REGISTRY_PATH), _load(CONFIG_PATH))
    assert violations == []


def test_check_config_coverage_flags_missing_and_duplicate(tmp_path):
    registry = {
        "schema_version": "1.0",
        "tools": [
            _entry(tool_id="a", config_key="alpha"),
            _entry(tool_id="b", config_key="alpha"),
        ],
    }
    config = {"tools": {"alpha": ["x"], "beta": ["y"]}}
    violations = tool_registry.check_config_coverage(registry, config)
    assert len(violations) == 2
    assert any("beta" in v and "登记数=0" in v for v in violations)
    assert any("alpha" in v and "登记数=2" in v for v in violations)


def test_real_registry_entries_are_lightweight():
    """轻量模式：每条目只含契约字段；不出现行为控制字段；8 个默认字段齐全。"""
    allowed = set(tool_registry.TOOL_REQUIRED_FIELDS) | set(tool_registry.TOOL_OPTIONAL_FIELDS)
    for entry in _load(REGISTRY_PATH).get("tools") or []:
        assert set(entry) <= allowed, f"{entry.get('tool_id')}: 超出轻量字段集"
        assert set(tool_registry.TOOL_REQUIRED_FIELDS) <= set(entry)


# ---------- 结构校验负例 ----------


def test_missing_required_field_flagged():
    entry = _entry()
    del entry["known_limitations"]
    violations = tool_registry.validate_registry({"schema_version": "1.0", "tools": [entry]})
    assert any("known_limitations" in v for v in violations)


def test_forbidden_control_field_flagged():
    entry = _entry(approval_required=True, rate_controls={"delay": 2})
    violations = tool_registry.validate_registry({"schema_version": "1.0", "tools": [entry]})
    assert any("approval_required" in v for v in violations)
    assert any("rate_controls" in v for v in violations)


def test_invalid_status_flagged():
    entry = _entry(status="conditional")
    violations = tool_registry.validate_registry({"schema_version": "1.0", "tools": [entry]})
    assert any("status 非法" in v and "conditional" in v for v in violations)


def test_duplicate_tool_id_flagged():
    tools = [_entry(), _entry(path="other")]
    violations = tool_registry.validate_registry({"schema_version": "1.0", "tools": tools})
    assert any("tool_id 重复" in v for v in violations)


def test_unknown_field_flagged():
    entry = _entry(behavior_profile={"auto": True})
    violations = tool_registry.validate_registry({"schema_version": "1.0", "tools": [entry]})
    assert any("未登记字段 behavior_profile" in v for v in violations)


def test_dependencies_wrong_type_flagged():
    entry = _entry(dependencies="requests")
    violations = tool_registry.validate_registry({"schema_version": "1.0", "tools": [entry]})
    assert any("dependencies" in v for v in violations)


def test_schema_version_drift_flagged():
    violations = tool_registry.validate_registry({"schema_version": "2.0", "tools": [_entry()]})
    assert any("schema_version" in v for v in violations)


# ---------- status↔path 一致性 ----------


def test_active_with_missing_path_flagged_but_unavailable_clean(tmp_path):
    active = _entry(tool_id="gone", path=str(tmp_path / "missing.exe"), status="active")
    unavailable = _entry(tool_id="absent", path=str(tmp_path / "also-missing.exe"), status="unavailable")
    data = {"schema_version": "1.0", "tools": [active, unavailable]}
    violations = tool_registry.check_status_consistency(data, tmp_path)
    assert len(violations) == 1
    assert "gone" in violations[0]


def test_relative_path_resolves_against_root(tmp_path):
    tool_file = tmp_path / "bin"
    tool_file.mkdir()
    (tool_file / "tool.exe").write_bytes(b"")
    entry = _entry(tool_id="rel", path="bin/tool.exe", status="active")
    assert tool_registry.check_status_consistency(
        {"schema_version": "1.0", "tools": [entry]}, tmp_path
    ) == []


# ---------- tool_strategy 交叉校验（含 13.2 负例） ----------


def _strategy(section: str, phase: str, **roles: str) -> dict:
    return {section: {phase: roles}, "approval_gated_phases": {}}


def test_unregistered_logical_tool_name_flagged(tmp_path):
    """13.2 负例：registry 中不存在的逻辑工具名必须报违例。"""
    known = _entry(tool_id="known_tool", path=str(tmp_path / "known.exe"), status="active")
    (tmp_path / "known.exe").write_bytes(b"")
    strategy = _strategy("phases", "fuzz", primary="ghost_scanner", backup="manual_review")
    violations = tool_registry.check_tool_strategy_references(
        {"schema_version": "1.0", "tools": [known]}, strategy, tmp_path
    )
    assert len(violations) == 1
    assert "ghost_scanner" in violations[0]
    assert "未登记" in violations[0]


def test_exact_unavailable_reference_flagged(tmp_path):
    ghost = _entry(tool_id="ghost", path="", status="unavailable")
    strategy = _strategy("phases", "validate", primary="ghost", backup="manual_review")
    violations = tool_registry.check_tool_strategy_references(
        {"schema_version": "1.0", "tools": [ghost]}, strategy, tmp_path
    )
    assert len(violations) == 1
    assert "unavailable" in violations[0]


def test_internal_prefixes_and_root_scripts_not_flagged(tmp_path):
    (tmp_path / "my_triage.py").write_text("", encoding="utf-8")
    known = _entry(tool_id="known_tool", path=str(tmp_path / "known.exe"), status="active")
    (tmp_path / "known.exe").write_bytes(b"")
    strategy = _strategy(
        "phases",
        "fuzz",
        primary="runner_fuzz_phase",
        backup="my_triage.py_or_manual_request_review",
    )
    violations = tool_registry.check_tool_strategy_references(
        {"schema_version": "1.0", "tools": [known]}, strategy, tmp_path
    )
    assert violations == []


def test_compound_reference_with_active_alternative_clean(tmp_path):
    """逻辑候选名（a_or_b）只要命中任一已登记工具即放行；不因备选不可用而误报。"""
    known = _entry(tool_id="known_tool", path=str(tmp_path / "known.exe"), status="active")
    (tmp_path / "known.exe").write_bytes(b"")
    strategy = _strategy("phases", "fuzz", primary="known_tool_or_ghost_tool", backup="manual_review")
    violations = tool_registry.check_tool_strategy_references(
        {"schema_version": "1.0", "tools": [known]}, strategy, tmp_path
    )
    assert violations == []


def test_hold_tool_compound_mention_clean_exact_unavailable_still_flagged(tmp_path):
    """hold 工具在复合引用中不报违例；精确引用 unavailable 仍报违例。"""
    held = _entry(tool_id="held_tool", path=str(tmp_path / "held"), status="hold")
    banned = _entry(tool_id="banned_tool", path="", status="unavailable")
    strategy = {
        "phases": {
            "fuzz": {"primary": "held_tool_or_other", "backup": "manual_review"},
            "validate": {"primary": "banned_tool", "backup": "manual_review"},
        },
        "approval_gated_phases": {},
    }
    violations = tool_registry.check_tool_strategy_references(
        {"schema_version": "1.0", "tools": [held, banned]}, strategy, tmp_path
    )
    assert len(violations) == 1
    assert "banned_tool" in violations[0]


def test_missing_strategy_section_flagged(tmp_path):
    known = _entry(tool_id="known_tool", path="", status="active")
    violations = tool_registry.check_tool_strategy_references(
        {"schema_version": "1.0", "tools": [known]}, {"phases": {}}, tmp_path
    )
    assert any("approval_gated_phases" in v for v in violations)


# ---------- 纯度 ----------


def test_validators_are_readonly_and_deterministic(tmp_path):
    """校验函数零写盘、重复调用结果一致（幂等只读）。"""
    data = _load(REGISTRY_PATH)
    strategy = _load(STRATEGY_PATH)
    first = (
        tool_registry.validate_registry(data),
        tool_registry.check_status_consistency(data, ROOT),
        tool_registry.check_tool_strategy_references(data, strategy, ROOT),
    )
    second = (
        tool_registry.validate_registry(data),
        tool_registry.check_status_consistency(data, ROOT),
        tool_registry.check_tool_strategy_references(data, strategy, ROOT),
    )
    assert first == second
    assert first[0] == [] and first[1] == [] and first[2] == []
    assert not (tmp_path / "anything").exists()


@pytest.mark.parametrize(
    "field",
    [
        "scope_controls",
        "rate_controls",
        "concurrency_controls",
        "read_only_mode",
        "queue_only_mode",
        "approval_required",
        "evidence_output",
        "auto_update_disabled",
    ],
)
def test_every_control_field_is_forbidden(field):
    entry = _entry(**{field: True})
    violations = tool_registry.validate_registry({"schema_version": "1.0", "tools": [entry]})
    assert any(field in v for v in violations)


# ---------- rebuild_tool_inventory 行为（batch4_1） ----------

from scripts.maintenance import rebuild_tool_inventory  # noqa: E402


def test_rebuild_on_real_data_is_noop_and_bytewise_idempotent():
    """真实 registry + 真实 config：rebuild 零变更、写盘字节级不变（幂等）。"""
    registry = _load(REGISTRY_PATH)
    config = _load(CONFIG_PATH)
    _, changes = rebuild_tool_inventory.rebuild_registry(registry, config, ROOT)
    assert changes == [], changes
    before = REGISTRY_PATH.read_bytes()
    assert rebuild_tool_inventory.main(["--rebuild"]) == 0
    assert REGISTRY_PATH.read_bytes() == before


def test_rebuild_cli_check_json_on_real_root():
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "maintenance" / "rebuild_tool_inventory.py"),
         "--check", "--json"],
        capture_output=True, text=True, cwd=ROOT, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True and payload["violations"] == []


def test_rebuild_demotes_active_when_candidates_missing(tmp_path):
    config = {"tianhu_base": str(tmp_path / "nowhere"), "tools": {"afrog": ["{base}/tools/afrog.exe"]}}
    registry = {"schema_version": "1.0", "tools": [_entry(tool_id="afrog", config_key="afrog", path="tools/afrog.exe", status="active")]}
    _, changes = rebuild_tool_inventory.rebuild_registry(registry, config, tmp_path)
    assert registry["tools"][0]["status"] == "unavailable"
    assert registry["tools"][0]["checked_at"]
    assert any("降级 unavailable" in c for c in changes)


def test_rebuild_never_auto_promotes_hold_or_unavailable(tmp_path):
    tool_file = tmp_path / "bin"
    tool_file.mkdir()
    (tool_file / "tool.exe").write_bytes(b"")
    config = {"tianhu_base": "", "tools": {"t": ["{base}/bin/tool.exe"], "t2": ["{base}/bin/tool.exe"]}}
    registry = {
        "schema_version": "1.0",
        "tools": [
            _entry(tool_id="held", config_key="t", path="bin/tool.exe", status="hold"),
            _entry(tool_id="unavail", config_key="t2", path="bin/tool.exe", status="unavailable"),
        ],
    }
    _, changes = rebuild_tool_inventory.rebuild_registry(registry, config, tmp_path)
    by_id = {e["tool_id"]: e for e in registry["tools"]}
    assert by_id["held"]["status"] == "hold"
    assert by_id["unavail"]["status"] == "unavailable"
    assert any("人工状态 hold 保留" in c for c in changes)
    assert any("人工状态 unavailable 保留" in c for c in changes)


def test_rebuild_resolves_first_existing_candidate_and_normalizes(tmp_path):
    tool_dir = tmp_path / "bin"
    tool_dir.mkdir()
    (tool_dir / "tool.exe").write_bytes(b"")
    config = {"tianhu_base": "", "tools": {"t": ["{base}/missing/none.exe", "{base}/bin/tool.exe"]}}
    registry = {"schema_version": "1.0", "tools": [_entry(tool_id="t", config_key="t", path="", status="active")]}
    _, changes = rebuild_tool_inventory.rebuild_registry(registry, config, tmp_path)
    assert registry["tools"][0]["path"] == "bin/tool.exe"
    assert registry["tools"][0]["status"] == "active"
    assert any("重解析" in c for c in changes)


def test_rebuild_skips_config_key_count_mismatch(tmp_path):
    config = {"tianhu_base": "", "tools": {"ghost_tool": ["{base}/x.exe"]}}
    registry = {"schema_version": "1.0", "tools": [_entry(tool_id="other", path="", status="unavailable")]}
    _, changes = rebuild_tool_inventory.rebuild_registry(registry, config, tmp_path)
    assert any("登记数=0" in c and "跳过" in c for c in changes)


def test_rebuild_check_reports_violation_on_drifted_registry(tmp_path):
    """--check 对 config 覆盖漂移的 tmp 根报违例并返回 1。"""
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "tool_registry.json").write_text(
        json.dumps({"schema_version": "1.0", "tools": [_entry()]}), encoding="utf-8"
    )
    (tmp_path / "gov_exercise_config.json").write_text(
        json.dumps({"tianhu_base": "", "tools": {"some_tool": ["x"]}}, ensure_ascii=False), encoding="utf-8"
    )
    (tmp_path / "tool_strategy.json").write_text(
        json.dumps({"phases": {}, "approval_gated_phases": {}}), encoding="utf-8"
    )
    assert rebuild_tool_inventory.main(["--check", "--root", str(tmp_path)]) == 1


# ---------- Batch 16 工具补充同步（batch16_6 / 规格 7.2） ----------

BATCH16_TOOL_IDS = ("ffuf", "xsstrike", "dalfox", "subfinder", "dnsx", "semgrep", "codeql")

BATCH16_CAPABILITY_MODULES = (
    ROOT / "src" / "authorized_assessment" / "triage" / "ffuf_directory_candidates.py",
    ROOT / "src" / "authorized_assessment" / "triage" / "single_candidate_xss_validation.py",
    ROOT / "src" / "authorized_assessment" / "discovery" / "passive_subdomain_candidates.py",
    ROOT / "src" / "authorized_assessment" / "analysis" / "static_analysis_signals.py",
    ROOT / "src" / "authorized_assessment" / "analysis" / "sbom_inventory.py",
)


def test_batch16_tools_registered_unavailable_without_config_key():
    data = _load(REGISTRY_PATH)
    by_id = {entry["tool_id"]: entry for entry in data["tools"] if isinstance(entry, dict)}
    for tool_id in BATCH16_TOOL_IDS:
        entry = by_id[tool_id]
        assert entry["status"] == "unavailable", f"{tool_id} 必须显式 unavailable（本地未下载）"
        assert "config_key" not in entry, f"{tool_id} 无 config 候选表关联"
        for field in ("path", "version", "runtime", "known_limitations"):
            assert field in entry
        assert entry["known_limitations"].strip(), f"{tool_id} 必须写明已知限制"


def test_batch16_losers_recorded_explicitly_not_fuzzy():
    """严格规范第十节：二选一败者必须显式登记，不得写成模糊 or。"""
    data = _load(REGISTRY_PATH)
    by_id = {entry["tool_id"]: entry for entry in data["tools"]}
    assert "未选用" in by_id["dalfox"]["known_limitations"]
    assert "未选用" in by_id["codeql"]["known_limitations"]
    assert "二选一" in by_id["xsstrike"]["known_limitations"]
    assert "二选一" in by_id["semgrep"]["known_limitations"]


def test_strategy_compound_or_names_removed():
    strategy = _load(STRATEGY_PATH)
    phases = strategy["phases"]
    assert phases["directory_fuzz"]["primary"] == "dirsearch"
    assert phases["xss_candidate_screening"]["backup"] == "nuclei"
    blob = json.dumps(phases, ensure_ascii=False)
    assert "dirsearch_or_ffuf" not in blob
    assert "nuclei_or_dalfox_or_xsstrike" not in blob


def test_strategy_never_references_batch16_unavailable_tools():
    """规格 7.1：strategy 角色不得精确引用 unavailable tool_id。"""
    strategy = _load(STRATEGY_PATH)
    for section in ("phases", "approval_gated_phases"):
        for phase, meta in strategy.get(section, {}).items():
            for role in ("primary", "backup"):
                ref = str(meta.get(role) or "").strip().lower()
                for tool_id in BATCH16_TOOL_IDS:
                    assert ref != tool_id, f"{section}.{phase}.{role} 引用了 unavailable {tool_id}"


def test_batch16_capability_modules_present_and_import_pure():
    import ast

    for module_path in BATCH16_CAPABILITY_MODULES:
        assert module_path.is_file(), f"缺少能力模块 {module_path.name}"
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        for node in tree.body:  # 模块作用域零环境写入/零流重配置（batch8_8 纯度先例）
            if isinstance(node, ast.If):
                continue
            for child in ast.walk(node) if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else []:
                if isinstance(child, ast.Call) and getattr(child.func, "attr", "") == "reconfigure":
                    raise AssertionError(f"{module_path.name} 模块作用域含流重配置")
        text = module_path.read_text(encoding="utf-8")
        assert "os.environ[" not in text, f"{module_path.name} 不得在模块内写环境变量"
        assert "reconfigure" not in text, f"{module_path.name} 不得重配置全局流（batch8_8 纯度纪律）"


def test_batch16_capability_modules_registry_tools_match(tmp_path):
    """能力模块解析的 tool_id 与 registry 登记一致且 executable=false fail-closed。"""
    import sys

    for mod_path in BATCH16_CAPABILITY_MODULES:
        spec_dir = mod_path.parents[1]
        for base in (str(ROOT), str(ROOT / "src")):
            if base not in sys.path:
                sys.path.insert(0, base)
        import importlib

        module = importlib.import_module(
            "."
            + ".".join(mod_path.relative_to(ROOT / "src" / "authorized_assessment").with_suffix("").parts),
            package="authorized_assessment",
        )
        resolver = getattr(module, "resolve_ffuf_tool", None) or getattr(
            module, "resolve_xsstrike_tool", None
        ) or getattr(module, "resolve_semgrep_tool", None) or getattr(
            module, "_resolve_tool", None
        )
        if resolver is None:
            continue  # sbom_inventory 无工具二进制依赖
        if resolver.__name__ == "_resolve_tool":
            tool = resolver("subfinder", None, ROOT)
        else:
            tool = resolver(None, ROOT)
        assert tool["registered"] is True
        assert tool["status"] == "unavailable"
        assert tool["executable"] is False
