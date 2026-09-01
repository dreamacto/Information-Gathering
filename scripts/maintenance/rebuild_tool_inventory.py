#!/usr/bin/env python3
"""rebuild_tool_inventory.py —— 轻量工具 registry 校验/再生成入口（实施规格 7.1；Batch 4）。

纯 stdlib、零网络、不执行任何工具。两个模式：

  --check    校验 tools/tool_registry.json：结构 + status↔path 一致性（fail-closed）+
             gov_exercise_config.tools 候选表覆盖 + tool_strategy.json 逻辑工具名交叉。
             退出码 0/1。
  --rebuild  从 gov_exercise_config.json 工具候选表 fail-closed 再解析：
             - config_key 条目按候选顺序重解析（首个存在的候选胜出），路径归一化
               （项目根内→相对 posix；根外→绝对 posix）；
             - active 条目路径失配 → 降级 unavailable 并记 checked_at（不保留 active 假象）；
             - hold/unavailable/retired 为人工状态，一律不自动改判（不自动升级）；
             - 无变化时不写文件（字节级幂等）。

新工具登记仍由人工编辑 tools/tool_registry.json（8 个默认字段），本脚本不凭空补元数据。
AGENT_MANIFEST.md 由 scripts/gen_agent_manifest.py 生成，与本脚本无关。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT_ROOT = Path(__file__).resolve().parents[2]
for candidate in (SCRIPT_ROOT, SCRIPT_ROOT / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from authorized_assessment.tools import registry as tool_registry  # noqa: E402

TZ = timezone(timedelta(hours=8))


def _load_json(path: Path) -> tuple[object, str | None]:
    if not path.is_file():
        return None, f"missing file: {path.name}"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as exc:
        return None, f"unparseable {path.name}: {exc}"


def _expand(candidate: str, base: Path, tianhu: str) -> Path:
    expanded = str(candidate).replace("{base}", str(base)).replace("{tianhu}", tianhu)
    return Path(expanded)


def _normalize(resolved: Path, root: Path) -> str:
    """项目根内→相对 posix；根外→绝对 posix（保证 registry 稳定可读）。"""
    try:
        relative = resolved.resolve().relative_to(root.resolve())
    except ValueError:
        return resolved.resolve().as_posix()
    return relative.as_posix()


def collect_check_violations(root: Path) -> list[str]:
    """--check 的全部校验：结构 + status 一致性 + config 覆盖 + strategy 交叉。"""
    registry, err = tool_registry.load_registry(root / "tools" / "tool_registry.json")
    if err:
        return [err]
    assert registry is not None
    violations = tool_registry.validate_registry(registry)
    violations += tool_registry.check_status_consistency(registry, root)
    config, err2 = _load_json(root / "gov_exercise_config.json")
    if err2:
        violations.append(f"gov_exercise_config.json: {err2}")
    else:
        assert config is not None
        violations += tool_registry.check_config_coverage(registry, config)
    strategy, err3 = _load_json(root / "tool_strategy.json")
    if err3:
        violations.append(f"tool_strategy.json: {err3}")
    else:
        assert strategy is not None
        violations += tool_registry.check_tool_strategy_references(registry, strategy, root)
    return violations


def rebuild_registry(registry: dict, config: dict, root: Path) -> tuple[dict, list[str]]:
    """fail-closed 再解析；返回 (更新后的 registry, 变更说明列表)。不自动升级人工状态。"""
    changes: list[str] = []
    now = datetime.now(TZ).isoformat(timespec="seconds")
    config_tools = config.get("tools") or {}
    tianhu = str(config.get("tianhu_base") or "")
    by_config_key: dict[str, list[dict]] = {}
    for entry in registry.get("tools") or []:
        if isinstance(entry, dict) and entry.get("config_key"):
            by_config_key.setdefault(str(entry["config_key"]), []).append(entry)

    for name, candidates in config_tools.items():
        entries = by_config_key.get(name, [])
        if len(entries) != 1:
            changes.append(f"config 工具 {name}: registry 登记数={len(entries)}，跳过再解析（须人工修正登记）")
            continue
        entry = entries[0]
        candidate_list = candidates if isinstance(candidates, list) else [candidates]
        resolved: Path | None = None
        for candidate in candidate_list:
            expanded = _expand(str(candidate), root, tianhu)
            if expanded.exists():
                resolved = expanded
                break
        old_path = str(entry.get("path") or "")
        old_status = str(entry.get("status") or "")
        if resolved is not None:
            new_path = _normalize(resolved, root)
            if old_status in ("active", ""):
                if old_path != new_path or old_status != "active":
                    entry["path"] = new_path
                    entry["status"] = "active"
                    entry["checked_at"] = now
                    changes.append(f"{entry.get('tool_id')}: 路径/状态重解析为 {new_path}（active）")
            else:
                entry["checked_at"] = now
                changes.append(
                    f"{entry.get('tool_id')}: 候选可解析但人工状态 {old_status} 保留（不自动升级），见 {new_path}"
                )
        else:
            if old_status == "active":
                entry["status"] = "unavailable"
                entry["checked_at"] = now
                changes.append(f"{entry.get('tool_id')}: 全部候选路径不存在，active 降级 unavailable（fail-closed）")
            else:
                changes.append(
                    f"{entry.get('tool_id')}: 全部候选路径不存在，人工状态 {old_status} 保留（不自动改判）"
                )

    for entry in registry.get("tools") or []:
        if not isinstance(entry, dict) or entry.get("config_key"):
            continue
        if str(entry.get("status") or "") != "active":
            continue
        resolved = tool_registry.resolve_tool_path(str(entry.get("path") or ""), root)
        if not str(entry.get("path") or "").strip() or not resolved.exists():
            entry["status"] = "unavailable"
            entry["checked_at"] = now
            changes.append(f"{entry.get('tool_id')}: 登记路径不可解析，active 降级 unavailable（fail-closed）")
    return registry, changes


def _write_registry(root: Path, registry: dict) -> None:
    path = root / "tools" / "tool_registry.json"
    path.write_text(
        json.dumps(registry, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="轻量工具 registry 校验/再生成（离线、零网络）")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="校验 registry（默认）")
    mode.add_argument("--rebuild", action="store_true", help="从 config 候选表 fail-closed 再解析并写回")
    parser.add_argument("--json", action="store_true", help="输出机器可读 JSON 报告")
    parser.add_argument("--root", type=Path, default=SCRIPT_ROOT, help="项目根（默认仓库根）")
    args = parser.parse_args(argv)
    root = args.root.resolve()

    if args.rebuild:
        registry, err = tool_registry.load_registry(root / "tools" / "tool_registry.json")
        if err:
            print(f"[!] {err}")
            return 1
        config, err2 = _load_json(root / "gov_exercise_config.json")
        if err2:
            print(f"[!] {err2}")
            return 1
        assert registry is not None and config is not None
        _, changes = rebuild_registry(registry, config, root)
        if changes:
            _write_registry(root, registry)
            print(f"[+] rebuild 完成：{len(changes)} 项变更已写回")
        else:
            print("[+] rebuild 完成：无变更，文件保持字节级不变（幂等）")
        for item in changes:
            print(f"  - {item}")
        violations = collect_check_violations(root)
        if args.json:
            print(
                json.dumps(
                    {"mode": "rebuild", "changes": changes, "violations": violations, "ok": not violations},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        if violations:
            print(f"[!] rebuild 后仍有 {len(violations)} 项违例（见 --json）")
            return 1
        return 0

    violations = collect_check_violations(root)
    if args.json:
        print(
            json.dumps(
                {"mode": "check", "violations": violations, "ok": not violations},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        if violations:
            print(f"[!] {len(violations)} 项工具 registry 违例：")
            for item in violations:
                print(f"  - {item}")
        else:
            print("[+] 工具 registry 校验通过：结构完整、status 与盘上路径一致、config 候选表全覆盖、tool_strategy 引用无漂移")
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
