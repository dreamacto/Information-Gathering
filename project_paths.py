"""Canonical repository paths shared by offline and controlled workflows.

Keep this module dependency-free.  It centralizes path ownership without
moving existing local assets or changing the compatibility entrypoints.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "config"
RUNS_DIR = ROOT / "runs"
CONTRACTS_DIR = ROOT / "contracts"
PROMPTS_DIR = ROOT / "prompts"
TOOLS_DIR = ROOT / "tools"
RUNTIME_STATE_DIR = ROOT / "runtime"

# Root-level names remain the compatibility locations until all callers have
# migrated.  New callers should use these helpers instead of spelling paths.
CONFIG_FILES = {
    "exercise": "gov_exercise_config.json",
    "workflow": "gov_exercise_workflow.json",
    "tool_strategy": "tool_strategy.json",
    "reporting": "reporting_config.json",
    "legacy_yaml": "config.yaml",
}


def config_path(name: str, *, prefer_managed: bool = False) -> Path:
    """Return a configuration path with an explicit compatibility fallback."""
    try:
        filename = CONFIG_FILES[name]
    except KeyError as exc:
        raise KeyError(f"unknown configuration name: {name}") from exc
    managed = CONFIG_DIR / filename
    legacy = ROOT / filename
    if prefer_managed and managed.is_file():
        return managed
    return managed if managed.is_file() else legacy


def contract_path(filename: str) -> Path:
    """Return a JSON contract path under ``contracts/``."""
    return CONTRACTS_DIR / filename


def runtime_state_dir() -> Path:
    """Return the runtime state directory (created on demand by callers)."""
    return RUNTIME_STATE_DIR


def policy_snapshot_path() -> Path:
    """Return the single canonical policy snapshot location."""
    return RUNTIME_STATE_DIR / "policy_snapshot.json"
