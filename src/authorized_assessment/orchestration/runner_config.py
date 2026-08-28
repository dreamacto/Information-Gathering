"""Configuration helpers for the controlled exercise runner."""
from __future__ import annotations

from pathlib import Path
from typing import Callable


def load_config(path: Path, *, read_json: Callable[[Path], dict], default_workflow: Path, default_tool_strategy: Path) -> dict:
    """Load runner configuration and apply safe defaults."""
    cfg = read_json(path)
    cfg.setdefault("label", "gx_gov")
    cfg.setdefault("max_targets", 500)
    cfg.setdefault("default_delay_seconds", 2.0)
    cfg.setdefault("probe_timeout_seconds", 8)
    cfg.setdefault("rate_control", {
        "default_delay_seconds": 2.0,
        "jitter_ratio": 0.25,
        "per_host_min_interval_seconds": 2.0,
        "backoff_status_codes": [429, 500, 502, 503, 504],
        "backoff_seconds": 10,
        "max_concurrency_default": 1,
        "stop_on_repeated_errors_per_host": 5,
    })
    cfg.setdefault("allowed_modes", ["check", "probe"])
    cfg.setdefault("workflow", str(default_workflow))
    cfg.setdefault("tool_strategy", str(default_tool_strategy))
    cfg.setdefault("blocked_actions", [
        "password_spray",
        "bruteforce",
        "webshell",
        "c2",
        "tunnel",
        "data_export",
        "destructive_write",
        "ddos",
        "social_engineering",
        "near_field",
    ])
    return cfg


def load_workflow(path: Path, *, read_json: Callable[[Path], dict]) -> dict:
    workflow = read_json(path)
    if not workflow:
        raise SystemExit(f"Workflow file is missing or empty: {path}")
    return workflow


def load_tool_strategy(path: Path, *, read_json: Callable[[Path], dict]) -> dict:
    strategy = read_json(path)
    if not strategy:
        raise SystemExit(f"Tool strategy file is missing or empty: {path}")
    return strategy


def resolve_relative_config_path(config_file: Path, configured: str | Path | None, default: Path) -> Path:
    path = Path(configured) if configured else default
    if not path.is_absolute():
        path = config_file.resolve().parent / path
    return path
