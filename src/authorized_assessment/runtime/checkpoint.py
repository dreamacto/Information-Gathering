"""Atomic, monotonic recovery checkpoints for WZ/XCX/FH orchestration."""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

WORKFLOWS = frozenset({"wz", "xcx", "fh"})
CURSORS = frozenset({"phase", "task", "batch", "recovery"})
FILES = frozenset({"phase_status.json", "phase_status.miniapp.json", "run_status.json"})
STATUSES = frozenset({"pending", "running", "complete", "blocked", "failed", "cancelled"})
_ID = re.compile(r"^checkpoint_[A-Za-z0-9._-]+$")
_SENSITIVE = ("cookie", "token", "authorization", "session", "password", "passwd", "secret", "api_key", "apikey", "credential", "har", "raw_response")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe(node: Any, path: str = "checkpoint") -> None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            if any(part in str(key).lower().replace("-", "_") for part in _SENSITIVE):
                raise ValueError(f"sensitive field rejected: {path}.{key}")
            _safe(value, f"{path}.{key}")
    elif isinstance(node, (list, tuple)):
        for i, value in enumerate(node): _safe(value, f"{path}[{i}]")


def validate_checkpoint(value: Any) -> list[str]:
    if not isinstance(value, dict): return ["checkpoint must be a JSON object"]
    required = ("checkpoint_id", "assessment_id", "task_id", "workflow", "phase", "cursor_kind", "status_file", "sequence", "status", "updated_at")
    errors = [f"missing required field: {x}" for x in required if x not in value]
    if not isinstance(value.get("checkpoint_id"), str) or not _ID.fullmatch(value.get("checkpoint_id", "")): errors.append("checkpoint_id has invalid format")
    for key in ("assessment_id", "task_id", "phase"):
        if not isinstance(value.get(key), str) or not value.get(key): errors.append(f"{key} must be a non-empty string")
    if value.get("workflow") not in WORKFLOWS: errors.append("workflow is invalid")
    if value.get("cursor_kind") not in CURSORS: errors.append("cursor_kind is invalid")
    if value.get("status_file") not in FILES: errors.append("status_file is invalid")
    expected = "phase_status.miniapp.json" if value.get("workflow") == "xcx" else ("phase_status.json" if value.get("workflow") == "wz" else "run_status.json")
    if value.get("workflow") in WORKFLOWS and value.get("status_file") != expected: errors.append("workflow/status_file isolation violation")
    if not isinstance(value.get("sequence"), int) or isinstance(value.get("sequence"), bool) or value.get("sequence", -1) < 0: errors.append("sequence must be a non-negative integer")
    if value.get("status") not in STATUSES: errors.append("status is invalid")
    for key in ("completed_task_ids", "pending_task_ids", "blocked_task_ids", "failed_task_ids"):
        if key in value and (not isinstance(value[key], list) or not all(isinstance(x, str) and x for x in value[key])): errors.append(f"{key} must be a list of strings")
    if "attempt" in value and (not isinstance(value["attempt"], int) or isinstance(value["attempt"], bool) or value["attempt"] < 1): errors.append("attempt must be >= 1")
    if "cancel_requested" in value and not isinstance(value["cancel_requested"], bool): errors.append("cancel_requested must be boolean")
    try: _safe(value)
    except ValueError as exc: errors.append(str(exc))
    return errors


def save_checkpoint(path: Path, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    data = dict(checkpoint)
    errors = validate_checkpoint(data)
    if errors: raise ValueError("checkpoint rejected: " + "; ".join(errors))
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.name != data["status_file"]: raise ValueError("checkpoint path/status_file mismatch")
    if target.exists():
        try: old = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc: raise RuntimeError("existing checkpoint invalid; refusing overwrite") from exc
        old_errors = validate_checkpoint(old)
        if old_errors: raise RuntimeError("existing checkpoint invalid; refusing overwrite")
        if old["workflow"] != data["workflow"] or data["sequence"] <= old["sequence"]: raise ValueError("checkpoint sequence must increase within workflow")
    try:
        fd, name = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=target.parent)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, ensure_ascii=False, sort_keys=True, indent=2); fh.write("\n"); fh.flush(); os.fsync(fh.fileno())
        os.replace(name, target)
        return data
    except OSError as exc:
        try:
            if 'name' in locals() and os.path.exists(name): os.unlink(name)
        except OSError: pass
        raise RuntimeError("checkpoint save failed closed") from exc


def load_checkpoint(path: Path) -> dict[str, Any]:
    try: data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc: raise RuntimeError("checkpoint load failed closed") from exc
    errors = validate_checkpoint(data)
    if errors: raise ValueError("invalid checkpoint: " + "; ".join(errors))
    if Path(path).name != data["status_file"]: raise ValueError("checkpoint path/status_file mismatch")
    return data
