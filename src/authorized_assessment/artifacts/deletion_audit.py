"""Audited deletion helper for important local artifacts."""
from __future__ import annotations

import getpass
import json
from pathlib import Path
from .manifest import now_iso, sha256_file

PROTECTED_PREFIXES = ("evidence/raw", "evidence/redacted", "sessions", "artifact_manifest")


def record_delete(path: Path, run_dir: Path, reason: str, actor: str | None = None) -> dict:
    root = run_dir.resolve()
    target = path.resolve()
    try:
        relative = target.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("refusing to delete outside run directory") from exc
    if any(relative == prefix or relative.startswith(prefix + "/") for prefix in PROTECTED_PREFIXES):
        raise PermissionError(f"protected artifact cannot be deleted by helper: {relative}")
    if not target.is_file():
        raise FileNotFoundError(target)
    event = {
        "timestamp": now_iso(), "operation": "delete", "relative_path": relative,
        "reason": str(reason or "unspecified")[:200], "actor": actor or getpass.getuser(),
        "size": target.stat().st_size, "sha256_before": sha256_file(target),
    }
    audit = root / "deletion_audit.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    with audit.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
    target.unlink()
    return event
