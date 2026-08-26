"""Lightweight integrity manifests for local run artifacts."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Iterable


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def list_artifacts(root: Path, exclude: Iterable[str] = ()) -> list[dict[str, object]]:
    root = root.resolve()
    excluded = {str(item).replace("\\", "/").strip("/") for item in exclude}
    records: list[dict[str, object]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative in {"artifact_manifest.json", "artifact_manifest.sha256"}:
            continue
        if any(relative == item or relative.startswith(item + "/") for item in excluded):
            continue
        if any(part in {"__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        try:
            stat = path.stat()
            records.append({"path": relative, "size": stat.st_size, "mtime": stat.st_mtime,
                            "sha256": sha256_file(path), "hash_scope": "full_file"})
        except OSError:
            continue
    return records


def create_manifest(root: Path, output: Path | None = None, exclude: Iterable[str] = ()) -> dict:
    root = root.resolve()
    output = (output or root / "artifact_manifest.json").resolve()
    files = list_artifacts(root, exclude={"sessions", "evidence/raw", *exclude})
    canonical = json.dumps(files, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    manifest = {"schema_version": "1.0", "generated_at": now_iso(), "hash_algorithm": "sha256",
                "hash_scope": "full_file", "files": files,
                "root_sha256": hashlib.sha256(canonical).hexdigest()}
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temp_name, output)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    return manifest


def verify_manifest(root: Path, manifest_path: Path | None = None) -> dict[str, object]:
    root = root.resolve()
    manifest_path = (manifest_path or root / "artifact_manifest.json").resolve()
    if not manifest_path.is_file():
        return {"status": "legacy_unsealed", "missing": [], "changed": [], "added": []}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = {str(item["path"]): item for item in manifest.get("files", [])}
    except (OSError, ValueError, TypeError):
        return {"status": "invalid_manifest", "missing": [], "changed": [], "added": []}
    current = {str(item["path"]): item for item in list_artifacts(root, exclude={"sessions", "evidence/raw"})}
    missing = sorted(set(expected) - set(current))
    added = sorted(set(current) - set(expected))
    changed = sorted(path for path in set(expected) & set(current)
                     if expected[path].get("sha256") != current[path].get("sha256")
                     or expected[path].get("size") != current[path].get("size"))
    status = "sealed" if not (missing or added or changed) else "mismatch"
    return {"status": status, "missing": missing, "added": added, "changed": changed}
