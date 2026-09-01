"""Context snapshot: persist, validate, restore and hash-verify loaded context.

Implements implementation spec sections 3.8/3.10/3.11 on top of
:mod:`context_loader`.  Snapshots record what was loaded (with source hashes),
what was excluded and why, current facts vs historical inputs, and rule
conflicts, so a new session can resume without re-reading the whole project.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_SRC_PARENT = Path(__file__).resolve().parents[2]  # src/
_REPO_ROOT = Path(__file__).resolve().parents[3]
for _bootstrap in (str(_SRC_PARENT), str(_REPO_ROOT)):
    if _bootstrap not in sys.path:
        sys.path.insert(0, _bootstrap)

from authorized_assessment.runtime import context_loader

try:
    from project_paths import ROOT as PROJECT_ROOT
except ImportError:  # pragma: no cover - direct execution without repo root
    PROJECT_ROOT = Path(__file__).resolve().parents[3]

SNAPSHOT_SCHEMA_PATH = PROJECT_ROOT / "contracts" / "context_snapshot_schema.json"

SNAPSHOT_REQUIRED_FIELDS = (
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
)

LOADED_SOURCE_REQUIRED_FIELDS = ("path", "purpose", "sha256", "loaded_at", "required")
HISTORICAL_CLASSIFICATIONS = ("historical_fact", "derived_pattern", "stale_reference")
FORBIDDEN_KEY_FRAGMENTS = (
    "cookie",
    "token",
    "authorization",
    "session_key",
    "appsecret",
    "app_secret",
    "password",
    "secret",
    "api_key",
)


def validate_context_snapshot(snapshot: Any) -> list[str]:
    """Return contract violations; empty list means valid."""
    errors: list[str] = []
    if not isinstance(snapshot, dict):
        return ["snapshot must be a JSON object"]

    for field in SNAPSHOT_REQUIRED_FIELDS:
        if field not in snapshot:
            errors.append(f"missing required field: {field}")

    if not isinstance(snapshot.get("task_type"), str) or not snapshot.get("task_type"):
        errors.append("task_type must be a non-empty string")
    for optional_text in ("workflow", "phase", "engagement_id"):
        value = snapshot.get(optional_text)
        if value is not None and not isinstance(value, str):
            errors.append(f"{optional_text} must be a string or null")

    loaded = snapshot.get("loaded_sources")
    if not isinstance(loaded, list):
        errors.append("loaded_sources must be a list")
    else:
        for index, item in enumerate(loaded):
            if not isinstance(item, dict):
                errors.append(f"loaded_sources[{index}] must be an object")
                continue
            for field in LOADED_SOURCE_REQUIRED_FIELDS:
                if field not in item:
                    errors.append(f"loaded_sources[{index}] missing field: {field}")
            if "required" in item and not isinstance(item["required"], bool):
                errors.append(f"loaded_sources[{index}].required must be a boolean")

    if not isinstance(snapshot.get("source_hashes"), dict):
        errors.append("source_hashes must be an object")
    if not isinstance(snapshot.get("policy_digest"), dict):
        errors.append("policy_digest must be an object")

    facts = snapshot.get("current_facts")
    if not isinstance(facts, list) or not all(isinstance(f, str) for f in facts):
        errors.append("current_facts must be a list of strings")

    historical = snapshot.get("historical_inputs")
    if not isinstance(historical, list):
        errors.append("historical_inputs must be a list")
    else:
        for index, item in enumerate(historical):
            if not isinstance(item, dict) or "path" not in item or "classification" not in item:
                errors.append(f"historical_inputs[{index}] needs path and classification")
            elif item["classification"] not in HISTORICAL_CLASSIFICATIONS:
                errors.append(f"historical_inputs[{index}].classification invalid")

    excluded = snapshot.get("excluded_sources")
    enum_reasons: set[str] = set()
    if SNAPSHOT_SCHEMA_PATH.is_file():
        schema = json.loads(SNAPSHOT_SCHEMA_PATH.read_text(encoding="utf-8"))
        enum_reasons = set(
            schema["properties"]["excluded_sources"]["items"]["properties"]["reason"]["enum"]
        )
    if not isinstance(excluded, list):
        errors.append("excluded_sources must be a list")
    else:
        for index, item in enumerate(excluded):
            if not isinstance(item, dict) or "path" not in item or "reason" not in item:
                errors.append(f"excluded_sources[{index}] needs path and reason")
            elif enum_reasons and item["reason"] not in enum_reasons:
                errors.append(f"excluded_sources[{index}].reason not in schema enum: {item['reason']}")

    if not isinstance(snapshot.get("context_conflicts"), list):
        errors.append("context_conflicts must be a list")

    errors.extend(_credential_scan(snapshot, ""))
    return errors


def _credential_scan(node: Any, prefix: str) -> list[str]:
    errors: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key).lower()
            path = f"{prefix}.{key}" if prefix else str(key)
            if key_text == "authorization_status":
                continue
            if any(fragment in key_text for fragment in FORBIDDEN_KEY_FRAGMENTS):
                errors.append(f"credential-like key is forbidden in snapshot: {path}")
            errors.extend(_credential_scan(value, path))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            errors.extend(_credential_scan(value, f"{prefix}[{index}]"))
    return errors


def build_snapshot_from_bundle(bundle: context_loader.ContextBundle) -> dict:
    snapshot = bundle.to_snapshot_dict()
    errors = validate_context_snapshot(snapshot)
    if errors:
        raise ValueError("bundle produced invalid snapshot: " + "; ".join(errors))
    return snapshot


def run_snapshot_path(run_dir: Path) -> Path:
    return Path(run_dir) / "context_snapshot.json"


def engagement_snapshot_path(engagement_dir: Path) -> Path:
    return Path(engagement_dir) / "notes" / "context_snapshot.json"


def write_context_snapshot(snapshot: dict, output_path: Path) -> Path:
    errors = validate_context_snapshot(snapshot)
    if errors:
        raise ValueError("refusing to write invalid context snapshot: " + "; ".join(errors))
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


def load_context_snapshot(path: Path) -> dict:
    snapshot = json.loads(Path(path).read_text(encoding="utf-8"))
    errors = validate_context_snapshot(snapshot)
    if errors:
        raise ValueError(f"{path}: invalid context snapshot: " + "; ".join(errors))
    return snapshot


def restore_from_snapshot(snapshot: dict) -> dict:
    """Resume payload for a new session (no raw file content re-injected)."""
    return {
        "task_type": snapshot["task_type"],
        "workflow": snapshot.get("workflow"),
        "phase": snapshot.get("phase"),
        "engagement_id": snapshot.get("engagement_id"),
        "policy_digest": snapshot.get("policy_digest", {}),
        "current_facts": list(snapshot.get("current_facts", [])),
        "historical_inputs": list(snapshot.get("historical_inputs", [])),
        "context_conflicts": list(snapshot.get("context_conflicts", [])),
        "source_hashes": dict(snapshot.get("source_hashes", {})),
    }


def verify_source_hashes(snapshot: dict) -> list[str]:
    """Recompute hashes of recorded sources; hash drift must trigger re-read."""
    problems: list[str] = []
    for rel_path, recorded in sorted(snapshot.get("source_hashes", {}).items()):
        path = PROJECT_ROOT / rel_path
        if not path.is_file():
            problems.append(f"source_missing:{rel_path}")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != recorded:
            problems.append(f"hash_drift:{rel_path}")
    return problems


def create_for_task(
    *,
    task_type: str,
    workflow: str | None = None,
    phase: str | None = None,
    engagement_dir: Path | None = None,
    run_dir: Path | None = None,
    include_history: bool = False,
) -> tuple[dict, Path]:
    """Load context and write the snapshot next to the current workdir."""
    bundle = context_loader.load_context(
        task_type=task_type,
        workflow=workflow,
        phase=phase,
        engagement_dir=engagement_dir,
        run_dir=run_dir,
        include_history=include_history,
    )
    snapshot = build_snapshot_from_bundle(bundle)
    if run_dir is not None:
        target = run_snapshot_path(run_dir)
    elif engagement_dir is not None:
        target = engagement_snapshot_path(engagement_dir)
    else:
        target = PROJECT_ROOT / "runtime" / "context_snapshot_last.json"
    written = write_context_snapshot(snapshot, target)
    return snapshot, written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or verify a context snapshot.")
    parser.add_argument("--task-type", default=None)
    parser.add_argument("--workflow", default=None)
    parser.add_argument("--phase", default=None)
    parser.add_argument("--engagement-dir", default=None)
    parser.add_argument("--run-dir", default=None)
    parser.add_argument("--include-history", action="store_true")
    parser.add_argument("--verify", default=None, help="path to a snapshot to verify")
    args = parser.parse_args(argv)

    if args.verify:
        snapshot = load_context_snapshot(Path(args.verify))
        problems = verify_source_hashes(snapshot)
        if problems:
            print("\n".join(problems))
            return 1
        print(f"snapshot verified: {len(snapshot.get('source_hashes', {}))} sources unchanged")
        return 0

    if not args.task_type:
        parser.error("--task-type is required (or use --verify)")
    engagement_dir = Path(args.engagement_dir) if args.engagement_dir else None
    run_dir = Path(args.run_dir) if args.run_dir else None
    snapshot, written = create_for_task(
        task_type=args.task_type,
        workflow=args.workflow,
        phase=args.phase,
        engagement_dir=engagement_dir,
        run_dir=run_dir,
        include_history=args.include_history,
    )
    print(f"context snapshot written: {written}")
    print(f"conflicts: {len(snapshot['context_conflicts'])}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
