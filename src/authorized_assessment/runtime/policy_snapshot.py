"""Policy snapshot: machine-readable L0 policy derived from project rule sources.

The snapshot is generated (never hand-maintained) from:

- ``gov_exercise_config.json`` -> ``rate_control`` numbers, ``blocked_actions``
- ``tool_strategy.json`` -> ``approval_gated_phases`` names
- ROE.md section 6 -> ``stop_conditions`` (encoded below, doc is the source)

Credential values (cookie/token/authorization/session_key/appsecret/...) must
never enter the snapshot: :func:`validate_policy_snapshot` rejects forbidden
key names anywhere in the document.  The loader consumes this file as part of
L0 via ``docs/CONTEXT_LOADING_MAP.yaml``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from project_paths import config_path as _config_path
    from project_paths import policy_snapshot_path as _policy_snapshot_path
except ImportError:  # pragma: no cover - direct execution without repo root on sys.path
    _ROOT = Path(__file__).resolve().parents[3]

    def _config_path(name: str, *, prefer_managed: bool = False) -> Path:
        names = {
            "exercise": "gov_exercise_config.json",
            "tool_strategy": "tool_strategy.json",
        }
        return _ROOT / names[name]

    def _policy_snapshot_path() -> Path:
        return _ROOT / "runtime" / "policy_snapshot.json"


SCHEMA_VERSION = "1.0"

SNAPSHOT_REQUIRED_FIELDS = (
    "schema_version",
    "engagement_id",
    "workflow",
    "phase",
    "authorization_status",
    "active_testing_authorized",
    "allowed_actions",
    "blocked_actions",
    "approval_required",
    "rate_policy",
    "stop_conditions",
    "source_hashes",
    "generated_at",
)

RATE_POLICY_REQUIRED_FIELDS = (
    "same_host_delay_seconds",
    "same_host_concurrency",
    "cross_host_worker_limit",
)

AUTHORIZATION_STATUSES = ("unknown", "unconfirmed", "confirmed", "expired", "revoked")

DEFAULT_STOP_CONDITIONS = (
    "out_of_scope_asset",
    "service_degradation",
    "waf_alarm",
    "window_closed",
    "operator_stop_request",
)

DEFAULT_ALLOWED_ACTIONS = ("offline_analysis", "readonly_get")

FORBIDDEN_CREDENTIAL_KEY_FRAGMENTS = (
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_policy_snapshot(
    *,
    engagement_id: str | None = None,
    workflow: str | None = None,
    phase: str | None = None,
    authorization_status: str = "unknown",
    active_testing_authorized: bool = False,
    allowed_actions: list[str] | None = None,
    exercise_config_path: Path | None = None,
    tool_strategy_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a policy snapshot dict from the real rule sources on disk."""
    if authorization_status not in AUTHORIZATION_STATUSES:
        raise ValueError(f"unknown authorization_status: {authorization_status}")
    if not isinstance(active_testing_authorized, bool):
        raise TypeError("active_testing_authorized must be a boolean")

    exercise_path = exercise_config_path or _config_path("exercise")
    strategy_path = tool_strategy_path or _config_path("tool_strategy")
    exercise = _load_json(exercise_path)
    strategy = _load_json(strategy_path)

    rate_control = exercise.get("rate_control")
    if not isinstance(rate_control, dict):
        raise ValueError(f"{exercise_path}: missing rate_control object")
    blocked_actions = exercise.get("blocked_actions")
    if not isinstance(blocked_actions, list) or not all(isinstance(a, str) for a in blocked_actions):
        raise ValueError(f"{exercise_path}: blocked_actions must be a list of strings")

    approval_gated = strategy.get("approval_gated_phases")
    if not isinstance(approval_gated, dict):
        raise ValueError(f"{strategy_path}: missing approval_gated_phases object")

    # ROE.md section 2: same host stays serial with >= 2s between requests;
    # cross-host workers come from max_concurrency_default.
    rate_policy: dict[str, Any] = {
        "same_host_delay_seconds": rate_control.get("per_host_min_interval_seconds"),
        "same_host_concurrency": 1,
        "cross_host_worker_limit": rate_control.get("max_concurrency_default"),
        "jitter_ratio": rate_control.get("jitter_ratio"),
        "backoff_status_codes": rate_control.get("backoff_status_codes"),
        "backoff_seconds": rate_control.get("backoff_seconds"),
        "stop_on_repeated_errors_per_host": rate_control.get("stop_on_repeated_errors_per_host"),
        "source_notes": {
            "same_host_concurrency": "ROE.md#2 同一 host 内保持串行",
            "cross_host_worker_limit": "gov_exercise_config.json#rate_control.max_concurrency_default",
        },
    }

    timestamp = (now or datetime.now(timezone.utc)).isoformat()
    return {
        "schema_version": SCHEMA_VERSION,
        "engagement_id": engagement_id,
        "workflow": workflow,
        "phase": phase,
        "authorization_status": authorization_status,
        "active_testing_authorized": active_testing_authorized,
        "allowed_actions": list(allowed_actions or DEFAULT_ALLOWED_ACTIONS),
        "blocked_actions": list(blocked_actions),
        "approval_required": sorted(approval_gated.keys()),
        "rate_policy": rate_policy,
        "stop_conditions": list(DEFAULT_STOP_CONDITIONS),
        "source_hashes": {
            "gov_exercise_config.json": _sha256(exercise_path),
            "tool_strategy.json": _sha256(strategy_path),
        },
        "generated_at": timestamp,
    }


def validate_policy_snapshot(snapshot: Any) -> list[str]:
    """Return a list of contract violations (empty list means valid)."""
    errors: list[str] = []
    if not isinstance(snapshot, dict):
        return ["snapshot must be a JSON object"]

    for field in SNAPSHOT_REQUIRED_FIELDS:
        if field not in snapshot:
            errors.append(f"missing required field: {field}")

    if snapshot.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version must be '1.0'")
    if snapshot.get("authorization_status") not in AUTHORIZATION_STATUSES:
        errors.append(f"authorization_status must be one of {AUTHORIZATION_STATUSES}")
    if not isinstance(snapshot.get("active_testing_authorized"), bool):
        errors.append("active_testing_authorized must be a boolean")

    blocked = snapshot.get("blocked_actions")
    if not isinstance(blocked, list) or not blocked or not all(isinstance(a, str) for a in blocked):
        errors.append("blocked_actions must be a non-empty list of strings")

    approval = snapshot.get("approval_required")
    if not isinstance(approval, list) or not all(isinstance(a, str) for a in approval):
        errors.append("approval_required must be a list of strings")

    rate_policy = snapshot.get("rate_policy")
    if not isinstance(rate_policy, dict):
        errors.append("rate_policy must be an object")
    else:
        for field in RATE_POLICY_REQUIRED_FIELDS:
            if field not in rate_policy:
                errors.append(f"rate_policy missing required field: {field}")
        if not isinstance(rate_policy.get("same_host_concurrency"), int):
            errors.append("rate_policy.same_host_concurrency must be an integer")

    if not isinstance(snapshot.get("source_hashes"), dict) or not snapshot.get("source_hashes"):
        errors.append("source_hashes must be a non-empty object")

    errors.extend(_credential_scan(snapshot, prefix=""))
    return errors


def _credential_scan(node: Any, prefix: str) -> list[str]:
    errors: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key).lower()
            path = f"{prefix}.{key}" if prefix else str(key)
            # authorization_status is the spec-required enum field, not a credential.
            if key_text == "authorization_status":
                continue
            if any(fragment in key_text for fragment in FORBIDDEN_CREDENTIAL_KEY_FRAGMENTS):
                errors.append(f"credential-like key is forbidden in snapshot: {path}")
            errors.extend(_credential_scan(value, path))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            errors.extend(_credential_scan(value, f"{prefix}[{index}]"))
    return errors


def write_policy_snapshot(snapshot: dict[str, Any], output_path: Path | None = None) -> Path:
    """Validate then write the snapshot; returns the written path."""
    errors = validate_policy_snapshot(snapshot)
    if errors:
        raise ValueError("refusing to write invalid policy snapshot: " + "; ".join(errors))
    target = Path(output_path) if output_path else _policy_snapshot_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


def load_policy_snapshot(path: Path | None = None) -> dict[str, Any]:
    """Load and validate a snapshot; raises ValueError on contract violations."""
    source = Path(path) if path else _policy_snapshot_path()
    snapshot = _load_json(source)
    errors = validate_policy_snapshot(snapshot)
    if errors:
        raise ValueError(f"{source}: invalid policy snapshot: " + "; ".join(errors))
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the L0 policy snapshot.")
    parser.add_argument("--engagement-id", default=None)
    parser.add_argument("--workflow", default=None)
    parser.add_argument("--phase", default=None)
    parser.add_argument(
        "--authorization-status",
        default="unknown",
        choices=sorted(AUTHORIZATION_STATUSES),
    )
    parser.add_argument("--active-testing-authorized", action="store_true")
    parser.add_argument("--output", default=None, help="defaults to runtime/policy_snapshot.json")
    args = parser.parse_args(argv)

    snapshot = build_policy_snapshot(
        engagement_id=args.engagement_id,
        workflow=args.workflow,
        phase=args.phase,
        authorization_status=args.authorization_status,
        active_testing_authorized=args.active_testing_authorized,
    )
    written = write_policy_snapshot(snapshot, args.output)
    print(f"policy snapshot written: {written}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
