"""Offline state-version helpers for optimistic local orchestration.

This module deliberately contains no persistence or execution.  A version is an
integer belonging to one entity; callers must provide the entity and expected
version before applying a state transition.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

SCHEMA_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class StateVersion:
    entity_id: str
    state_version: int = 0
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_state_version(self.state_version)
        if not isinstance(self.entity_id, str) or not self.entity_id:
            raise ValueError("entity_id must be a non-empty string")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported schema_version")

    def to_dict(self) -> dict[str, Any]:
        return {"entity_id": self.entity_id, "schema_version": self.schema_version,
                "state_version": self.state_version}


def validate_state_version(version: Any) -> int:
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ValueError("state_version must be a non-negative integer")
    return version


def compare_versions(current: Any, expected: Any) -> int:
    """Return -1, 0, or 1 after validating both versions."""
    current = validate_state_version(current)
    expected = validate_state_version(expected)
    return (current > expected) - (current < expected)


def check_optimistic_version(*, entity_id: str, current_version: Any,
                             expected_version: Any, requested_entity_id: str | None = None) -> dict[str, Any]:
    """Validate an optimistic-concurrency precondition without changing state."""
    if not entity_id or (requested_entity_id is not None and requested_entity_id != entity_id):
        return {"status": "conflict", "reason": "entity_mismatch", "entity_id": entity_id}
    try:
        current = validate_state_version(current_version)
        expected = validate_state_version(expected_version)
    except (TypeError, ValueError) as exc:
        return {"status": "conflict", "reason": "invalid_version", "detail": str(exc), "entity_id": entity_id}
    if current != expected:
        return {"status": "conflict", "reason": "version_conflict", "entity_id": entity_id,
                "current_version": current, "expected_version": expected}
    return {"status": "ok", "reason": "version_matches", "entity_id": entity_id,
            "current_version": current, "expected_version": expected}


def bump_state_version(*, entity_id: str, current_version: Any, expected_version: Any,
                       requested_entity_id: str | None = None) -> dict[str, Any]:
    check = check_optimistic_version(entity_id=entity_id, current_version=current_version,
                                     expected_version=expected_version, requested_entity_id=requested_entity_id)
    if check["status"] != "ok":
        return check
    check.update({"status": "updated", "state_version": check["current_version"] + 1})
    return check


def validate_state_record(record: Any) -> list[str]:
    if not isinstance(record, Mapping):
        return ["state must be an object"]
    errors: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version must be '1.0'")
    if not isinstance(record.get("entity_id"), str) or not record.get("entity_id"):
        errors.append("entity_id must be a non-empty string")
    try:
        validate_state_version(record.get("state_version"))
    except (TypeError, ValueError) as exc:
        errors.append(str(exc))
    return errors


# Friendly aliases used by callers.
optimistic_check = check_optimistic_version
increment_state_version = bump_state_version
