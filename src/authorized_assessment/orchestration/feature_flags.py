"""Small, deterministic orchestration mode snapshots.

This module deliberately contains no configuration or credential I/O.  Snapshots
are control-plane metadata only and are safe to persist or compare.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping


class OrchestrationMode(str, Enum):
    LEGACY = "legacy"
    GRAPH_SHADOW = "graph_shadow"
    GRAPH_READONLY = "graph_readonly"
    GRAPH_ACTIVE_APPROVED = "graph_active_approved"


VALID_MODES = tuple(item.value for item in OrchestrationMode)
DEFAULT_MODE = OrchestrationMode.LEGACY
_MODE_ORDER = {mode.value: index for index, mode in enumerate(OrchestrationMode)}
_SENSITIVE_NAMES = frozenset(
    {"cookie", "cookies", "token", "access_token", "refresh_token", "session",
     "session_id", "sessionid", "password", "passwd", "secret", "authorization",
     "credential", "credentials", "har", "raw", "raw_response", "response_body"}
)


def parse_mode(value: Any = None) -> OrchestrationMode:
    """Parse a mode, defaulting only for an omitted/empty value."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return DEFAULT_MODE
    if isinstance(value, OrchestrationMode):
        return value
    if isinstance(value, str):
        try:
            return OrchestrationMode(value.strip().lower())
        except ValueError:
            pass
    raise ValueError(f"invalid orchestration mode: {value!r}")


def _check_safe(value: Any, path: str = "snapshot") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).lower().replace("-", "_")
            if name in _SENSITIVE_NAMES or any(part in name for part in ("cookie", "token", "password", "secret", "session", "har", "raw_response")):
                raise ValueError(f"sensitive field is not allowed: {path}.{key}")
            _check_safe(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _check_safe(child, f"{path}[{index}]")


@dataclass(frozen=True)
class FeatureFlagSnapshot:
    mode: str = DEFAULT_MODE.value
    schema_version: int = 1
    graph_enabled: bool = False
    readonly: bool = False
    active: bool = False
    metadata: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["metadata"] = dict(self.metadata)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @property
    def snapshot_hash(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    @property
    def hash(self) -> str:
        return self.snapshot_hash

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FeatureFlagSnapshot":
        if not isinstance(value, Mapping):
            raise ValueError("snapshot must be an object")
        _check_safe(value)
        mode = parse_mode(value.get("mode"))
        metadata = value.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ValueError("metadata must be an object")
        flags = mode_snapshot(mode, metadata=metadata)
        # Derived flags are authoritative; accepting contradictory input is unsafe.
        for name in ("graph_enabled", "readonly", "active"):
            if name in value and value[name] is not getattr(flags, name):
                raise ValueError(f"inconsistent snapshot flag: {name}")
        return flags


def mode_snapshot(mode: Any = None, *, metadata: Mapping[str, Any] | None = None, **safe_fields: Any) -> FeatureFlagSnapshot:
    parsed = parse_mode(mode)
    combined: dict[str, Any] = dict(metadata or {})
    combined.update(safe_fields)
    _check_safe(combined)
    items = tuple(sorted(combined.items(), key=lambda pair: str(pair[0])))
    return FeatureFlagSnapshot(
        mode=parsed.value,
        graph_enabled=parsed is not OrchestrationMode.LEGACY,
        readonly=parsed is OrchestrationMode.GRAPH_READONLY,
        active=parsed is OrchestrationMode.GRAPH_ACTIVE_APPROVED,
        metadata=items,
    )


def serialize_snapshot(snapshot: FeatureFlagSnapshot | Mapping[str, Any]) -> str:
    value = snapshot if isinstance(snapshot, FeatureFlagSnapshot) else FeatureFlagSnapshot.from_dict(snapshot)
    return value.to_json()


def deserialize_snapshot(value: str | bytes) -> FeatureFlagSnapshot:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid snapshot JSON") from exc
    return FeatureFlagSnapshot.from_dict(parsed)


def can_transition(current: Any, target: Any) -> bool:
    """Allow staying put or moving one step forward; no implicit downgrade/skip."""
    return _MODE_ORDER[parse_mode(target).value] - _MODE_ORDER[parse_mode(current).value] in (0, 1)


__all__ = ["OrchestrationMode", "VALID_MODES", "DEFAULT_MODE", "FeatureFlagSnapshot", "parse_mode", "mode_snapshot", "serialize_snapshot", "deserialize_snapshot", "can_transition"]
