"""Worker manifest models and fail-closed permission validation."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

WORKER_TYPES = frozenset({"code", "analyst", "verifier"})
_ID = re.compile(r"^worker_[A-Za-z0-9._-]+$")


@dataclass(frozen=True)
class WorkerPermissions:
    network: str = "none"
    read_only: bool = True
    write_scope: bool = False
    write_approval: bool = False
    write_cursor: bool = False
    write_confirmed: bool = False


@dataclass(frozen=True)
class WorkerLimits:
    timeout_seconds: int = 60
    cancellation_supported: bool = True


@dataclass(frozen=True)
class WorkerManifest:
    worker_id: str
    worker_type: str
    name: str
    version: str
    capabilities: tuple[str, ...] = ()
    input_allowlist: tuple[str, ...] = ()
    output_contracts: tuple[str, ...] = ()
    permissions: WorkerPermissions = WorkerPermissions()
    limits: WorkerLimits = WorkerLimits()
    created_at: str = ""
    producer: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["capabilities"] = list(self.capabilities)
        value["input_allowlist"] = list(self.input_allowlist)
        value["output_contracts"] = list(self.output_contracts)
        if not value["created_at"]:
            value["created_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return value


def _safe_text(value: Any, label: str, *, required: bool = False) -> list[str]:
    if not isinstance(value, str) or (required and not value.strip()):
        return [f"{label} must be a non-empty string" if required else f"{label} must be a string"]
    return []


def validate_manifest(value: Mapping[str, Any] | WorkerManifest) -> list[str]:
    data = value.as_dict() if isinstance(value, WorkerManifest) else dict(value) if isinstance(value, Mapping) else None
    if data is None:
        return ["manifest must be an object"]
    errors: list[str] = []
    errors += _safe_text(data.get("worker_id"), "worker_id", required=True)
    if isinstance(data.get("worker_id"), str) and not _ID.fullmatch(data["worker_id"]):
        errors.append("worker_id has invalid format")
    if data.get("worker_type") not in WORKER_TYPES:
        errors.append("worker_type is invalid")
    for field in ("name", "version"):
        errors += _safe_text(data.get(field), field, required=True)
    for field in ("capabilities", "input_allowlist", "output_contracts"):
        if not isinstance(data.get(field), (list, tuple)) or not all(isinstance(x, str) and x for x in data[field]):
            errors.append(f"{field} must be a list of strings")
    permissions = data.get("permissions")
    if not isinstance(permissions, Mapping):
        errors.append("permissions must be an object")
    else:
        if permissions.get("network") not in {"none", "metadata_only"}:
            errors.append("permissions.network is invalid")
        if not isinstance(permissions.get("read_only"), bool):
            errors.append("permissions.read_only must be boolean")
        for field in ("write_scope", "write_approval", "write_cursor", "write_confirmed"):
            if permissions.get(field) is not False:
                errors.append(f"permissions.{field} must be false")
    limits = data.get("limits")
    if not isinstance(limits, Mapping):
        errors.append("limits must be an object")
    else:
        timeout = limits.get("timeout_seconds")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1:
            errors.append("limits.timeout_seconds must be >= 1")
        if not isinstance(limits.get("cancellation_supported"), bool):
            errors.append("limits.cancellation_supported must be boolean")
    errors += _safe_text(data.get("created_at"), "created_at", required=True)
    return errors


def build_manifest(*, worker_id: str, worker_type: str, name: str, version: str = "1.0", capabilities: list[str] | tuple[str, ...] = (), input_allowlist: list[str] | tuple[str, ...] = (), output_contracts: list[str] | tuple[str, ...] = (), timeout_seconds: int = 60, cancellation_supported: bool = True, producer: str | None = None) -> WorkerManifest:
    manifest = WorkerManifest(worker_id, worker_type, name, version, tuple(capabilities), tuple(input_allowlist), tuple(output_contracts), WorkerPermissions(), WorkerLimits(timeout_seconds, cancellation_supported), datetime.now(timezone.utc).isoformat(timespec="seconds"), producer)
    errors = validate_manifest(manifest)
    if errors:
        raise ValueError("manifest rejected: " + "; ".join(errors))
    return manifest


def manifest_from_dict(value: Mapping[str, Any]) -> WorkerManifest:
    errors = validate_manifest(value)
    if errors:
        raise ValueError("manifest rejected: " + "; ".join(errors))
    p = value["permissions"]
    l = value["limits"]
    return WorkerManifest(value["worker_id"], value["worker_type"], value["name"], value["version"], tuple(value["capabilities"]), tuple(value["input_allowlist"]), tuple(value["output_contracts"]), WorkerPermissions(**p), WorkerLimits(**l), value["created_at"], value.get("producer"))

validate = validate_manifest
Manifest = WorkerManifest
