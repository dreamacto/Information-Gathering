"""Route mini-program phase state away from a co-located wz phase cursor."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

MINIAPP_PHASE_STATUS_FILENAME = "phase_status.miniapp.json"
LEGACY_PHASE_STATUS_FILENAME = "phase_status.json"
MINIAPP_STREAM = "miniapp_xcx"

_MINIAPP_PHASE_HINTS = {
    "identity",
    "platform_identification",
    "material_acquisition",
    "package_inventory",
    "package_unpack_decompile",
    "source_reconstruction",
    "dynamic_mapping",
    "authentication_session",
    "backend_web_api_testing",
    "client_storage_crypto",
}
_WZ_ONLY_HINTS = {"application_mapping", "unauthenticated_testing", "authenticated_testing"}


@dataclass(frozen=True)
class PhaseStatusRoute:
    path: Path | None
    stream: str | None
    legacy_single_stream: bool = False
    error: str | None = None


def _payload(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _is_explicit_miniapp(payload: dict[str, Any]) -> bool:
    return payload.get("stream") == MINIAPP_STREAM


def _is_legacy_standalone_xcx(root: Path, payload: dict[str, Any]) -> bool:
    """Recognize only an old standalone xcx workspace, never a co-located wz one."""
    if not (root / "miniapp.json").is_file():
        return False
    engagement = _payload(root / "engagement.json")
    if engagement.get("engagement_name") or engagement.get("target_input_sha256"):
        return False
    phases = payload.get("phases")
    if not isinstance(phases, list):
        return False
    names = {str(row.get("phase", "")).strip() for row in phases if isinstance(row, dict)}
    return len(names & _MINIAPP_PHASE_HINTS) >= 3 and not (names & _WZ_ONLY_HINTS)


def resolve_phase_status(root: Path, *, for_write: bool = False) -> PhaseStatusRoute:
    """Resolve the xcx cursor without ever silently falling back to a wz cursor."""
    root = Path(root)
    miniapp_path = root / MINIAPP_PHASE_STATUS_FILENAME
    legacy_path = root / LEGACY_PHASE_STATUS_FILENAME
    if miniapp_path.is_file():
        payload = _payload(miniapp_path)
        stream = payload.get("stream") or MINIAPP_STREAM
        return PhaseStatusRoute(miniapp_path, str(stream), False)
    if legacy_path.is_file():
        payload = _payload(legacy_path)
        if _is_explicit_miniapp(payload) or _is_legacy_standalone_xcx(root, payload):
            return PhaseStatusRoute(legacy_path, MINIAPP_STREAM, True)
        return PhaseStatusRoute(
            None,
            None,
            False,
            "XCX_PHASE_STATUS_MISSING: phase_status.miniapp.json is required; "
            "phase_status.json belongs to the wz stream and will not be used",
        )
    if for_write:
        return PhaseStatusRoute(miniapp_path, MINIAPP_STREAM, False)
    return PhaseStatusRoute(
        None,
        None,
        False,
        "XCX_PHASE_STATUS_MISSING: phase_status.miniapp.json is required for xcx audit",
    )


def route_metadata(route: PhaseStatusRoute) -> dict[str, Any]:
    return {
        "phase_status_file": route.path.name if route.path else None,
        "stream": route.stream,
        "legacy_single_stream": route.legacy_single_stream,
    }
