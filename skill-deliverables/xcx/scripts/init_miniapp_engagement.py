#!/usr/bin/env python3
"""Create or resume a portable mini-program assessment workspace without network access."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit


os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


PLATFORMS = ("auto", "wechat", "alipay", "douyin", "baidu", "quickapp", "other")
WECHAT_APPID_RE = re.compile(r"^wx[0-9a-fA-F]{16}$")
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif"}
PACKAGE_SUFFIXES = {".wxapkg", ".hap", ".rpk", ".pkg", ".zip"}

PHASES = (
    "authorization",
    "identity",
    "platform_identification",
    "material_acquisition",
    "initial_decoding",
    "preflight",
    "package_inventory",
    "package_unpack_decompile",
    "source_reconstruction",
    "static_analysis",
    "endpoint_inventory",
    "host_classification",
    "dynamic_setup",
    "dynamic_mapping",
    "authentication_session",
    "backend_web_api_testing",
    "access_control_testing",
    "input_file_testing",
    "business_logic_testing",
    "client_storage_crypto",
    "webview_bridge_links",
    "plugins_cloud_third_party",
    "candidate_validation",
    "evidence",
    "cleanup",
    "retest",
    "reporting",
)

MATERIAL_FIELDS = (
    "material_id", "active", "material_type", "platform", "path_or_value", "size",
    "sha256", "provenance", "version", "analysis_status", "derived_from", "notes",
)

HOST_FIELDS = (
    "host_id", "active", "host", "service_type", "scope_state", "owner",
    "source_material", "source_location", "ownership_rationale", "permitted_actions",
    "confirmed_at", "notes",
)

ENDPOINT_FIELDS = (
    "endpoint_id", "active", "host", "method", "path", "parameters", "content_type",
    "auth_required", "roles", "state_changing", "client_route", "source_material",
    "source_location", "test_status", "notes",
)

DECODING_FIELDS = (
    "decoding_id", "material_id", "input_type", "input_ref", "input_sha256", "tool",
    "tool_version", "mode", "status", "output_path", "recovered_clues", "notes",
)

LEDGER_FIELDS = (
    "item_id", "active", "priority", "category", "platform", "asset", "client_route",
    "endpoint", "parameter", "role", "candidate_type", "status", "confidence", "summary",
    "source", "validation_plan", "validation_result", "evidence_ref", "finding_id", "owner",
    "updated_at",
)


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def directory_manifest_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        try:
            relative = item.relative_to(path).as_posix()
            size = item.stat().st_size
        except OSError:
            continue
        digest.update(f"{relative}\0{size}\n".encode("utf-8", errors="replace"))
    return digest.hexdigest()


def classify_path(path: Path) -> tuple[str, str]:
    if path.is_dir():
        packages = [item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in PACKAGE_SUFFIXES]
        source_markers = any((path / name).is_file() for name in ("app.json", "app.js", "manifest.json", "project.config.json"))
        source_files = any(path.rglob("*.wxml")) or any(path.rglob("*.axml")) or any(path.rglob("*.ttml"))
        if packages and not source_markers:
            return "package_cache", detect_platform_from_suffix(packages[0].suffix.lower())
        if source_markers or source_files:
            return "unpacked_source", "unknown"
        return "directory", "unknown"
    suffix = path.suffix.lower()
    if suffix in PACKAGE_SUFFIXES:
        return "package", detect_platform_from_suffix(suffix)
    if suffix in IMAGE_SUFFIXES:
        return "qr_image", "unknown"
    if suffix == ".har":
        return "traffic_export", "unknown"
    if suffix in {".xml", ".txt", ".json"}:
        sample = path.read_text(encoding="utf-8-sig", errors="replace")[:65536].lower()
        if any(token in sample for token in ("http/1.", '"request"', "<request", "\thttps://", "\thttp://")):
            return "traffic_export", "unknown"
        return "structured_or_text_artifact", "unknown"
    return "file", "unknown"


def detect_platform_from_suffix(suffix: str) -> str:
    return {".wxapkg": "wechat", ".hap": "quickapp", ".rpk": "quickapp"}.get(suffix, "unknown")


def classify_input(value: str) -> tuple[str, str, dict[str, str]]:
    candidate = Path(value)
    if candidate.exists():
        material_type, platform = classify_path(candidate)
        size = str(candidate.stat().st_size) if candidate.is_file() else ""
        digest = sha256_file(candidate) if candidate.is_file() else directory_manifest_sha256(candidate)
        return material_type, platform, {
            "path_or_value": str(candidate.resolve()), "size": size, "sha256": digest,
        }
    stripped = value.strip()
    if WECHAT_APPID_RE.fullmatch(stripped):
        return "identifier", "wechat", {"identifier": stripped.lower(), "path_or_value": stripped.lower()}
    if "://" in stripped:
        parsed = urlsplit(stripped)
        if parsed.scheme and parsed.netloc:
            return "entry_url", "unknown", {"path_or_value": stripped}
    return "name", "unknown", {"name": stripped, "path_or_value": stripped}


def write_csv_if_missing(path: Path, fields: tuple[str, ...], rows: Iterable[dict[str, str]]) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_text_if_missing(path: Path, content: str) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize a mini-program assessment workspace.")
    parser.add_argument("input", help="Name, identifier, QR, package, source, traffic, or URL.")
    parser.add_argument("--output", required=True, help="Engagement workspace directory.")
    parser.add_argument("--platform", choices=PLATFORMS, default="auto")
    parser.add_argument("--name", default="", help="Confirmed or candidate mini-program name.")
    parser.add_argument("--appid", default="", help="AppID or equivalent platform identifier.")
    parser.add_argument("--operator", default="", help="Operating entity.")
    parser.add_argument("--version", default="", help="Observed mini-program version.")
    parser.add_argument(
        "--authorization-ref",
        default="",
        help="Optional authorization evidence note; user-supplied input is accepted by default.",
    )
    parser.add_argument("--window", default="", help="Authorized testing window.")
    parser.add_argument("--rules", default="", help="Rules-of-engagement reference.")
    parser.add_argument("--rate", default="", help="Approved request-rate note.")
    parser.add_argument("--resume", action="store_true", help="Resume the same workspace.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        input_type, detected_platform, details = classify_input(args.input)
    except OSError as exc:
        print(f"ERROR: Cannot inspect input: {exc}", file=sys.stderr)
        return 2
    if not details.get("path_or_value", "").strip():
        print("ERROR: Input is empty.", file=sys.stderr)
        return 2

    platform = detected_platform if args.platform == "auto" else args.platform
    platform = platform if platform != "unknown" else "other"
    inferred_name = details.get("name", "")
    inferred_id = details.get("identifier", "")
    name = args.name.strip() or inferred_name
    identifier = args.appid.strip() or inferred_id
    identity_confirmed = bool(name and identifier and args.operator.strip() and platform)
    root = Path(args.output).resolve()
    engagement_path = root / "engagement.json"
    if root.exists() and not args.resume:
        print(f"ERROR: Output already exists; use --resume for the same engagement: {root}", file=sys.stderr)
        return 3
    if args.resume and engagement_path.is_file():
        existing = json.loads(engagement_path.read_text(encoding="utf-8-sig"))
        old_hash = existing.get("input_sha256")
        new_hash = hashlib.sha256(args.input.encode("utf-8")).hexdigest()
        if old_hash and old_hash != new_hash:
            print("ERROR: Resume input does not match the existing engagement.", file=sys.stderr)
            return 3

    for relative in (
        "artifacts", "evidence/raw", "evidence/redacted", "logs", "materials/original",
        "materials/working", "notes", "reports", "sessions",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)

    created = now()
    authorization_ref = args.authorization_ref.strip() or "user_supplied_initial_target"
    if not engagement_path.exists():
        engagement = {
            "workspace_version": 1,
            "created_at": created,
            "input_type": input_type,
            "input_sha256": hashlib.sha256(args.input.encode("utf-8")).hexdigest(),
            "authorization": {
                "status": "confirmed",
                "reference": authorization_ref,
                "basis": "user_supplied_initial_target",
                "window": args.window.strip(),
                "rules_reference": args.rules.strip(),
                "rate_note": args.rate.strip(),
            },
            "safety_controls": {
                "default_automation": "read_only",
                "write_actions": "operator_approval_required",
                "rate_limit": args.rate.strip() or "low_rate_no_disruption_required",
                "service_impact_policy": "stop_on_degradation",
            },
            "network_accessed_by_initializer": False,
        }
        engagement_path.write_text(
            json.dumps(engagement, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    miniapp_path = root / "miniapp.json"
    if not miniapp_path.exists():
        miniapp = {
            "platform": platform,
            "name": name,
            "identifier": identifier,
            "operator": args.operator.strip(),
            "version": args.version.strip(),
            "identity_status": "confirmed" if identity_confirmed else "pending",
            "identity_evidence": "",
            "updated_at": created,
        }
        miniapp_path.write_text(
            json.dumps(miniapp, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    material_rows: list[dict[str, str]] = []
    if input_type not in {"name", "identifier"}:
        material_identity = "|".join(
            (input_type, details.get("path_or_value", ""), details.get("sha256", ""))
        )
        material_rows.append(
            {
                "material_id": hashlib.sha256(material_identity.encode("utf-8")).hexdigest()[:16],
                "active": "true",
                "material_type": input_type,
                "platform": platform,
                "path_or_value": details.get("path_or_value", ""),
                "size": details.get("size", ""),
                "sha256": details.get("sha256", ""),
                "provenance": "operator_supplied",
                "version": args.version.strip(),
                "analysis_status": "pending",
                "derived_from": "",
                "notes": "",
            }
        )
    write_csv_if_missing(root / "materials.csv", MATERIAL_FIELDS, material_rows)
    write_csv_if_missing(root / "hosts.csv", HOST_FIELDS, [])
    write_csv_if_missing(root / "endpoints.csv", ENDPOINT_FIELDS, [])
    write_csv_if_missing(root / "artifacts" / "decoding-ledger.csv", DECODING_FIELDS, [])
    write_csv_if_missing(root / "review_ledger.csv", LEDGER_FIELDS, [])
    write_csv_if_missing(
        root / "artifacts" / "package-inventory.csv",
        (
            "package_id", "material_id", "package_path", "package_type", "subpackage",
            "size", "sha256", "extractor", "extractor_version", "extraction_status",
            "output_dir", "notes",
        ),
        [],
    )
    write_csv_if_missing(
        root / "artifacts" / "source-map.csv",
        (
            "source_id", "material_id", "package_id", "source_path", "source_type",
            "recovered_from", "sha256", "parse_status", "notes",
        ),
        [],
    )
    write_csv_if_missing(
        root / "evidence" / "index.csv",
        (
            "evidence_id", "finding_id", "captured_at", "sha256", "sensitivity",
            "raw_path", "redacted_path", "retention", "notes",
        ),
        [],
    )

    phase_path = root / "phase_status.json"
    if not phase_path.exists():
        phases = []
        for phase in PHASES:
            status = "pending"
            reason = ""
            artifacts: list[str] = []
            if phase == "authorization":
                status, reason, artifacts = "complete", authorization_ref, ["engagement.json"]
            elif phase == "identity" and identity_confirmed:
                status, reason, artifacts = "complete", "Identity fields supplied", ["miniapp.json"]
            elif phase == "platform_identification" and platform:
                status, reason, artifacts = "complete", f"Platform classified as {platform}", ["miniapp.json"]
            phases.append(
                {
                    "phase": phase, "required": True, "status": status, "reason": reason,
                    "artifacts": artifacts, "updated_at": created if status == "complete" else "",
                }
            )
        phase_path.write_text(
            json.dumps({"phases": phases}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    write_text_if_missing(root / "notes" / "tool-inventory.md", "# Tool inventory\n")
    write_text_if_missing(root / "notes" / "coverage.md", "# Coverage\n")
    write_text_if_missing(
        root / "notes" / "safety-controls.md",
        "# Safety controls\n\n"
        "- Default automation: read-only\n"
        "- Write or state-changing actions: operator approval required before execution\n"
        f"- Rate profile: {args.rate.strip() or 'low_rate_no_disruption_required'}\n"
        "- Stop policy: stop on service degradation, error spikes, or normal-user impact risk\n",
    )
    write_text_if_missing(
        root / "reports" / "final-report.md",
        "# Final report\n\n"
        "## Executive summary\n\n"
        "## Mini-program identity, scope, and rules\n\n"
        "## Client/package analysis coverage\n\n"
        "## Backend host and API classification\n\n"
        "## Confirmed findings\n\n"
        "## Rejected candidates and false positives\n\n"
        "## Blocked, approval-gated, and not-applicable areas\n\n"
        "## Cleanup, retest, and residual risk\n\n"
        "## Evidence index\n\n",
    )
    write_text_if_missing(root / "reports" / ".gitkeep", "")
    print(f"workspace={root}")
    print(f"input_type={input_type}")
    print(f"platform={platform}")
    print(f"identity={'confirmed' if identity_confirmed else 'pending'}")
    print("authorization=confirmed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
