"""Context loader: layered, whitelist-only context loading.

Implements implementation spec section 3.6 for the loading map in
``docs/CONTEXT_LOADING_MAP.yaml``:

1. L0 first, then exactly one L1 workflow, then L2 phase inputs;
2. only whitelist sources from the map are returned;
3. every source records path/purpose/sha256/loaded_at/required;
4. credential files, raw-response drafts and stale output are excluded by
   pattern and never read;
5. history is gated on ``include_history`` plus task type
   (review/planning/precision_analysis);
6. historical inputs are classified historical_fact/derived_pattern/
   stale_reference, never as current facts;
7. rule conflicts are recorded in ``context_conflicts`` and block active
   actions (fail-closed);
8. missing L0 sources fail closed;
9. files unrelated to the current phase are never loaded, even if present;
10. loaded file count and byte totals are reported.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

try:
    from project_paths import config_path, policy_snapshot_path
    from project_paths import ROOT as PROJECT_ROOT
except ImportError:  # pragma: no cover - direct execution without repo root
    PROJECT_ROOT = Path(__file__).resolve().parents[3]

    def config_path(name: str, *, prefer_managed: bool = False) -> Path:
        names = {"exercise": "gov_exercise_config.json", "tool_strategy": "tool_strategy.json"}
        return PROJECT_ROOT / names[name]

    def policy_snapshot_path() -> Path:
        return PROJECT_ROOT / "runtime" / "policy_snapshot.json"


MAP_PATH = PROJECT_ROOT / "docs" / "CONTEXT_LOADING_MAP.yaml"
LOADING_MAP_SCHEMA_VERSION = "1.0"
CONTENT_SIZE_CAP = 262144  # per-source read cap; larger rule files are hashed + path-referenced
HISTORY_TASK_TYPES = ("review", "planning", "precision_analysis")
HISTORY_INDEX_NAME = "context_history_index.json"
ENGAGEMENT_L0_FILES = ("engagement.json", "scope.csv")
ENGAGEMENT_OPTIONAL_FILES = ("phase_status.json",)
ROOT_GUARD_FILES = ("auth_sessions.local.json", "sessions.jsonl")

CLASSIFICATION_VALUES = ("historical_fact", "derived_pattern", "stale_reference")
EXCLUSION_CREDENTIAL = "credential_file"
EXCLUSION_RAW_RESPONSE = "raw_response"
EXCLUSION_STALE = "stale_reference"
EXCLUSION_OTHER_WORKFLOW = "other_workflow"
EXCLUSION_HISTORY_DISABLED = "history_disabled"
EXCLUSION_MISSING_OPTIONAL = "missing_optional_source"


class ContextLoadError(RuntimeError):
    """Raised when the loading map itself is unusable (loader cannot operate)."""


@dataclass
class LoadedSource:
    path: str
    purpose: str
    sha256: str | None
    loaded_at: str
    required: bool
    layer: str
    exists: bool
    size_bytes: int = 0
    content: str | None = None
    truncated: bool = False
    note: str | None = None


@dataclass
class ExcludedSource:
    path: str
    reason: str
    detail: str | None = None


@dataclass
class ContextBundle:
    task_type: str
    workflow: str | None
    phase: str | None
    engagement_dir: Path | None
    run_dir: Path | None
    include_history: bool
    created_at: str
    loaded_sources: list[LoadedSource] = field(default_factory=list)
    excluded_sources: list[ExcludedSource] = field(default_factory=list)
    historical_inputs: list[dict] = field(default_factory=list)
    context_conflicts: list[str] = field(default_factory=list)
    missing_required: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)
    fail_closed: bool = False
    active_actions_blocked: bool = False
    policy_digest: dict = field(default_factory=dict)

    @property
    def total_files(self) -> int:
        return len(self.loaded_sources)

    @property
    def total_bytes(self) -> int:
        return sum(source.size_bytes for source in self.loaded_sources)

    @property
    def excluded_count(self) -> int:
        return len(self.excluded_sources)

    @property
    def has_blocking_findings(self) -> bool:
        return bool(self.missing_required or self.context_conflicts or self.fail_closed)

    def current_facts(self) -> list[str]:
        """Facts derived only from current run/engagement and the policy snapshot."""
        facts: list[str] = []
        if self.engagement_dir is not None:
            facts.append(f"engagement_dir={self.engagement_dir.name}")
        if self.run_dir is not None:
            facts.append(f"run_dir={self.run_dir.name}")
        status = self.policy_digest.get("authorization_status")
        if status is not None:
            facts.append(f"policy_snapshot.authorization_status={status}")
        facts.append(f"active_actions_blocked={str(self.active_actions_blocked).lower()}")
        facts.append(f"task_type={self.task_type}")
        return facts

    def to_snapshot_dict(self, *, engagement_id: str | None = None) -> dict:
        """Serialize into the contracts/context_snapshot_schema.json shape."""
        return {
            "task_type": self.task_type,
            "workflow": self.workflow,
            "phase": self.phase,
            "engagement_id": engagement_id,
            "loaded_sources": [
                {
                    "path": source.path,
                    "purpose": source.purpose,
                    "sha256": source.sha256,
                    "loaded_at": source.loaded_at,
                    "required": source.required,
                    "layer": source.layer,
                }
                for source in self.loaded_sources
            ],
            "source_hashes": {
                source.path: source.sha256 for source in self.loaded_sources if source.sha256
            },
            "policy_digest": self.policy_digest,
            "current_facts": self.current_facts(),
            "historical_inputs": self.historical_inputs,
            "excluded_sources": [
                {"path": excluded.path, "reason": excluded.reason}
                for excluded in self.excluded_sources
            ],
            "context_conflicts": self.context_conflicts,
            "created_at": self.created_at,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_loading_map(map_path: Path | None = None) -> dict:
    """Parse and minimally validate the loading map; raise ContextLoadError if unusable."""
    source = Path(map_path) if map_path else MAP_PATH
    if not source.is_file():
        raise ContextLoadError(f"loading map missing: {source}")
    try:
        doc = yaml.safe_load(source.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ContextLoadError(f"loading map unparsable: {source}: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema_version") != LOADING_MAP_SCHEMA_VERSION:
        raise ContextLoadError(f"loading map schema mismatch: {source}")
    for section in ("global", "workflows", "phases", "historical_data"):
        if section not in doc:
            raise ContextLoadError(f"loading map missing section: {section}")
    return doc


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:  # outside the repository (e.g. test temp dirs)
        return path.as_posix()


def _extract_markdown_section(text: str, section: str) -> str | None:
    """Extract a '## <heading>' section; returns None when not found."""
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == f"## {section}":
            start = index
            break
    if start is None:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("## ") or stripped.startswith("# "):
            end = index
            break
    return "\n".join(lines[start:end]).strip() or None


def _read_source(path: Path, entry: dict, layer: str, loaded_at: str) -> LoadedSource:
    exists = path.is_file()
    source = LoadedSource(
        path=_display_path(path),
        purpose=str(entry.get("purpose", "")),
        sha256=None,
        loaded_at=loaded_at,
        required=bool(entry.get("required", False)),
        layer=layer,
        exists=exists,
        note=entry.get("section"),
    )
    if not exists:
        return source
    data = path.read_bytes()
    source.sha256 = hashlib.sha256(data).hexdigest()
    source.size_bytes = len(data)
    section = entry.get("section")
    text = data.decode("utf-8", errors="replace")
    if section and path.suffix.lower() == ".json":
        # JSON section pointer: content resolved by the consumer after verification.
        source.content = None
        return source
    if section:
        extracted = _extract_markdown_section(text, section)
        if extracted is not None:
            source.content = extracted
            source.note = f"section:{section}"
            return source
        source.note = f"section_not_found:{section}:full_file_fallback"
    if len(text) > CONTENT_SIZE_CAP:
        source.truncated = True
        source.content = text[:CONTENT_SIZE_CAP]
    else:
        source.content = text
    return source


def _verify_json_section(source: LoadedSource, path: Path, section: str, bundle: ContextBundle) -> None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        bundle.context_conflicts.append(f"section_source_unreadable:{source.path}:{exc}")
        return
    if section not in doc:
        message = f"section_missing:{source.path}#{section}"
        if source.required:
            bundle.missing_required.append(f"{source.path}#{section}")
            bundle.fail_closed = True
            bundle.context_conflicts.append(message)
        else:
            bundle.unavailable.append(f"{source.path}#{section}")


def _classify_forbidden(path: Path) -> str | None:
    name = path.name.lower()
    parts = [part.lower() for part in path.parts]
    if name == "auth_sessions.local.json" or name == "sessions.jsonl":
        return EXCLUSION_CREDENTIAL
    if ".codex_fh_quality_check" in parts and "stale_output" in parts:
        return EXCLUSION_STALE
    if "reports" in parts and "draft" in name:
        return EXCLUSION_RAW_RESPONSE
    return None


def _scan_forbidden(root: Path | None, bundle: ContextBundle) -> None:
    if root is None or not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        reason = _classify_forbidden(path)
        if reason is not None:
            bundle.excluded_sources.append(
                ExcludedSource(path=_display_path(path), reason=reason)
            )


def _policy_conflicts(bundle: ContextBundle, snapshot: dict) -> None:
    try:
        exercise = json.loads(config_path("exercise").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        bundle.context_conflicts.append(f"exercise_config_unreadable:{exc}")
        bundle.fail_closed = True
        return
    snapshot_blocked = set(snapshot.get("blocked_actions") or [])
    config_blocked = set(exercise.get("blocked_actions") or [])
    if snapshot_blocked != config_blocked:
        bundle.context_conflicts.append(
            "policy_snapshot_blocked_actions_drift:"
            f"snapshot={sorted(snapshot_blocked)}:config={sorted(config_blocked)}"
        )
        bundle.fail_closed = True
    if snapshot.get("authorization_status") != "confirmed":
        bundle.context_conflicts.append(
            f"scope_not_confirmed:{snapshot.get('authorization_status')}"
        )
        bundle.active_actions_blocked = True
    if snapshot.get("active_testing_authorized") and snapshot.get("authorization_status") != "confirmed":
        bundle.context_conflicts.append("active_testing_without_confirmation")
        bundle.fail_closed = True


def _historical_index_inputs(path: Path, bundle: ContextBundle) -> None:
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        bundle.context_conflicts.append(f"history_index_unreadable:{exc}")
        return
    if not isinstance(entries, list):
        bundle.context_conflicts.append("history_index_not_a_list")
        return
    for entry in entries:
        if not isinstance(entry, dict) or "path" not in entry or "classification" not in entry:
            bundle.context_conflicts.append(f"history_index_bad_entry:{entry!r}")
            continue
        if entry["classification"] not in CLASSIFICATION_VALUES:
            bundle.context_conflicts.append(
                f"history_index_bad_classification:{entry.get('classification')}"
            )
            continue
        bundle.historical_inputs.append(
            {"path": str(entry["path"]), "classification": entry["classification"]}
        )


def load_context(
    *,
    task_type: str,
    workflow: str | None = None,
    phase: str | None = None,
    engagement_dir: Path | None = None,
    run_dir: Path | None = None,
    include_history: bool = False,
    map_path: Path | None = None,
) -> ContextBundle:
    """Load the whitelisted context for one task; see module docstring."""
    if not task_type:
        raise ValueError("task_type is required")
    doc = load_loading_map(map_path)
    loaded_at = _now_iso()
    bundle = ContextBundle(
        task_type=task_type,
        workflow=workflow,
        phase=phase,
        engagement_dir=Path(engagement_dir) if engagement_dir else None,
        run_dir=Path(run_dir) if run_dir else None,
        include_history=include_history,
        created_at=loaded_at,
    )

    # --- L0: repo-level hard boundary -------------------------------------
    for entry in doc["global"]["always"]:
        if "symbol" in entry:
            continue
        path = PROJECT_ROOT / entry["path"]
        source = _read_source(path, entry, "L0", loaded_at)
        bundle.loaded_sources.append(source)
        if not source.exists:
            if source.required:
                bundle.missing_required.append(source.path)
                bundle.fail_closed = True
            else:
                bundle.unavailable.append(source.path)
                bundle.excluded_sources.append(
                    ExcludedSource(path=source.path, reason=EXCLUSION_MISSING_OPTIONAL)
                )
    if bundle.missing_required:
        # L0 broken: report and stop; nothing else may be loaded as current fact.
        return bundle

    snapshot_path = policy_snapshot_path()
    if snapshot_path.is_file():
        try:
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            bundle.context_conflicts.append(f"policy_snapshot_unparsable:{exc}")
            bundle.fail_closed = True
            snapshot = {}
        bundle.policy_digest = {
            "authorization_status": snapshot.get("authorization_status"),
            "active_testing_authorized": snapshot.get("active_testing_authorized"),
            "allowed_actions": snapshot.get("allowed_actions"),
            "blocked_actions": snapshot.get("blocked_actions"),
            "approval_required": snapshot.get("approval_required"),
            "rate_policy": snapshot.get("rate_policy"),
        }
        _policy_conflicts(bundle, snapshot)
    else:
        bundle.context_conflicts.append("policy_snapshot_missing")
        bundle.fail_closed = True

    # --- engagement-level L0 ----------------------------------------------
    if bundle.engagement_dir is not None:
        if not bundle.engagement_dir.is_dir():
            bundle.context_conflicts.append(f"engagement_dir_missing:{bundle.engagement_dir}")
            bundle.fail_closed = True
        else:
            for name in ENGAGEMENT_L0_FILES:
                path = bundle.engagement_dir / name
                entry = {"purpose": f"engagement L0: {name}", "required": True}
                source = _read_source(path, entry, "L0", loaded_at)
                bundle.loaded_sources.append(source)
                if not source.exists:
                    bundle.missing_required.append(source.path)
                    bundle.fail_closed = True
            for name in ENGAGEMENT_OPTIONAL_FILES:
                path = bundle.engagement_dir / name
                entry = {"purpose": f"engagement L0 optional: {name}", "required": False}
                source = _read_source(path, entry, "L0", loaded_at)
                bundle.loaded_sources.append(source)
                if not source.exists:
                    bundle.unavailable.append(source.path)

    # --- L1: exactly one workflow ------------------------------------------
    workflows = doc["workflows"]
    if workflow is not None:
        if workflow not in workflows:
            raise ContextLoadError(f"workflow not in loading map: {workflow}")
        for entry in workflows[workflow]:
            path = PROJECT_ROOT / entry["path"]
            source = _read_source(path, entry, "L1", loaded_at)
            bundle.loaded_sources.append(source)
            if not source.exists:
                if source.required:
                    bundle.missing_required.append(source.path)
                    bundle.fail_closed = True
                else:
                    bundle.unavailable.append(source.path)
        for other, entries in workflows.items():
            if other == workflow or not entries:
                continue
            bundle.excluded_sources.append(
                ExcludedSource(
                    path=entries[0]["path"],
                    reason=EXCLUSION_OTHER_WORKFLOW,
                    detail=f"workflow '{other}' not active",
                )
            )

    # --- L2: current phase inputs -------------------------------------------
    phases = doc["phases"]
    if phase is not None:
        if phase not in phases:
            raise ContextLoadError(f"phase not in loading map: {phase}")
        for entry in phases[phase]:
            path = PROJECT_ROOT / entry["path"]
            source = _read_source(path, entry, "L2", loaded_at)
            bundle.loaded_sources.append(source)
            if not source.exists:
                if source.required:
                    bundle.missing_required.append(source.path)
                    bundle.fail_closed = True
                else:
                    bundle.unavailable.append(source.path)
            elif entry.get("section"):
                _verify_json_section(source, path, entry["section"], bundle)

    # --- sensitive/forbidden material: exclude by pattern, never read --------
    for guard in ROOT_GUARD_FILES:
        path = PROJECT_ROOT / guard
        if path.is_file():
            bundle.excluded_sources.append(
                ExcludedSource(path=guard, reason=EXCLUSION_CREDENTIAL)
            )
    _scan_forbidden(bundle.run_dir, bundle)
    _scan_forbidden(bundle.engagement_dir, bundle)

    # --- history gate ---------------------------------------------------------
    history_allowed = task_type in HISTORY_TASK_TYPES
    if include_history and not history_allowed:
        bundle.context_conflicts.append(
            f"history_not_allowed_for_task_type:{task_type}"
        )
    if bundle.run_dir is not None and bundle.run_dir.is_dir():
        index = bundle.run_dir / HISTORY_INDEX_NAME
        if include_history and history_allowed:
            if index.is_file():
                _historical_index_inputs(index, bundle)
            else:
                bundle.unavailable.append(str(index))
        else:
            bundle.excluded_sources.append(
                ExcludedSource(
                    path=str(index),
                    reason=EXCLUSION_HISTORY_DISABLED,
                    detail=f"include_history={include_history}, task_type={task_type}",
                )
            )

    return bundle


def summarize(bundle: ContextBundle) -> str:
    """Short pre-execution digest (implementation spec 3.10)."""
    lines = [
        f"task_type={bundle.task_type}",
        f"workflow={bundle.workflow}",
        f"phase={bundle.phase}",
        f"loaded_files={bundle.total_files}",
        f"loaded_bytes={bundle.total_bytes}",
        f"excluded={bundle.excluded_count}",
        f"conflicts={len(bundle.context_conflicts)}",
        f"fail_closed={bundle.fail_closed}",
        f"active_actions_blocked={bundle.active_actions_blocked}",
    ]
    return "\n".join(lines)
