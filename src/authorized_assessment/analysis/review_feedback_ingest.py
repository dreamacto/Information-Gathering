"""Offline, deterministic ingestion of finalized review feedback."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DISPOSITIONS = {
    "confirmed", "rejected", "accepted_risk", "duplicate",
    "needs_login", "approval_required", "blocked",
}
SENSITIVE = re.compile(
    r"(?:cookie|authorization|token|password|secret|private[_ -]?key|credential|set-cookie)",
    re.I,
)
OBSERVATION_FIELDS = (
    "product_family", "server_fingerprint", "response_status", "content_type",
    "body_similarity", "path_pattern", "negative_context", "api_source",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(value):
    return None if value is None else str(value).strip() or None


def feedback_key(row: dict) -> str:
    value = str(row.get("feedback_id") or row.get("id") or "").strip()
    if not value:
        raise ValueError("feedback_id is required")
    return value


def _safe(value) -> bool:
    if isinstance(value, dict):
        return all(not SENSITIVE.search(str(k)) and _safe(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return all(_safe(v) for v in value)
    if isinstance(value, str):
        return not SENSITIVE.search(value)
    return True


def normalize_feedback(row: dict) -> dict:
    if not isinstance(row, dict) or not _safe(row):
        raise ValueError("feedback contains sensitive material")
    disposition = str(row.get("disposition") or row.get("status") or "").strip().lower()
    if disposition not in DISPOSITIONS:
        raise ValueError(f"unsupported disposition: {disposition}")
    observation = row.get("observation") if isinstance(row.get("observation"), dict) else {}
    provenance = row.get("provenance") if isinstance(row.get("provenance"), dict) else {}
    run_dir = _text(provenance.get("run_dir") or row.get("run_dir"))
    artifact_ref = _text(provenance.get("artifact_ref") or row.get("evidence_ref"))
    if not run_dir or not artifact_ref:
        raise ValueError("provenance.run_dir and provenance.artifact_ref are required")
    candidate_id = str(row.get("candidate_id") or row.get("candidate_key") or "").strip()
    if not candidate_id:
        raise ValueError("candidate_id is required")
    return {
        "feedback_id": feedback_key(row),
        "candidate_id": candidate_id,
        "disposition": disposition,
        "observed_at": _text(row.get("observed_at") or row.get("ts")) or now_iso(),
        "source": _text(row.get("source")) or "review_ledger",
        "observation": {key: observation[key] for key in OBSERVATION_FIELDS if key in observation},
        "provenance": {
            "run_dir": run_dir,
            "artifact_ref": artifact_ref,
            "line": provenance.get("line"),
        },
        "notes": _text(row.get("notes") or row.get("note")),
    }


def _read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                rows.append(value)
    return rows


def _append_unique(path: Path, rows: list[dict], key_field: str = "feedback_id") -> int:
    existing = _read(path)
    keys = {str(item.get(key_field)) for item in existing if item.get(key_field)}
    added = 0
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            key = str(row.get(key_field) or "")
            if not key or key in keys:
                continue
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            keys.add(key)
            added += 1
    return added


def _pattern_id(key: tuple) -> str:
    return hashlib.sha256("|".join(str(value) for value in key).encode()).hexdigest()[:16]


def ingest_feedback(rows, knowledge_base_dir) -> dict:
    """Validate finalized rows and append feedback plus deterministic aggregates."""
    knowledge_base = Path(knowledge_base_dir).resolve()
    knowledge_base.mkdir(parents=True, exist_ok=True)
    normalized, skipped = [], []
    for row in rows:
        try:
            normalized.append(normalize_feedback(row))
        except ValueError as error:
            skipped.append({"reason": str(error)})
    normalized.sort(key=lambda item: item["feedback_id"])
    added = _append_unique(knowledge_base / "review_feedback.jsonl", normalized)

    groups = defaultdict(list)
    for item in _read(knowledge_base / "review_feedback.jsonl"):
        observation = item.get("observation", {})
        key = tuple(observation.get(name) for name in ("product_family", "server_fingerprint", "path_pattern"))
        groups[key].append(item)
    false_positive, precision = [], []
    for key, values in sorted(groups.items(), key=lambda pair: repr(pair[0])):
        confirmed = sum(item["disposition"] == "confirmed" for item in values)
        rejected = sum(item["disposition"] == "rejected" for item in values)
        total = confirmed + rejected
        if rejected:
            false_positive.append({
                "pattern_id": _pattern_id(key), "product_family": key[0],
                "server_fingerprint": key[1], "path_pattern": key[2],
                "first_seen": min(item["observed_at"] for item in values),
                "last_seen": max(item["observed_at"] for item in values),
                "sample_count": len(values), "candidate_count": len(values),
                "confirmed_count": confirmed, "rejected_count": rejected,
                "precision": confirmed / total if total else 0.0,
                "suppression_rule": "downgrade_known_false_positive" if confirmed == 0 else "retain_signal",
            })
        precision.append({
            "pattern_id": _pattern_id(key), "candidate_count": len(values),
            "confirmed_count": confirmed, "rejected_count": rejected,
            "precision": confirmed / total if total else None,
            "last_seen": max(item["observed_at"] for item in values),
        })
    for path, values in (
        (knowledge_base / "false_positive_patterns.jsonl", false_positive),
        (knowledge_base / "fingerprint_precision.jsonl", precision),
    ):
        path.write_text(
            "".join(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n" for value in values),
            encoding="utf-8",
            newline="\n",
        )
    return {"accepted": len(normalized), "added": added, "skipped": skipped}
