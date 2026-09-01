"""Tests for context_snapshot.py (implementation spec 3.8/3.10/3.11)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from authorized_assessment.runtime import context_loader as cl
from authorized_assessment.runtime import context_snapshot as cs


@pytest.fixture()
def bundle_snapshot() -> dict:
    bundle = cl.load_context(task_type="offline_implementation", workflow="wz")
    return cs.build_snapshot_from_bundle(bundle)


def test_roundtrip_write_load_restore(bundle_snapshot: dict, tmp_path: Path):
    target = tmp_path / "context_snapshot.json"
    written = cs.write_context_snapshot(bundle_snapshot, target)
    assert written == target
    loaded = cs.load_context_snapshot(target)
    assert cs.validate_context_snapshot(loaded) == []
    restored = cs.restore_from_snapshot(loaded)
    assert restored["task_type"] == "offline_implementation"
    assert restored["workflow"] == "wz"
    assert restored["phase"] is None
    assert restored["policy_digest"]["authorization_status"] == "unknown"
    assert any(f.startswith("policy_snapshot.authorization_status") for f in restored["current_facts"])


def test_snapshot_written_next_to_run_dir(tmp_path: Path):
    run_dir = tmp_path / "runs" / "20260829_130000"
    run_dir.mkdir(parents=True)
    snapshot, written = cs.create_for_task(
        task_type="review", run_dir=run_dir, include_history=False
    )
    assert written == run_dir / "context_snapshot.json"
    assert written.is_file()
    assert snapshot["task_type"] == "review"


def test_snapshot_written_to_engagement_notes(tmp_path: Path):
    engagement = tmp_path / "engagements" / "example.test"
    engagement.mkdir(parents=True)
    (engagement / "engagement.json").write_text("{}", encoding="utf-8")
    (engagement / "scope.csv").write_text("host\n", encoding="utf-8")
    snapshot, written = cs.create_for_task(
        task_type="offline_implementation", engagement_dir=engagement
    )
    assert written == engagement / "notes" / "context_snapshot.json"
    assert snapshot["engagement_id"] is None  # 传入的是目录而非登记的 id 字段


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda s: s.pop("current_facts"), "missing required field: current_facts"),
        (lambda s: s.__setitem__("task_type", ""), "task_type must be a non-empty string"),
        (lambda s: s["loaded_sources"][0].pop("sha256"), "missing field: sha256"),
        (lambda s: s["loaded_sources"][0].__setitem__("required", "yes"), "must be a boolean"),
        (
            lambda s: s["historical_inputs"].append({"path": "x", "classification": "current"}),
            "classification invalid",
        ),
        (lambda s: s["excluded_sources"].append({"path": "x", "reason": "meh"}), "not in schema enum"),
        (lambda s: s.setdefault("headers", {}).__setitem__("cookie", "abc"), "credential-like key"),
    ],
)
def test_validator_negatives(bundle_snapshot: dict, mutate, expected: str):
    doc = json.loads(json.dumps(bundle_snapshot))
    doc["loaded_sources"] = doc.get("loaded_sources") or [{"path": "p", "purpose": "u", "sha256": "h", "loaded_at": "t", "required": False}]
    doc["historical_inputs"] = doc.get("historical_inputs") or []
    doc["excluded_sources"] = doc.get("excluded_sources") or []
    mutate(doc)
    errors = cs.validate_context_snapshot(doc)
    assert any(expected in err for err in errors), errors


def test_write_refuses_invalid_snapshot(bundle_snapshot: dict, tmp_path: Path):
    bad = json.loads(json.dumps(bundle_snapshot))
    bad.pop("created_at")
    with pytest.raises(ValueError, match="refusing to write"):
        cs.write_context_snapshot(bad, tmp_path / "bad.json")
    assert not (tmp_path / "bad.json").exists()


def test_hash_verify_detects_drift_and_missing(bundle_snapshot: dict):
    assert cs.verify_source_hashes(bundle_snapshot) == []
    tampered = json.loads(json.dumps(bundle_snapshot))
    first_path = sorted(tampered["source_hashes"])[0]
    tampered["source_hashes"][first_path] = "0" * 64
    problems = cs.verify_source_hashes(tampered)
    assert problems == [f"hash_drift:{first_path}"]
    ghost = json.loads(json.dumps(bundle_snapshot))
    ghost["source_hashes"]["ghost/missing.md"] = "1" * 64
    assert f"source_missing:ghost/missing.md" in cs.verify_source_hashes(ghost)


def test_history_never_mixed_into_current_facts(bundle_snapshot: dict):
    doc = json.loads(json.dumps(bundle_snapshot))
    doc["historical_inputs"] = [
        {"path": "runs/old/candidates.json", "classification": "historical_fact"},
        {"path": "runs/old/patterns.json", "classification": "derived_pattern"},
    ]
    assert cs.validate_context_snapshot(doc) == []
    historical_paths = {item["path"] for item in doc["historical_inputs"]}
    assert not historical_paths.intersection(set(doc["current_facts"]))
    assert doc["current_facts"] == bundle_snapshot["current_facts"]


def test_cli_create_and_verify(tmp_path: Path):
    run_dir = tmp_path / "runs" / "20260829_140000"
    run_dir.mkdir(parents=True)
    rc = cs.main(
        [
            "--task-type", "review",
            "--run-dir", str(run_dir),
        ]
    )
    assert rc == 0
    snapshot_path = run_dir / "context_snapshot.json"
    assert snapshot_path.is_file()
    rc_verify = cs.main(["--verify", str(snapshot_path)])
    assert rc_verify == 0
    tampered = json.loads(snapshot_path.read_text(encoding="utf-8"))
    key = sorted(tampered["source_hashes"])[0]
    tampered["source_hashes"][key] = "f" * 64
    bad_path = tmp_path / "tampered.json"
    bad_path.write_text(json.dumps(tampered), encoding="utf-8")
    assert cs.main(["--verify", str(bad_path)]) == 1


def test_bundle_snapshot_conflicts_and_exclusions_recorded(bundle_snapshot: dict):
    # 默认快照 authorization_status=unknown → 必须携带 scope 冲突；wz 激活 → 其他 workflow 被排除。
    assert any(c.startswith("scope_not_confirmed") for c in bundle_snapshot["context_conflicts"])
    reasons = {e["reason"] for e in bundle_snapshot["excluded_sources"]}
    assert "other_workflow" in reasons
