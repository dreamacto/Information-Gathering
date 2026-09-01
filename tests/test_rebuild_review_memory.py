import json
import tempfile
import unittest
from pathlib import Path

from scripts.maintenance.rebuild_review_memory import rebuild


def feedback(fid, disposition="rejected"):
    return {
        "feedback_id": fid,
        "candidate_id": "candidate-1",
        "disposition": disposition,
        "observed_at": "2026-08-30T00:00:00+00:00",
        "source": "review_ledger",
        "observation": {"product_family": "waf", "server_fingerprint": "generic", "path_pattern": "/"},
        "provenance": {"run_dir": "runs/r1", "artifact_ref": "verdicts/1.json"},
    }


class RebuildTests(unittest.TestCase):
    def test_rebuild_is_deterministic_and_replaces_stale_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "input.jsonl"
            source.write_text("\n".join(json.dumps(item) for item in [feedback("b"), feedback("a", "confirmed")]) + "\n", encoding="utf-8")
            kb = root / "kb"
            first = rebuild(source, kb)
            first_bytes = {name: (kb / name).read_bytes() for name in ("review_feedback.jsonl", "false_positive_patterns.jsonl", "fingerprint_precision.jsonl")}
            (kb / "false_positive_patterns.jsonl").write_text("stale\n", encoding="utf-8")
            second = rebuild(source, kb)
            second_bytes = {name: (kb / name).read_bytes() for name in first_bytes}
            self.assertEqual(first["added"], 2)
            self.assertEqual(second["added"], 2)
            self.assertEqual(first_bytes, second_bytes)

    def test_invalid_and_sensitive_rows_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "input.jsonl"
            bad = feedback("bad")
            bad["provenance"] = {}
            source.write_text(json.dumps(bad) + "\nnot-json\n", encoding="utf-8")
            result = rebuild(source, root / "kb")
            self.assertEqual(result["accepted"], 0)
            self.assertEqual(len(result["skipped"]), 1)


if __name__ == "__main__":
    unittest.main()
