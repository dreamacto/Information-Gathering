import unittest

from authorized_assessment.runtime.run_dedup import find_reuse
from authorized_assessment.runtime.run_identity import build_run_metadata


class RunDedupTests(unittest.TestCase):
    def setUp(self):
        self.meta = build_run_metadata(engagement_id="e", canonical_target="https://x", phase="p", config={"a": 1}, input_data={"b": 2}, started_at="2026-08-30T00:00:00+00:00")
        self.meta["run_id"] = "run-1"
        self.meta["finished_at"] = "2026-08-30T00:30:00+00:00"
        self.meta["terminal_state"] = "complete"

    def test_same_key_in_cooldown_reuses(self):
        out = find_reuse(self.meta, [self.meta], now="2026-08-30T01:00:00+00:00", cooldown_seconds=3600)
        self.assertEqual(out["action"], "resume_delta")
        self.assertEqual(out["matched_run_id"], "run-1")

    def test_outside_cooldown_runs_full(self):
        out = find_reuse(self.meta, [self.meta], now="2026-08-30T02:00:01+00:00", cooldown_seconds=3600)
        self.assertFalse(out["duplicate"])
        self.assertEqual(out["action"], "full_run")

    def test_nonterminal_is_not_reused(self):
        row = dict(self.meta, terminal_state="in_progress")
        out = find_reuse(self.meta, [row], now="2026-08-30T01:00:00+00:00")
        self.assertFalse(out["duplicate"])


if __name__ == "__main__":
    unittest.main()
