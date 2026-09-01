import unittest

from authorized_assessment.runtime.run_identity import build_run_metadata, canonical_hash, dedup_key


class RunIdentityTests(unittest.TestCase):
    def test_hash_ignores_mapping_order(self):
        self.assertEqual(canonical_hash({"b": 2, "a": 1}), canonical_hash({"a": 1, "b": 2}))

    def test_metadata_contains_lineage_and_hashes(self):
        data = build_run_metadata(
            engagement_id="eng-1", canonical_target="https://example.test", phase="fingerprint",
            config={"delay": 2}, input_data={"targets": ["example.test"]},
            parent_run_id="run-parent", attempt_no=2, retry_of="run-old",
            started_at="2026-08-31T00:00:00+00:00",
        )
        self.assertEqual(data["attempt_no"], 2)
        self.assertEqual(data["retry_of"], "run-old")
        self.assertEqual(len(data["config_hash"]), 64)
        self.assertEqual(data["dedup_key"], dedup_key(engagement_id="eng-1", canonical_target="https://example.test", phase="fingerprint", config_hash=data["config_hash"], input_hash=data["input_hash"]))

    def test_invalid_attempt_and_required_identity_rejected(self):
        with self.assertRaises(ValueError):
            build_run_metadata(engagement_id="", canonical_target="x", phase="p", config={}, input_data={})
        with self.assertRaises(ValueError):
            build_run_metadata(engagement_id="e", canonical_target="x", phase="p", config={}, input_data={}, attempt_no=0)

    def test_metadata_does_not_copy_config_or_input(self):
        data = build_run_metadata(engagement_id="e", canonical_target="x", phase="p", config={"token": "secret"}, input_data={"password": "secret"})
        self.assertNotIn("token", data)
        self.assertNotIn("password", data)


if __name__ == "__main__":
    unittest.main()
