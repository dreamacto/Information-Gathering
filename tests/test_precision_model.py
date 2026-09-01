import unittest

from authorized_assessment.analysis.precision_model import (
    KNOWN_FP,
    KNOWN_HIGH,
    UNKNOWN,
    classify_feedback,
    rank_candidates,
)


class PrecisionModelTests(unittest.TestCase):
    def test_known_false_positive_requires_two_rejections(self):
        signal = classify_feedback({"pattern_id": "p", "candidate_count": 2, "confirmed_count": 0, "rejected_count": 2})
        self.assertEqual(signal["classification"], KNOWN_FP)

    def test_single_rejection_stays_unknown(self):
        signal = classify_feedback({"candidate_count": 1, "confirmed_count": 0, "rejected_count": 1})
        self.assertEqual(signal["classification"], UNKNOWN)

    def test_high_precision_threshold(self):
        signal = classify_feedback({"candidate_count": 5, "confirmed_count": 4, "rejected_count": 1})
        self.assertEqual(signal["classification"], KNOWN_HIGH)

    def test_boundary_below_high_precision_is_unknown(self):
        signal = classify_feedback({"candidate_count": 5, "confirmed_count": 3, "rejected_count": 2})
        self.assertEqual(signal["classification"], UNKNOWN)

    def test_rank_is_deterministic_and_preserves_status(self):
        aggregates = [
            {"pattern_id": "fp", "product_family": "waf", "server_fingerprint": "generic", "path_pattern": "/", "candidate_count": 2, "confirmed_count": 0, "rejected_count": 2},
            {"pattern_id": "hi", "product_family": "app", "server_fingerprint": "nginx", "path_pattern": "/api", "candidate_count": 2, "confirmed_count": 2, "rejected_count": 0},
        ]
        candidates = [
            {"candidate_id": "a", "finding_status": "candidate", "observation": {"product_family": "waf", "server_fingerprint": "generic", "path_pattern": "/"}},
            {"candidate_id": "b", "finding_status": "candidate", "observation": {"product_family": "app", "server_fingerprint": "nginx", "path_pattern": "/api"}},
        ]
        result = rank_candidates(candidates, aggregates)
        self.assertEqual([row["candidate_id"] for row in result], ["b", "a"])
        self.assertEqual([row["finding_status"] for row in result], ["candidate", "candidate"])
        self.assertEqual(result[0]["precision_signal"], KNOWN_HIGH)


if __name__ == "__main__":
    unittest.main()
