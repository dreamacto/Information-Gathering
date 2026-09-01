import json
import tempfile
import unittest
from pathlib import Path
from authorized_assessment.analysis.review_feedback_ingest import ingest_feedback, normalize_feedback

def row(fid="f1", disposition="rejected"):
    return {"feedback_id":fid,"candidate_id":"cand-1","disposition":disposition,"observed_at":"2026-08-30T00:00:00+00:00","source":"review_ledger","observation":{"product_family":"waf","server_fingerprint":"generic-200","path_pattern":"/admin"},"provenance":{"run_dir":"runs/r1","artifact_ref":"verdicts/1.json"}}

class ReviewFeedbackTests(unittest.TestCase):
    def test_normalize_accepts_final_disposition(self):
        out=normalize_feedback(row())
        self.assertEqual(out["disposition"],"rejected")
        self.assertEqual(out["candidate_id"],"cand-1")
    def test_rejects_unknown_disposition(self):
        with self.assertRaises(ValueError): normalize_feedback(row(disposition="candidate"))
    def test_rejects_sensitive_material(self):
        r=row(); r["observation"]["cookie"]="secret"
        with self.assertRaises(ValueError): normalize_feedback(r)
        r=row(); r["notes"]="authorization bearer-value"
        with self.assertRaises(ValueError): normalize_feedback(r)
    def test_ingest_is_idempotent_and_aggregates(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb=Path(tmp); result=ingest_feedback([row(),row("f2","confirmed")],kb)
            self.assertEqual(result["added"],2)
            again=ingest_feedback([row(),row("f2","confirmed")],kb)
            self.assertEqual(again["added"],0)
            ingest_feedback([row("f3","rejected")],kb)
            feedback=[json.loads(x) for x in (kb/"review_feedback.jsonl").read_text().splitlines()]
            self.assertEqual(len(feedback),3)
            fp=json.loads((kb/"false_positive_patterns.jsonl").read_text().splitlines()[0])
            self.assertEqual(fp["rejected_count"],2); self.assertEqual(fp["confirmed_count"],1); self.assertEqual(fp["precision"],1 / 3)
    def test_invalid_row_is_skipped_without_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=ingest_feedback([{"feedback_id":"bad","candidate_id":"c","disposition":"rejected"}],Path(tmp))
            self.assertEqual(result["accepted"],0); self.assertEqual(len(result["skipped"]),1)

if __name__ == "__main__": unittest.main()
