import csv
import json
import tempfile
import unittest
from pathlib import Path

from operator_action_hub import HUB_DIR_NAME, build_operator_action_hub


class OperatorActionHubTests(unittest.TestCase):
    def test_builds_prominent_login_api_and_weak_credential_queues(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "reports").mkdir()
            (run_dir / "manual_auth_queue.json").write_text(json.dumps({
                "items": [{
                    "base_url": "https://hospital.test",
                    "host": "hospital.test",
                    "scope_state": "in_current_scope",
                    "registration_candidate": False,
                    "reasons": ["fingerprint_login"],
                    "evidence_urls": ["https://hospital.test/login"],
                    "manual_action": "login and paste cookie locally",
                }]
            }, ensure_ascii=False), encoding="utf-8")
            (run_dir / "api_candidates.jsonl").write_text(
                json.dumps({
                    "base_url": "https://hospital.test",
                    "url": "https://hospital.test/api/patient/list?pageSize=1",
                    "tags": ["api", "data_query"],
                    "priority_score": 6,
                }, ensure_ascii=False) + "\n" +
                json.dumps({
                    "base_url": "https://hospital.test",
                    "url": "https://hospital.test/api/patient/export",
                    "tags": ["api", "file_or_upload"],
                    "priority_score": 10,
                }, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            (run_dir / "fingerprints.jsonl").write_text(
                json.dumps({
                    "url": "https://hospital.test/login",
                    "categories": ["login", "java"],
                    "title": "Hospital Login",
                }, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            (run_dir / "priority_targets.json").write_text(json.dumps({
                "items": [{
                    "score": 12,
                    "host": "hospital.test",
                    "url": "https://hospital.test",
                    "reasons": ["fingerprint_login"],
                    "sources": ["fingerprints"],
                }]
            }, ensure_ascii=False), encoding="utf-8")
            (run_dir / "xss_reflection_checks.jsonl").write_text(
                json.dumps({
                    "url": "https://hospital.test/search?q=<redacted>",
                    "probe_url": "https://hospital.test/search?q=xssprobe_test",
                    "host": "hospital.test",
                    "param": "q",
                    "confidence": "medium",
                    "reflection_context": "html_tag_or_attribute",
                    "marker_reflected": True,
                    "manual_check_recommended": True,
                }, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

            summary = build_operator_action_hub(run_dir)

            hub = run_dir / HUB_DIR_NAME
            self.assertTrue((hub / "README_先看这里.md").exists())
            self.assertEqual(summary["login_cookie_queue"], 1)
            self.assertEqual(summary["business_api_review_queue"], 1)
            self.assertEqual(summary["weak_credential_manual_queue"], 1)
            self.assertEqual(summary["reportable_candidates"], 1)
            self.assertEqual(summary["xss_review_queue"], 1)
            self.assertEqual(summary["manual_guides"], 6)
            self.assertTrue((hub / "10_越权和接口泄露复核.md").exists())
            self.assertTrue((hub / "04C_XSS反射候选队列.md").exists())

            with (hub / "02_业务API只读复核队列.csv").open(encoding="utf-8-sig") as handle:
                api_rows = list(csv.DictReader(handle))
            self.assertEqual(len(api_rows), 1)
            self.assertIn("/api/patient/list", api_rows[0]["url"])
            self.assertNotIn("export", api_rows[0]["url"])

            weak_text = (hub / "03_弱口令人工确认队列_不自动跑.md").read_text(encoding="utf-8")
            self.assertIn("不自动跑", weak_text)
            self.assertIn("manual_gate_only", weak_text)
            self.assertNotIn("admin/admin", weak_text)


if __name__ == "__main__":
    unittest.main()
