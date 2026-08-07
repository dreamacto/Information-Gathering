import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from authenticated_session_review import build_manual_auth_handoff, run_authenticated_review


class AuthenticatedSessionReviewTests(unittest.TestCase):
    def test_handoff_detects_login_and_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "reports").mkdir()
            (run_dir / "fingerprints.jsonl").write_text(
                json.dumps({"url": "https://example.test", "categories": ["login"]}) + "\n",
                encoding="utf-8",
            )
            (run_dir / "api_candidates.jsonl").write_text(
                json.dumps({
                    "base_url": "https://example.test",
                    "url": "https://example.test/api/user/register",
                    "tags": ["api"],
                }) + "\n",
                encoding="utf-8",
            )
            result = build_manual_auth_handoff(run_dir)
            queue = json.loads((run_dir / "manual_auth_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(result["count"], 1)
            self.assertTrue(queue["items"][0]["registration_candidate"])

    def test_handoff_merges_wechat_login_domains(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "fingerprints.jsonl").write_text("", encoding="utf-8")
            (run_dir / "api_candidates.jsonl").write_text("", encoding="utf-8")
            (run_dir / "api_discovery.jsonl").write_text("", encoding="utf-8")
            (run_dir / "wechat_auth_domains.json").write_text(json.dumps({"items": [{
                "base_url": "https://mini.hospital.test",
                "login_urls": ["https://mini.hospital.test/api/login"],
                "registration_candidate": False,
                "scope_state": "in_current_scope",
            }]}), encoding="utf-8")
            build_manual_auth_handoff(run_dir)
            queue = json.loads((run_dir / "manual_auth_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(queue["count"], 1)
            self.assertEqual(queue["items"][0]["host"], "mini.hospital.test")
            self.assertEqual(queue["items"][0]["scope_state"], "in_current_scope")

    def test_authenticated_review_keeps_cookie_and_values_out_of_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "targets.json").write_text(json.dumps({
                "count": 1,
                "targets": [{"url": "https://example.test"}],
            }), encoding="utf-8")
            (run_dir / "api_candidates.jsonl").write_text("", encoding="utf-8")
            cookie_file = run_dir / "auth_sessions.local.json"
            cookie_file.write_text(json.dumps({"sessions": [{
                "base_url": "https://example.test",
                "entry_url": "https://example.test/dashboard",
                "cookie": "SESSION=super-secret-cookie",
            }]}), encoding="utf-8")

            def fake_fetch(url, headers, timeout, max_bytes=131072):
                base = {
                    "checked_at": "now", "url": url, "status": 200, "final_url": url,
                    "content_type": "text/html", "declared_content_length": "", "sample_length": 10,
                    "sample_sha256": "abc", "elapsed_seconds": 0.01, "set_cookie_present": False, "error": "",
                }
                if url.endswith("/dashboard"):
                    return base, '<html><script src="/app.js"></script><h1>Dashboard</h1></html>'
                if url.endswith("/app.js"):
                    return base, 'const endpoint="/api/data/list";'
                base["content_type"] = "application/json"
                return base, json.dumps({"records": [{"realName": "private-value", "mobile": "13800000000"}]})

            with patch("authenticated_session_review.fetch_metadata", side_effect=fake_fetch), patch(
                "authenticated_session_review.time.sleep", return_value=None
            ):
                result = run_authenticated_review(run_dir, cookie_file, 0, 5, 3, 5)

            combined = "\n".join(
                path.read_text(encoding="utf-8", errors="ignore")
                for path in run_dir.iterdir()
                if path.name not in {cookie_file.name, "targets.json"}
            )
            self.assertEqual(result["impact_count"], 1)
            self.assertNotIn("super-secret-cookie", combined)
            self.assertNotIn("private-value", combined)
            self.assertIn("realName", combined)
            self.assertIn("mobile", combined)


if __name__ == "__main__":
    unittest.main()
