import json
import tempfile
import unittest
from http.cookiejar import CookieJar
from pathlib import Path
from unittest.mock import patch

from weak_credential_review import (
    credential_pairs_for_candidate,
    parse_login_form,
    run_review,
)


class WeakCredentialReviewTests(unittest.TestCase):
    def test_dynamic_pairs_are_limited_and_product_aware(self):
        jeecg_pairs = credential_pairs_for_candidate({
            "base_url": "https://example.test",
            "reason": ["product_login_default_credential_review"],
            "evidence": ["Jeecg Boot login"],
        }, 5)
        generic_pairs = credential_pairs_for_candidate({
            "base_url": "https://example.test",
            "reason": ["fingerprint_login"],
        }, 5)

        self.assertEqual(len(jeecg_pairs), 5)
        self.assertEqual(len(generic_pairs), 5)
        self.assertEqual(jeecg_pairs[0]["username"], "admin")
        self.assertEqual(jeecg_pairs[0]["password"], "123456")
        self.assertTrue(all("123456" not in pair["preset_id"] for pair in jeecg_pairs))

    def test_parse_post_login_form(self):
        form, reason = parse_login_form("https://example.test/login", """
        <form method="post" action="/doLogin">
          <input type="hidden" name="csrf" value="abc">
          <input name="username">
          <input type="password" name="password">
        </form>
        """)
        self.assertEqual(reason, "")
        self.assertIsNotNone(form)
        self.assertEqual(form.action, "https://example.test/doLogin")

    def test_run_review_does_not_persist_password_cookie_or_body(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "manual_auth_queue.json").write_text(json.dumps({
                "items": [{
                    "base_url": "https://example.test",
                    "host": "example.test",
                    "scope_state": "in_current_scope",
                    "registration_candidate": False,
                    "reasons": ["fingerprint_login"],
                    "evidence_urls": ["https://example.test/login"],
                }]
            }), encoding="utf-8")
            (run_dir / "fingerprints.jsonl").write_text("", encoding="utf-8")

            def fake_fetch_text_simple(url, timeout):
                return (
                    {"status": 200, "final_url": url, "content_type": "text/html", "sample_length": 1, "sample_sha256": "a", "set_cookie_present": False, "error": ""},
                    """
                    <form method="post" action="/login">
                      <input name="username">
                      <input type="password" name="password">
                    </form>
                    """,
                    CookieJar(),
                )

            def fake_submit(opener, form, pair, timeout):
                return (
                    {"status": 200, "final_url": "https://example.test/dashboard", "content_type": "text/html", "sample_length": 11, "sample_sha256": "b", "set_cookie_present": True, "error": ""},
                    "Welcome dashboard logout SECRET_RESPONSE_VALUE",
                )

            with patch("weak_credential_review.fetch_text_simple", side_effect=fake_fetch_text_simple), patch(
                "weak_credential_review.submit_login_form", side_effect=fake_submit
            ), patch("weak_credential_review.time.sleep", return_value=None):
                manifest = run_review(run_dir, max_targets=1, max_pairs=5, delay=0, timeout=5, force=True)

            self.assertEqual(manifest["outcomes"][0]["status"], "success")
            combined = "\n".join(
                path.read_text(encoding="utf-8", errors="ignore")
                for path in run_dir.iterdir()
                if path.is_file()
            )
            self.assertNotIn("123456", combined)
            self.assertNotIn("admin123", combined)
            self.assertNotIn("SECRET_RESPONSE_VALUE", combined)
            self.assertNotIn("Set-Cookie", combined)
            self.assertIn("password_persisted", combined)
            self.assertIn("cookie_persisted", combined)

    def test_auto_auth_uses_transient_token_without_persisting_value(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "manual_auth_queue.json").write_text(json.dumps({
                "items": [{
                    "base_url": "https://example.test",
                    "host": "example.test",
                    "scope_state": "in_current_scope",
                    "registration_candidate": False,
                    "reasons": ["jeecg_login"],
                    "evidence_urls": ["https://example.test/login"],
                }]
            }), encoding="utf-8")
            (run_dir / "fingerprints.jsonl").write_text("", encoding="utf-8")
            token_value = "eyJhbGciOiAUTOSECRET"
            captured = {}

            def fake_fetch_text_simple(url, timeout):
                return (
                    {"status": 200, "final_url": url, "content_type": "text/html", "sample_length": 1, "sample_sha256": "a", "set_cookie_present": False, "error": ""},
                    """
                    <form method="post" action="/jeecg-boot/sys/login">
                      <input name="username">
                      <input type="password" name="password">
                    </form>
                    """,
                    CookieJar(),
                )

            def fake_submit(opener, form, pair, timeout):
                return (
                    {"status": 200, "final_url": "https://example.test/dashboard", "content_type": "application/json", "sample_length": 64, "sample_sha256": "c", "set_cookie_present": False, "error": ""},
                    json.dumps({"success": True, "result": {"token": token_value}}, ensure_ascii=False),
                )

            def fake_auto_auth(**kwargs):
                captured["sessions"] = kwargs["sessions"]
                captured["manifest_name"] = kwargs["manifest_name"]
                return {
                    "session_count": len(kwargs["sessions"]),
                    "request_count": 1,
                    "impact_count": 0,
                    "cookie_persisted": False,
                    "token_persisted": False,
                }

            with patch("weak_credential_review.fetch_text_simple", side_effect=fake_fetch_text_simple), patch(
                "weak_credential_review.submit_login_form", side_effect=fake_submit
            ), patch("weak_credential_review.run_authenticated_review_with_sessions", side_effect=fake_auto_auth), patch(
                "weak_credential_review.time.sleep", return_value=None
            ):
                manifest = run_review(
                    run_dir,
                    max_targets=1,
                    max_pairs=5,
                    delay=0,
                    timeout=5,
                    force=True,
                    auto_auth_review=True,
                    auth_max_js=1,
                    auth_max_endpoints=1,
                )

            self.assertEqual(manifest["auto_auth_transient_session_count"], 1)
            self.assertEqual(captured["manifest_name"], "weak_auto_authenticated_review_manifest.json")
            self.assertIn("Authorization", captured["sessions"][0]["headers"])
            self.assertIn(token_value, captured["sessions"][0]["headers"]["Authorization"])
            combined = "\n".join(
                path.read_text(encoding="utf-8", errors="ignore")
                for path in run_dir.iterdir()
                if path.is_file()
            )
            self.assertNotIn(token_value, combined)
            self.assertIn("transient_token_keys", combined)
            self.assertIn("token_persisted", combined)


if __name__ == "__main__":
    unittest.main()
