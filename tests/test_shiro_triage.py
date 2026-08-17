import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shiro_triage import HeaderFetch, analyze_target, api_login_seed_urls, load_seed_urls, refresh_outputs


def sample(url, status=200, headers="", cookies=None, text="home"):
    return HeaderFetch(
        url=url,
        status=status,
        final_url=url,
        content_type="text/html",
        content_length=str(len(text)),
        sample_sha256=str(abs(hash(text))),
        text=text,
        headers_raw=headers,
        set_cookies=cookies or [],
    )


class ShiroTriageTests(unittest.TestCase):
    def test_invalid_rememberme_delete_marks_high_confidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            responses = [
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
            ]
            with patch("shiro_triage.fetch_headers", side_effect=responses), patch("shiro_triage.time.sleep", return_value=None):
                record = analyze_target("https://example.test", run_dir, timeout=10, delay=0)
            self.assertTrue(record["manual_check_recommended"])
            self.assertEqual(record["confidence"], "high")
            self.assertIn("invalid_rememberme_deleted", record["signals"])
            self.assertEqual(record["delete_me_cookie_names"], ["rememberMe"])

    def test_delete_me_already_in_baseline_is_demoted(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            responses = [
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"]),
            ]
            with patch("shiro_triage.fetch_headers", side_effect=responses), patch("shiro_triage.time.sleep", return_value=None):
                record = analyze_target("https://example.test", run_dir, timeout=10, delay=0)
            self.assertTrue(record["baseline_has_delete_me"])
            self.assertNotIn("invalid_rememberme_deleted", record["signals"])
            self.assertIn("delete_me_present_in_baseline_and_probe", record["signals"])
            self.assertEqual(record["confidence"], "medium")

    def test_custom_cookie_name_hits_delete_me(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            responses = [
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["rm=deleteMe; Path=/; Max-Age=0"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
                sample("https://example.test", cookies=["JSESSIONID=abc; Path=/"]),
            ]
            with patch("shiro_triage.fetch_headers", side_effect=responses), patch("shiro_triage.time.sleep", return_value=None):
                record = analyze_target("https://example.test", run_dir, timeout=10, delay=0)
            self.assertEqual(record["confidence"], "high")
            self.assertIn("invalid_rememberme_deleted", record["signals"])
            self.assertEqual(record["delete_me_cookie_names"], ["rm"])

    def test_load_seed_urls_prefers_java_login_oa(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "targets.csv").write_text(
                "url,name,host,scheme,port,source_line\n"
                "https://all.example.test,,all.example.test,https,,1\n",
                encoding="utf-8",
            )
            (run_dir / "fingerprints.jsonl").write_text(
                json.dumps({"url": "https://java.example.test", "categories": ["java"]}) + "\n"
                + json.dumps({"url": "https://other.example.test", "categories": ["other"]}) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(load_seed_urls(run_dir, include_all=False, force=False), ["https://java.example.test"])
            self.assertIn("https://all.example.test", load_seed_urls(run_dir, include_all=True, force=False))

    def test_api_login_seed_urls_filters_login_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "api_candidates.jsonl").write_text(
                json.dumps({"url": "http://x.gov.cn/portal/nndwyw/login.html", "tags": []}) + "\n"
                + json.dumps({"url": "http://x.gov.cn/plain/api", "tags": []}) + "\n"
                + json.dumps({"url": "http://y.gov.cn/sso/login", "tags": []}) + "\n"
                + json.dumps({"url": "http://z.gov.cn/admin", "tags": []}) + "\n",
                encoding="utf-8",
            )
            urls = api_login_seed_urls(run_dir)
            self.assertIn("http://x.gov.cn/portal/nndwyw/login.html", urls)
            self.assertIn("http://y.gov.cn/sso/login", urls)
            self.assertIn("http://z.gov.cn/admin", urls)
            self.assertNotIn("http://x.gov.cn/plain/api", urls)

    def test_load_seed_urls_includes_api_login_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "api_candidates.jsonl").write_text(
                json.dumps({"url": "https://deep.gov.cn/portal/nndwyw/login.html", "tags": []}) + "\n",
                encoding="utf-8",
            )
            self.assertIn("https://deep.gov.cn/portal/nndwyw/login.html", load_seed_urls(run_dir, include_all=False, force=False))

    def test_refresh_outputs_writes_manual_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "shiro_candidates.jsonl").write_text(
                json.dumps({
                    "url": "https://example.test",
                    "host": "example.test",
                    "confidence": "high",
                    "signals": ["invalid_rememberme_deleted"],
                }) + "\n",
                encoding="utf-8",
            )
            refresh_outputs(run_dir)
            self.assertIn("https://example.test", (run_dir / "shiro_detected.txt").read_text(encoding="utf-8"))
            self.assertIn("ShiroAttack2", (run_dir / "shiro_manual_queue.csv").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
