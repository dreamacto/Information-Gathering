import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api_discovery import FetchResult
from xss_candidate_triage import (
    XssCandidate,
    analyze_reflection,
    choose_params,
    is_parameterized_http_url,
    load_url_params,
    redacted_url,
    reflection_context,
)


def sample(url, status=200, text="stable page", ctype="text/html"):
    return FetchResult(
        url=url,
        status=status,
        final_url=url,
        content_type=ctype,
        content_length=str(len(text)),
        elapsed_seconds=0.01,
        sample_sha256=str(abs(hash(text))),
        text=text,
    )


class XssCandidateTriageTests(unittest.TestCase):
    def test_loader_prioritizes_safe_get_and_marks_stored_manual_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "api_candidates.jsonl").write_text(
                json.dumps({"url": "https://example.test/search?token=abc&q=test&page=1", "priority_score": 3}) + "\n"
                + json.dumps({"url": "https://example.test/comment/save?content=hello", "priority_score": 9}) + "\n",
                encoding="utf-8",
            )
            params = load_url_params(run_dir, max_params_per_url=1, max_per_host=3, limit=0, force=False)
            self.assertEqual(len(params), 2)
            self.assertEqual(params[0].param, "content")
            self.assertEqual(params[0].default_action, "manual_only")
            self.assertEqual(params[1].param, "q")
            self.assertEqual(params[1].default_action, "auto_reflection_check")
            self.assertEqual(choose_params(params[1].url, 3), ["q", "page"])

    def test_reflection_context_classification(self):
        marker = "xssprobe_abc"
        self.assertEqual(reflection_context(f"<script>var q='{marker}'</script>", marker, "text/html"), "script_block")
        self.assertEqual(reflection_context(f"<input value='{marker}'>", marker, "text/html"), "html_tag_or_attribute")
        self.assertEqual(reflection_context(json.dumps({"q": marker}), marker, "application/json"), "json_data")

    def test_analyze_reflection_records_metadata_without_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            candidate = XssCandidate(
                url="https://example.test/search?q=old",
                param="q",
                source="api_candidates.jsonl",
            )
            with patch("xss_candidate_triage.fetch_wait", return_value=sample(
                "https://example.test/search?q=xssprobe_abc",
                text="<input value='xssprobe_abc'>",
            )):
                record = analyze_reflection(candidate, run_dir, timeout=10, delay=0, marker="xssprobe_abc")
            self.assertTrue(record["marker_reflected"])
            self.assertEqual(record["confidence"], "medium")
            self.assertNotIn("text", record)
            self.assertIn("<redacted>", record["url"])

    def test_redacts_query_values(self):
        url = "https://example.test/search?q=test&openid=oABC"
        self.assertTrue(is_parameterized_http_url(url))
        self.assertEqual(redacted_url(url), "https://example.test/search?q=<redacted>&openid=<redacted>")


if __name__ == "__main__":
    unittest.main()
