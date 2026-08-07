import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api_discovery import FetchResult
from sqli_triage import (
    UrlParam,
    analyze_probe,
    choose_params,
    is_probably_safe_get_url,
    load_url_params,
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


class SqliTriageTests(unittest.TestCase):
    def test_boolean_differential_marks_high_probability(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            responses = [
                sample("https://example.test/api/list?id=1", text="record id=1 name=alice"),
                sample("https://example.test/api/list?id=1", text="record id=1 name=alice"),
                sample("https://example.test/api/list?id=1'", text="record id=1 name=alice"),
                sample("https://example.test/api/list?id=1 AND 1=1", text="record id=1 name=alice"),
                sample("https://example.test/api/list?id=1 AND 1=2", text="empty result"),
            ]
            with patch("sqli_triage.fetch_wait", side_effect=responses):
                record = analyze_probe(UrlParam("https://example.test/api/list?id=1", "id"), run_dir, 10, 0)
            self.assertTrue(record["high_probability"])
            self.assertIn("boolean_differential", record["signals"])

    def test_500_status_delta_is_candidate_not_high_probability(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            responses = [
                sample("https://example.test/api/list?id=1", text="stable page"),
                sample("https://example.test/api/list?id=1", text="stable page"),
                sample("https://example.test/api/list?id=1'", status=500, text="server error"),
                sample("https://example.test/api/list?id=1 AND 1=1", text="stable page"),
                sample("https://example.test/api/list?id=1 AND 1=2", text="stable page"),
            ]
            with patch("sqli_triage.fetch_wait", side_effect=responses):
                record = analyze_probe(UrlParam("https://example.test/api/list?id=1", "id"), run_dir, 10, 0)
            self.assertFalse(record["high_probability"])
            self.assertEqual(record["confidence"], "medium")
            self.assertIn("quote_status_5xx_delta", record["signals"])

    def test_loader_skips_risky_paths_and_prioritizes_params(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "api_candidates.jsonl").write_text(
                json.dumps({"url": "https://example.test/api/list?callback=x&id=1&keyword=a", "priority_score": 9}) + "\n"
                + json.dumps({"url": "https://example.test/api/download?id=1", "priority_score": 9}) + "\n",
                encoding="utf-8",
            )
            params = load_url_params(run_dir, max_params_per_url=1, max_per_host=5, limit=0, force=False)
            self.assertEqual(len(params), 1)
            self.assertEqual(params[0].param, "id")
            self.assertTrue(is_probably_safe_get_url(params[0].url))
            self.assertEqual(choose_params(params[0].url, 2), ["id", "keyword"])


if __name__ == "__main__":
    unittest.main()
