import json
import tempfile
import unittest
from pathlib import Path

from screenshot_queue_builder import build_screenshot_queue


class ScreenshotQueueBuilderTests(unittest.TestCase):
    def test_builds_public_and_manual_screenshot_queue(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "reports").mkdir()
            (run_dir / "evidence").mkdir()
            (run_dir / "manual_auth_queue.json").write_text(json.dumps({
                "items": [{
                    "base_url": "https://portal.example.test",
                    "evidence_urls": ["https://portal.example.test/login"],
                    "reasons": ["fingerprint_login"],
                }]
            }), encoding="utf-8")
            (run_dir / "priority_targets.json").write_text(json.dumps({
                "items": [{
                    "url": "https://portal.example.test",
                    "score": 12,
                    "reasons": ["login"],
                }]
            }), encoding="utf-8")
            (run_dir / "api_interesting.jsonl").write_text(json.dumps({
                "url": "https://portal.example.test/api/student/list?page=1",
                "tags": ["api", "data_query"],
            }) + "\n", encoding="utf-8")
            (run_dir / "verified_exposures.jsonl").write_text(json.dumps({
                "base_url": "https://portal.example.test",
                "path": "/.env",
                "kind": "env_file",
            }) + "\n", encoding="utf-8")

            summary = build_screenshot_queue(run_dir)

            self.assertGreaterEqual(summary["total"], 3)
            self.assertGreaterEqual(summary["public_metadata_only"], 1)
            self.assertGreaterEqual(summary["manual_auth_required"], 1)
            self.assertGreaterEqual(summary["manual_redaction_required"], 1)
            self.assertTrue((run_dir / "reports" / "screenshot_queue.csv").exists())
            self.assertTrue((run_dir / "reports" / "screenshot_queue.md").exists())
            self.assertTrue((run_dir / "evidence" / "screenshots" / "README_截图说明.md").exists())
            self.assertTrue((run_dir / "evidence" / "screenshots" / "截图队列_一键采集.bat").exists())


if __name__ == "__main__":
    unittest.main()
