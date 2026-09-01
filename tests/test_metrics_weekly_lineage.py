import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import metrics_weekly


class MetricsLineageTests(unittest.TestCase):
    def test_same_dedup_key_counts_latest_run_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("run_a", "run_b"):
                d = root / name
                d.mkdir()
                (d / "candidates.jsonl").write_text('{"candidate":1}\n', encoding="utf-8")
                (d / "run_summary.json").write_text(json.dumps({"dedup_key": "same", "run_id": name}), encoding="utf-8")
            runs, incomplete = metrics_weekly.scan_runs(root, 99999, datetime.now(timezone.utc).astimezone(metrics_weekly.CST))
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["dir"], "run_b")
            self.assertEqual(incomplete, [])

    def test_legacy_runs_remain_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("run_a", "run_b"):
                d = root / name
                d.mkdir()
                (d / "run_summary.json").write_text("{}", encoding="utf-8")
            runs, _ = metrics_weekly.scan_runs(root, 99999, datetime.now(timezone.utc).astimezone(metrics_weekly.CST))
            self.assertEqual(len(runs), 2)


if __name__ == "__main__":
    unittest.main()
