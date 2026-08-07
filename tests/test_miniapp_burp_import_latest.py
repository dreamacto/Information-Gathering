import json
import tempfile
import unittest
from pathlib import Path

import miniapp_burp_import_latest as latest


class MiniappBurpImportLatestTests(unittest.TestCase):
    def test_prefers_latest_one_click_run_over_stale_marker(self):
        old_runs_dir = latest.RUNS_DIR
        try:
            with tempfile.TemporaryDirectory() as temp:
                runs = Path(temp) / "runs"
                runs.mkdir()
                old_run = runs / "20260721_130346_gx_gov"
                new_run = runs / "20260725_201122_one_click_full_weak"
                old_run.mkdir()
                new_run.mkdir()
                for run in [old_run, new_run]:
                    (run / "targets.json").write_text(json.dumps({
                        "source": "",
                        "targets": [{"url": "https://example.test", "host": "example.test"}],
                    }), encoding="utf-8")
                (runs / "last_one_click_run.txt").write_text(str(old_run), encoding="utf-8")
                latest.RUNS_DIR = runs

                selected, reason = latest.find_latest_run()

                self.assertEqual(selected, new_run)
                self.assertEqual(reason, "latest_one_click_run_by_folder_timestamp")
        finally:
            latest.RUNS_DIR = old_runs_dir

    def test_result_directory_name_is_single_burp_output_folder(self):
        self.assertEqual(latest.MINIAPP_BURP_DIR_NAME, "07_小程序Burp导入结果")

    def test_result_directory_uses_dragged_file_stem(self):
        run_dir = Path(r"D:\runs\20260725_200000_one_click_full_weak")
        export = Path(r"D:\Desktop\学院A小程序.txt")

        result = latest.result_dir_for_export(run_dir, export)

        self.assertEqual(result.name, "学院A小程序_导入结果")
        self.assertEqual(result.parent.name, "07_小程序Burp导入结果")


if __name__ == "__main__":
    unittest.main()
