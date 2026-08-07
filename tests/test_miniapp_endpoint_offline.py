import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class MiniappEndpointOfflineTests(unittest.TestCase):
    def test_offline_source_candidates_append_in_scope_api_candidates(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "wxapp"
            source.mkdir()
            (source / "app.js").write_text(
                'const base = "https://api.example.edu.cn";\n'
                'const endpoint = "/api/user/info";\n',
                encoding="utf-8",
            )
            targets = root / "targets.json"
            targets.write_text(json.dumps({
                "targets": [{"url": "https://portal.example.edu.cn", "host": "portal.example.edu.cn"}]
            }), encoding="utf-8")
            out_dir = root / "out"
            aggregate = root / "miniapp_source_api_candidates.jsonl"
            main_api = root / "api_candidates.jsonl"
            pending = root / "pending.txt"
            project = Path(__file__).resolve().parents[1]
            proc = subprocess.run([
                sys.executable,
                str(project / "miniapp_endpoint_offline.py"),
                "--source-dir",
                str(source),
                "--out-dir",
                str(out_dir),
                "--scope-targets",
                str(targets),
                "--api-candidates-out",
                str(aggregate),
                "--in-scope-api-candidates-out",
                str(main_api),
                "--pending-assets-out",
                str(pending),
            ], cwd=project, text=True, encoding="utf-8", errors="replace", capture_output=True)

            self.assertEqual(proc.returncode, 0, proc.stderr)
            aggregate_text = aggregate.read_text(encoding="utf-8")
            main_text = main_api.read_text(encoding="utf-8")
            self.assertIn("https://api.example.edu.cn/api/user/info", aggregate_text)
            self.assertIn("https://api.example.edu.cn/api/user/info", main_text)
            self.assertTrue((out_dir / "微信小程序源码离线分析.md").exists())


if __name__ == "__main__":
    unittest.main()
