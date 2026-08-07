import json
import tempfile
import unittest
from pathlib import Path

from miniapp_manual_search_helper import run_helper


class MiniappManualSearchHelperTests(unittest.TestCase):
    def test_generates_keywords_and_imports_in_scope_burp_urls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            targets = root / "targets.txt"
            targets.write_text("https://portal.example.edu.cn|测试学院\n", encoding="utf-8")
            burp = root / "burp.xml"
            burp.write_text("""<?xml version="1.0"?>
<items>
  <item><method>GET</method><url><![CDATA[https://api.example.edu.cn/api/user/info?id=1]]></url></item>
  <item><method>GET</method><url><![CDATA[https://other.test/api/user/info?id=2]]></url></item>
  <item><method>POST</method><url><![CDATA[https://api.example.edu.cn/api/user/update]]></url></item>
</items>
""", encoding="utf-8")
            out_dir = root / "out"
            all_out = root / "burp_miniapp_api_candidates.jsonl"
            in_scope_out = root / "burp_miniapp_in_scope_api_candidates.jsonl"
            main_out = root / "api_candidates.jsonl"
            pending = root / "pending.txt"

            manifest = run_helper(
                targets_file=targets,
                out_dir=out_dir,
                search_pack=True,
                burp_exports=[burp],
                api_candidates_out=all_out,
                in_scope_api_candidates_out=in_scope_out,
                main_api_candidates_out=main_out,
                pending_assets_out=pending,
            )

            self.assertGreater(manifest["keyword_count"], 0)
            self.assertTrue((out_dir / "miniapp_search_urls.html").exists())
            all_rows = [json.loads(line) for line in all_out.read_text(encoding="utf-8").splitlines()]
            main_rows = [json.loads(line) for line in main_out.read_text(encoding="utf-8").splitlines()]
            self.assertTrue(any(row["host"] == "other.test" for row in all_rows))
            self.assertEqual(len(main_rows), 1)
            self.assertIn("https://api.example.edu.cn/api/user/info", main_rows[0]["url"])
            self.assertNotIn("id=1", main_rows[0]["url"])
            self.assertIn("raw_url_sha256", main_rows[0])
            self.assertIn("other.test", pending.read_text(encoding="utf-8"))

    def test_imports_copied_burp_history_table_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            targets = root / "targets.txt"
            targets.write_text("https://portal.example.edu.cn|测试学院\n", encoding="utf-8")
            copied = root / "burp_copied_rows.txt"
            copied.write_text(
                "#\tHost\tMethod\tURL\tStatus code\tMIME type\tTime\n"
                "332\thttps://aaph.example.edu.cn\tPOST\t/blcs/api/miniApp/miniAppPage/list\t200\tJSON\t19:00:40\n"
                "333\thttps://api.example.edu.cn\tGET\t/api/user/info?id=1001\t200\tJSON\t19:00:41\n"
                "334\thttps://api.example.edu.cn\tGET\t/static/app.js\t200\tScript\t19:00:42\n",
                encoding="utf-8",
            )
            out_dir = root / "out"
            main_out = root / "api_candidates.jsonl"

            manifest = run_helper(
                targets_file=targets,
                out_dir=out_dir,
                search_pack=False,
                burp_exports=[copied],
                api_candidates_out=root / "all.jsonl",
                in_scope_api_candidates_out=root / "in_scope.jsonl",
                main_api_candidates_out=main_out,
                pending_assets_out=root / "pending.txt",
            )

            self.assertEqual(manifest["burp_url_count"], 3)
            main_rows = [json.loads(line) for line in main_out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(main_rows), 1)
            self.assertIn("https://api.example.edu.cn/api/user/info", main_rows[0]["url"])
            self.assertNotIn("static", main_rows[0]["url"])


if __name__ == "__main__":
    unittest.main()
