import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import subdomain_bruteforce_controlled as controlled
from subdomain_bruteforce_controlled import (
    build_queries,
    dedup_target_lines,
    is_host_within_scope,
    load_existing_target_lines,
    load_roots,
    load_scope_anchors,
    registered_parent,
    scope_anchor_for,
)


class SubdomainBruteforceControlledTests(unittest.TestCase):
    def test_registered_parent_handles_common_cn_suffix(self):
        self.assertEqual(registered_parent("api.example.com.cn"), "example.com.cn")
        self.assertEqual(registered_parent("www.example.cn"), "example.cn")

    def test_registered_parent_rejects_ips_and_placeholders(self):
        self.assertEqual(registered_parent("10.10.0.2"), "")
        self.assertEqual(registered_parent("0.2"), "")
        self.assertEqual(registered_parent("靶标url"), "")

    def test_load_scope_anchors_preserves_exact_csv_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.csv"
            path.write_text(
                "url,name,host,scheme,port,source_line\n"
                "https://www.example.com.cn,Example,www.example.com.cn,https,,1\n",
                encoding="utf-8",
            )
            self.assertEqual(load_scope_anchors(path), ["www.example.com.cn"])
            self.assertEqual(load_roots(path), ["www.example.com.cn"])

    def test_load_scope_anchors_skips_ip_targets_without_parent_widening(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.txt"
            path.write_text(
                "https://10.10.0.2:9212/\n"
                "https://api.example.com.cn/path\n"
                "https://靶标url\n",
                encoding="utf-8",
            )
            self.assertEqual(load_scope_anchors(path), ["api.example.com.cn"])

    def test_input_subdomain_never_becomes_parent_or_sibling_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.txt"
            path.write_text(
                "https://bgjt.bbwport.net|北港金投业务管理系统\n",
                encoding="utf-8",
            )
            anchors = load_scope_anchors(path)
            queries = build_queries(anchors, ["admin", "login"], 0)

            self.assertEqual(anchors, ["bgjt.bbwport.net"])
            self.assertEqual(queries, [
                ("bgjt.bbwport.net", "admin.bgjt.bbwport.net"),
                ("bgjt.bbwport.net", "login.bgjt.bbwport.net"),
            ])
            generated_hosts = {host for _, host in queries}
            self.assertNotIn("bbwport.net", anchors)
            self.assertNotIn("admin.bbwport.net", generated_hosts)
            self.assertNotIn("login.bbwport.net", generated_hosts)

    def test_scope_matching_rejects_parent_and_sibling_hosts(self):
        anchor = "bgjt.bbwport.net"
        self.assertTrue(is_host_within_scope(anchor, anchor))
        self.assertTrue(is_host_within_scope("api.bgjt.bbwport.net", anchor))
        self.assertFalse(is_host_within_scope("bbwport.net", anchor))
        self.assertFalse(is_host_within_scope("login.bbwport.net", anchor))
        self.assertEqual(
            scope_anchor_for("api.bgjt.bbwport.net", [anchor]),
            anchor,
        )
        self.assertEqual(scope_anchor_for("login.bbwport.net", [anchor]), "")

    def test_main_keeps_generated_outputs_below_exact_input_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            targets = tmp_path / "targets.txt"
            wordlist = tmp_path / "words.txt"
            out_dir = tmp_path / "out"
            targets.write_text(
                "https://bgjt.bbwport.net|北港金投业务管理系统\n",
                encoding="utf-8",
            )
            wordlist.write_text("admin\nlogin\n", encoding="utf-8")
            argv = [
                "subdomain_bruteforce_controlled.py",
                "--targets",
                str(targets),
                "--out-dir",
                str(out_dir),
                "--wordlist",
                str(wordlist),
                "--delay",
                "0",
            ]

            with patch("sys.argv", argv), patch.object(
                controlled,
                "resolve_host",
                return_value=(["192.0.2.10"], ""),
            ), patch.object(
                controlled,
                "ct_log_names",
                return_value=([], ""),
            ):
                self.assertEqual(controlled.main(), 0)

            discovered = (out_dir / "subdomains_dedup.txt").read_text(
                encoding="utf-8"
            ).splitlines()
            merged = (out_dir / "targets_with_auto_subdomains.txt").read_text(
                encoding="utf-8"
            )
            manifest = json.loads(
                (out_dir / "subdomain_bruteforce_manifest.json").read_text(
                    encoding="utf-8"
                )
            )

            # 新版策略（20260823）：输入主机自动补充注册根域锚点，输出允许 *.根域 内子域
            self.assertEqual(
                sorted(discovered),
                sorted([
                    "admin.bgjt.bbwport.net",
                    "login.bgjt.bbwport.net",
                    "admin.bbwport.net",
                    "login.bbwport.net",
                ]),
            )
            self.assertIn("https://bgjt.bbwport.net|北港金投业务管理系统", merged)
            self.assertNotIn("evil.bbwport.net", merged)  # 范围外不出现
            self.assertEqual(
                sorted(manifest["input_scope_anchors"]),
                sorted(["bgjt.bbwport.net", "bbwport.net"]),
            )
            # 补充根域锚点后锚点数=2（bgjt.bbwport.net + bbwport.net）
            self.assertEqual(manifest["scope_anchor_count"], 2)
            self.assertEqual(manifest["out_of_scope_rejected_count"], 0)

    def test_auto_merge_preserves_original_targets_and_dedups(self):
        lines = dedup_target_lines([
            "https://www.example.com.cn|Example",
            "https://api.example.com.cn|auto_subdomain:example.com.cn",
            "https://api.example.com.cn|duplicate",
        ])
        self.assertEqual(lines, [
            "https://www.example.com.cn|Example",
            "https://api.example.com.cn|auto_subdomain:example.com.cn",
        ])

    def test_load_existing_target_lines_from_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.csv"
            path.write_text(
                "url,name,host,scheme,port,source_line\n"
                "https://www.example.com.cn,Example,www.example.com.cn,https,,1\n",
                encoding="utf-8",
            )
            self.assertEqual(load_existing_target_lines(path), ["https://www.example.com.cn|Example"])

    def test_build_queries_applies_total_budget(self):
        self.assertEqual(
            build_queries(["example.com", "example.org"], ["www", "api", "admin"], 4),
            [
                ("example.com", "www.example.com"),
                ("example.com", "api.example.com"),
                ("example.com", "admin.example.com"),
                ("example.org", "www.example.org"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
