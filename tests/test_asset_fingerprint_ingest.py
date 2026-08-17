import json
import tempfile
import unittest
from pathlib import Path

from asset_fingerprint_ingest import (
    base_path_of,
    canonical_url,
    extract_rows,
    load_library,
    main,
    merge_rows,
    now_iso,
)

LIB_PATH_ORIG = "asset_fingerprint_lib.jsonl"


class CanonicalUrlTests(unittest.TestCase):
    def test_lowercase_and_default_port(self):
        self.assertEqual(canonical_url("http://A.Gov.CN:80/x"), "http://a.gov.cn/x")

    def test_keep_non_default_port(self):
        self.assertEqual(canonical_url("http://a.gov.cn:8080/x"), "http://a.gov.cn:8080/x")

    def test_https_kept(self):
        self.assertEqual(canonical_url("https://a.gov.cn/x"), "https://a.gov.cn/x")

    def test_trailing_slash_stripped(self):
        self.assertEqual(canonical_url("https://a.gov.cn/x/"), "https://a.gov.cn/x")


class BasePathTests(unittest.TestCase):
    def test_login_file_drops_to_dir(self):
        self.assertEqual(base_path_of("https://a.gov.cn/nndwyw/login.html"), "/nndwyw/")

    def test_root(self):
        self.assertEqual(base_path_of("https://a.gov.cn"), "/")

    def test_extensionless_kept_as_dir(self):
        self.assertEqual(base_path_of("https://a.gov.cn/netface"), "/netface/")

    def test_deep_path(self):
        self.assertEqual(base_path_of("https://a.gov.cn/wx/html/ywbl/index.html"), "/wx/html/ywbl/")


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.now = now_iso()
        self.lib = {}

    def test_new_entry(self):
        merge_rows(self.lib, [{
            "url": "https://a.gov.cn/login", "host": "a.gov.cn", "product": "shiro",
            "family": "framework", "version": None, "version_source": None,
            "source": "shiro_candidates", "confidence": "high", "checked_at": self.now,
        }], self.now)
        self.assertEqual(len(self.lib), 1)
        entry = next(iter(self.lib.values()))
        self.assertEqual(entry["seen_count"], 1)
        self.assertEqual(entry["first_seen"], self.now)

    def test_rescan_updates_count_not_first_seen(self):
        later = "2026-08-16T10:00:00+08:00"
        merge_rows(self.lib, [{
            "url": "https://a.gov.cn/login", "host": "a.gov.cn", "product": "shiro",
            "version": None, "source": "shiro_candidates", "confidence": "high", "checked_at": self.now,
        }], self.now)
        merge_rows(self.lib, [{
            "url": "https://a.gov.cn/login", "host": "a.gov.cn", "product": "shiro",
            "version": "1.7.1", "version_source": "some_tool", "source": "tool_fingerprints",
            "confidence": "high", "checked_at": later,
        }], later)
        entry = next(iter(self.lib.values()))
        self.assertEqual(entry["seen_count"], 2)
        self.assertEqual(entry["first_seen"], self.now)
        self.assertEqual(entry["last_seen"], later)
        self.assertEqual(entry["version"], "1.7.1")
        self.assertEqual(sorted(entry["source"]), ["shiro_candidates", "tool_fingerprints"])

    def test_http_https_same_site_collapse(self):
        merge_rows(self.lib, [{
            "url": "http://a.gov.cn/login", "host": "a.gov.cn", "product": "shiro",
            "version": None, "source": "product_fingerprints", "confidence": "high", "checked_at": self.now,
        }], self.now)
        merge_rows(self.lib, [{
            "url": "https://a.gov.cn/login", "host": "a.gov.cn", "product": "shiro",
            "version": None, "source": "shiro_candidates", "confidence": "high", "checked_at": self.now,
        }], self.now)
        self.assertEqual(len(self.lib), 1)

    def test_same_host_different_path_stay_separate(self):
        merge_rows(self.lib, [{
            "url": "https://a.gov.cn/portal/login", "host": "a.gov.cn", "product": "shiro",
            "version": None, "source": "product_fingerprints", "confidence": "high", "checked_at": self.now,
        }], self.now)
        merge_rows(self.lib, [{
            "url": "https://a.gov.cn/admin/login", "host": "a.gov.cn", "product": "shiro",
            "version": None, "source": "product_fingerprints", "confidence": "high", "checked_at": self.now,
        }], self.now)
        self.assertEqual(len(self.lib), 2)

    def test_version_not_overwritten_by_null(self):
        merge_rows(self.lib, [{
            "url": "https://a.gov.cn/login", "host": "a.gov.cn", "product": "jQuery",
            "version": "3.3.1", "version_source": "wappalyzer", "source": "tool_fingerprints",
            "confidence": "medium", "checked_at": self.now,
        }], self.now)
        merge_rows(self.lib, [{
            "url": "https://a.gov.cn/login", "host": "a.gov.cn", "product": "jQuery",
            "version": None, "version_source": None, "source": "product_fingerprints",
            "confidence": "medium", "checked_at": self.now,
        }], self.now)
        entry = next(iter(self.lib.values()))
        self.assertEqual(entry["version"], "3.3.1")


class ExtractRowsTests(unittest.TestCase):
    def test_wappalyzer_version_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "tool_fingerprints.jsonl").write_text(json.dumps({
                "url": "https://a.gov.cn/login", "host": "a.gov.cn",
                "technologies": ["jQuery:3.3.1", "Nginx", "Java Servlet:3.0"],
                "checked_at": "2026-08-01T00:00:00+08:00",
            }) + "\n", encoding="utf-8")
            rows = extract_rows(run_dir)
            tech = {r["product"]: r for r in rows}
            self.assertEqual(tech["jQuery"]["version"], "3.3.1")
            self.assertEqual(tech["jQuery"]["version_source"], "wappalyzer")
            self.assertIsNone(tech["Nginx"]["version"])
            self.assertEqual(tech["Java Servlet"]["version"], "3.0")


class MainTests(unittest.TestCase):
    def test_idempotent_double_import(self):
        import asset_fingerprint_ingest as m
        original = m.LIB_PATH
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                run_dir = root / "run1"
                run_dir.mkdir()
                (run_dir / "product_fingerprints.jsonl").write_text(json.dumps({
                    "base_url": "https://a.gov.cn/login", "host": "a.gov.cn",
                    "product_id": "tomcat", "confidence": "high", "checked_at": "2026-08-01T00:00:00+08:00",
                }) + "\n", encoding="utf-8")
                m.LIB_PATH = root / "lib.jsonl"
                self.assertEqual(main(["--run-dir", str(run_dir)]), 0)
                self.assertEqual(main(["--run-dir", str(run_dir)]), 0)
                rows = [r for r in load_library().values() if r["product"] == "tomcat"]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["seen_count"], 2)
        finally:
            m.LIB_PATH = original


if __name__ == "__main__":
    unittest.main()
