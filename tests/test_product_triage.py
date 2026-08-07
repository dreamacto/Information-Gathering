import csv
import json
import tempfile
import unittest
from pathlib import Path

from gov_exercise_runner import detect_categories
from product_triage import build_findings, build_vuln_candidates, template_risk, write_outputs


class ProductTriageTests(unittest.TestCase):
    def test_detect_categories_recognizes_chinese_oa_product(self):
        row = {
            "url": "https://oa.example.test",
            "title": "泛微 E-Cology 协同办公平台",
            "server": "Apache",
        }
        self.assertIn("oa", detect_categories(row))

    def test_build_findings_routes_seeyon_to_specialized_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "fingerprints.jsonl").write_text(
                json.dumps({
                    "url": "https://oa.example.test/seeyon/",
                    "title": "致远 A8 协同管理软件",
                    "categories": ["oa", "java"],
                }, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            findings = build_findings(run_dir)
            seeyon = next(item for item in findings if item["product_id"] == "seeyon")
            self.assertEqual(seeyon["branch"], "oa_seeyon")
            self.assertEqual(seeyon["default_action"], "queue_only")
            self.assertIn("afrog", seeyon["primary_tools"])
            self.assertIn("nuclei", seeyon["primary_tools"])
            self.assertIn("OA-EXPTOOL legacy templates", seeyon["backup_tools"])

    def test_template_risk_gates_active_oa_payloads(self):
        self.assertEqual(template_risk(Path("tongda-report-sqli.yaml")), "approval_required")
        self.assertEqual(template_risk(Path("ecology-arbitrary-file-upload.yaml")), "approval_required")
        self.assertEqual(template_risk(Path("seeyon-config-exposure.yaml")), "review_readonly")

    def test_write_outputs_creates_operator_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            finding = {
                "checked_at": "2026-07-12T00:00:00+08:00",
                "base_url": "https://oa.example.test",
                "host": "oa.example.test",
                "product_id": "tongda",
                "product": "Tongda OA",
                "family": "oa",
                "branch": "oa_tongda",
                "score": 50,
                "confidence": "medium",
                "primary_tools": ["OA-EXPTOOL", "dddd/nuclei"],
                "backup_tools": ["afrog"],
                "default_action": "queue_only",
                "notes": "test",
                "evidence": [],
                "template_matches": {
                    "review_readonly": [],
                    "approval_required": [{
                        "tool": "dddd",
                        "name": "tongda-auth-bypass.yaml",
                        "path": "templates/tongda-auth-bypass.yaml",
                        "risk": "approval_required",
                    }],
                    "review_unknown": [],
                },
            }
            summary = write_outputs(run_dir, [finding])
            self.assertEqual(summary["finding_count"], 1)
            with (run_dir / "product_triage_queue.csv").open(encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["default_action"], "queue_only")
            self.assertIn("tongda-auth-bypass.yaml", row["approval_templates"])

    def test_vuln_candidates_include_java_teacher_focus_queue(self):
        finding = {
            "checked_at": "2026-07-12T00:00:00+08:00",
            "base_url": "https://api.example.test",
            "host": "api.example.test",
            "product_id": "struts2",
            "product": "Apache Struts",
            "family": "framework",
            "branch": "java_struts",
            "score": 80,
            "confidence": "high",
            "primary_tools": ["nuclei"],
            "backup_tools": ["manual browser"],
            "default_action": "queue_only",
            "notes": "test",
            "evidence": [],
            "template_matches": {},
        }
        candidates = build_vuln_candidates([finding])
        candidate_types = {item["candidate_type"] for item in candidates}
        self.assertIn("struts2_ognl_rce", candidate_types)
        self.assertIn("log4j_log4shell", candidate_types)
        self.assertTrue(all(item["default_action"] == "queue_only" for item in candidates))
        struts_candidate = next(item for item in candidates if item["candidate_type"] == "struts2_ognl_rce")
        self.assertIn(".action", struts_candidate["evidence_to_collect"])
        self.assertIn("Do not", struts_candidate["do_not_do"])


if __name__ == "__main__":
    unittest.main()
