from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from healthcare_privacy_triage import _safe_url, build_triage, write_outputs
from health_scope_import import _category, _is_private_host, _normalize_url


class HealthcareScopeTests(unittest.TestCase):
    def test_url_and_network_classification(self) -> None:
        self.assertEqual(_normalize_url("HTTPS://Example.COM/a?x=1"), "https://example.com/a?x=1")
        self.assertTrue(_is_private_host("10.0.0.8"))
        self.assertFalse(_is_private_host("8.8.8.8"))

    def test_health_categories(self) -> None:
        self.assertIn("pacs_imaging", _category("医院 PACS 云胶片系统"))
        self.assertIn("lis_lab", _category("LIS 检验平台"))


class HealthcarePrivacyTests(unittest.TestCase):
    def test_url_values_and_credentials_are_redacted(self) -> None:
        sanitized = _safe_url("https://alice:secret@example.com/api/patient?idCard=123456&name=Li")
        self.assertEqual(sanitized, "https://example.com/api/patient?idCard=<redacted>&name=<redacted>")
        self.assertNotIn("secret", sanitized)
        self.assertNotIn("123456", sanitized)

    def test_outputs_contain_schema_not_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            record = {
                "url": "https://hospital.example/api/patient?idCard=SECRET-ID",
                "response": {"patient": {"name": "SECRET-NAME", "diagnosis": "SECRET-DIAGNOSIS"}},
            }
            (run_dir / "api_interesting.jsonl").write_text(json.dumps(record, ensure_ascii=False) + "\n", encoding="utf-8")
            findings = build_triage(run_dir)
            self.assertEqual(len(findings), 1)
            write_outputs(run_dir, findings)
            combined = "\n".join(
                path.read_text(encoding="utf-8-sig")
                for path in (run_dir / "healthcare_privacy").iterdir()
                if path.is_file()
            )
            self.assertNotIn("SECRET-ID", combined)
            self.assertNotIn("SECRET-NAME", combined)
            self.assertNotIn("SECRET-DIAGNOSIS", combined)
            self.assertIn("response.patient.name", combined)


if __name__ == "__main__":
    unittest.main()
