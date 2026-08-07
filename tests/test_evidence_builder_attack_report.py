import json
import tempfile
import unittest
from pathlib import Path

from docx import Document

from evidence_builder import make_attack_result_docx


class AttackResultDocxTests(unittest.TestCase):
    def test_generates_docx_with_team_name_and_screenshot_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run"
            run_dir.mkdir()
            template = root / "template.docx"
            config = root / "config.json"

            doc = Document()
            doc.add_paragraph("template placeholder")
            doc.save(template)

            (run_dir / "confirmed_findings.json").write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "system": "测试系统",
                                "target_url": "https://example.test/api/user",
                                "vuln_type": "未授权访问",
                                "description": "接口可读取敏感字段",
                                "exploitability": "登录后可稳定访问敏感字段。",
                                "limitations": "需要授权账号 Cookie。",
                                "remediation": "补充接口鉴权和字段级授权。",
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            config.write_text(
                json.dumps(
                    {
                        "reporting": {
                            "team_name": "观叶识微",
                            "attack_result_template": str(template),
                            "auto_generate_attack_report": True,
                        }
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            out = make_attack_result_docx(run_dir, config)

            self.assertIsNotNone(out)
            generated = Document(out)
            text = "\n".join(p.text for p in generated.paragraphs)
            self.assertIn("观叶识微", text)
            self.assertIn("【需截图】", text)
            self.assertIn("未授权访问", text)


if __name__ == "__main__":
    unittest.main()
