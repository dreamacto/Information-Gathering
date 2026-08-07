from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from wechat_miniapp_discovery import Seed, extract_clues, write_auth_handoff


class WeChatAuthHandoffTests(unittest.TestCase):
    def test_extracts_auth_and_backend_urls_without_values(self) -> None:
        text = r'''
        const login = "https:\/\/api.hospital.test\/api\/user\/login?code=SECRET";
        const backend = "https://api.hospital.test/patient/report/list?page=1";
        const script = "https://api.hospital.test/static/app.js";
        '''
        clues = extract_clues("https://hospital.test", text)
        auth = [row for row in clues if row["kind"] == "auth_endpoint_candidate"]
        backend = [row for row in clues if row["kind"] == "candidate_backend_url"]
        self.assertEqual(len(auth), 1)
        self.assertIn("code=<redacted>", auth[0]["value"])
        self.assertNotIn("SECRET", json.dumps(clues))
        self.assertEqual(len(backend), 1)
        self.assertNotIn("app.js", json.dumps(clues))

    def test_writes_in_scope_and_ownership_review_queues(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            rows = [
                {
                    "domain": "hospital.test",
                    "kind": "auth_endpoint_candidate",
                    "value": "https://hospital.test/api/login",
                    "registration_candidate": False,
                },
                {
                    "domain": "hospital.test",
                    "kind": "auth_endpoint_candidate",
                    "value": "https://vendor.example/api/register",
                    "registration_candidate": True,
                },
            ]
            (out / "wechat_miniapp_candidates.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            result = write_auth_handoff(
                [Seed(url="https://hospital.test", host="hospital.test")], out
            )
            self.assertEqual(result["count"], 2)
            self.assertEqual(result["in_scope_count"], 1)
            self.assertEqual(result["ownership_review_count"], 1)
            queue = json.loads((out / "wechat_auth_domains.json").read_text(encoding="utf-8"))
            states = {item["host"]: item["scope_state"] for item in queue["items"]}
            self.assertEqual(states["hospital.test"], "in_current_scope")
            self.assertEqual(states["vendor.example"], "ownership_confirmation_required")
            template = json.loads((out / "wechat_auth_sessions.template.json").read_text(encoding="utf-8"))
            self.assertEqual([row["base_url"] for row in template["sessions"]], ["https://hospital.test"])


if __name__ == "__main__":
    unittest.main()
