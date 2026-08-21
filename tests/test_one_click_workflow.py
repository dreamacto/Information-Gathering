import argparse
import unittest
from pathlib import Path

from one_click_workflow import runner_command


class OneClickWorkflowTests(unittest.TestCase):
    def test_full_mode_enables_discovery_tool_fingerprint_and_katana(self):
        args = argparse.Namespace(
            targets=Path("targets.txt"),
            mode="full",
            delay=3.0,
            limit=0,
            weak_max_targets=10,
            weak_max_pairs=5,
            sqli_limit=50,
            xss_limit=80,
            shiro_limit=30,
            second_pass_sql_limit=10,
            second_pass_xss_limit=20,
            second_pass_api_limit=20,
            header_sqli_limit=50,
            header_sqli_login_data=None,
            no_weak=False,
            no_xss=False,
            no_subdomain=False,
            no_tool_fingerprint=False,
            no_katana=False,
            no_review_intelligence=False,
            no_fingerprint_deepening=False,
            no_second_pass=False,
            miniapp_search_pack=False,
        )
        cmd = runner_command(args)
        self.assertIn("--subdomain-bruteforce", cmd)
        self.assertIn("--tool-fingerprint", cmd)
        self.assertIn("--api-use-katana", cmd)
        self.assertIn("--xss-triage", cmd)
        self.assertIn("--xss-reflect-check", cmd)

    def test_subdomain_mode_does_not_repeat_subdomain_bruteforce(self):
        args = argparse.Namespace(
            targets=Path("subdomains.txt"),
            mode="subdomains",
            delay=3.0,
            limit=0,
            weak_max_targets=10,
            weak_max_pairs=5,
            sqli_limit=50,
            xss_limit=80,
            shiro_limit=30,
            second_pass_sql_limit=10,
            second_pass_xss_limit=20,
            second_pass_api_limit=20,
            header_sqli_limit=50,
            header_sqli_login_data=None,
            no_weak=False,
            no_xss=False,
            no_subdomain=False,
            no_tool_fingerprint=False,
            no_katana=False,
            no_review_intelligence=False,
            no_fingerprint_deepening=False,
            no_second_pass=False,
            miniapp_search_pack=False,
        )
        cmd = runner_command(args)
        self.assertNotIn("--subdomain-bruteforce", cmd)
        self.assertIn("--tool-fingerprint", cmd)
        self.assertIn("--api-use-katana", cmd)
        self.assertIn("--xss-triage", cmd)


if __name__ == "__main__":
    unittest.main()
