import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shiro_bypass_review import (
    BYPASS_VARIANTS,
    FetchResult,
    analyze_baseline_variant,
    build_probe_plan,
    queued_candidates,
    load_approved_rows,
    rememberme_key_probe,
    run_plan,
)


def sample(url, status=200, text="login page"):
    return FetchResult(
        url=url,
        status=status,
        final_url=url,
        content_type="text/html",
        content_length=str(len(text)),
        text=text,
        sample_sha256=str(abs(hash(text))),
        title="login",
    )


def write_candidates(run_dir: Path, rows: list[dict]) -> None:
    (run_dir / "shiro_candidates.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


class ShiroBypassPlanTests(unittest.TestCase):
    def test_medium_and_high_candidates_enter_queue_low_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            write_candidates(run_dir, [
                {"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["invalid_rememberme_deleted"]},
                {"url": "https://b.test/login", "host": "b.test", "confidence": "medium", "signals": ["shiro_keyword"]},
                {"url": "https://c.test/login", "host": "c.test", "confidence": "low", "signals": []},
            ])
            manifest = run_plan(run_dir)
            self.assertEqual(manifest["queued_candidates"], 2)
            self.assertEqual(manifest["queued_items"], 2)
            rows = [json.loads(line) for line in (run_dir / "shiro_bypass_approval_queue.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(rows), 2)
            by_url = {row["url"]: row for row in rows}
            self.assertEqual(by_url["https://a.test/login"]["confidence"], "high")
            self.assertEqual(by_url["https://b.test/login"]["confidence"], "medium")
            self.assertEqual(by_url["https://b.test/login"]["rememberme_repro"], "no")
            self.assertTrue(all(row["approved"] == "no" for row in rows))

    def test_plan_is_offline_and_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            write_candidates(run_dir, [
                {"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": []},
            ])
            with patch("shiro_bypass_review.fetch_once") as mock_fetch:
                run_plan(run_dir)
                mock_fetch.assert_not_called()

    def test_build_probe_plan_has_bounded_variants(self):
        plan = build_probe_plan({"url": "https://a.test/nndwyw/login.html", "host": "a.test", "confidence": "high", "signals": []})
        self.assertEqual(plan["base_path"], "/nndwyw/")
        self.assertEqual(len(plan["variants"]), len(BYPASS_VARIANTS))
        self.assertEqual(plan["request_budget"], 1 + len(BYPASS_VARIANTS))
        self.assertIn("disabled_actions", plan)

    def test_build_probe_plan_rememberme_adds_liveness_budget(self):
        plan = build_probe_plan({"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["invalid_rememberme_deleted"]})
        self.assertTrue(plan["rememberme"]["detected"])
        self.assertIn("liveness_probe", plan["rememberme"])
        self.assertEqual(plan["request_budget"], 1 + len(BYPASS_VARIANTS) + 1)
        self.assertEqual(plan["rememberme"]["key_probe"]["authorization"], "rememberme_repro_col")

    def test_base_path_of_login_root(self):
        plan = build_probe_plan({"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": []})
        self.assertEqual(plan["base_path"], "/")

    def test_same_url_merged_into_one_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            write_candidates(run_dir, [
                {"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["invalid_rememberme_deleted"]},
                {"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["shiro_keyword", "another_signal"]},
            ])
            candidates = queued_candidates(run_dir)
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["signals"], ["another_signal", "invalid_rememberme_deleted", "shiro_keyword"])

    def test_plan_carries_rememberme_cross_reference(self):
        plan = build_probe_plan({"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["invalid_rememberme_deleted", "shiro_keyword"]})
        self.assertTrue(plan["rememberme"]["detected"])
        self.assertEqual(plan["rememberme"]["signals"], ["invalid_rememberme_deleted"])
        self.assertEqual(plan["rememberme"]["verification"], "manual_shiroattack2_single_target_only")
        self.assertEqual(plan["rememberme"]["auto_action"], "none")

    def test_plan_rememberme_false_when_no_rememberme_signal(self):
        plan = build_probe_plan({"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["shiro_keyword"]})
        self.assertFalse(plan["rememberme"]["detected"])
        self.assertEqual(plan["rememberme"]["signals"], [])

    def test_plan_outputs_one_row_per_url_with_rememberme_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            write_candidates(run_dir, [
                {"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["invalid_rememberme_deleted"]},
                {"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["shiro_keyword"]},
            ])
            run_plan(run_dir)
            rows = [json.loads(line) for line in (run_dir / "shiro_bypass_approval_queue.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["rememberme"]["detected"])

    def test_plan_id_is_stable_across_runs(self):
        from shiro_bypass_review import plan_id_of

        self.assertEqual(plan_id_of("https://a.test/login"), plan_id_of("https://a.test/login"))

    def test_legacy_numeric_duplicates_are_collapsed_keeping_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            write_candidates(run_dir, [
                {"url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["invalid_rememberme_deleted"]},
            ])
            legacy = [
                {"plan_id": "111", "url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["invalid_rememberme_deleted"], "approved": "no"},
                {"plan_id": "222", "url": "https://a.test/login", "host": "a.test", "confidence": "high", "signals": ["invalid_rememberme_deleted"], "approved": "yes"},
            ]
            (run_dir / "shiro_bypass_approval_queue.jsonl").write_text(
                "".join(json.dumps(r) + "\n" for r in legacy), encoding="utf-8"
            )
            run_plan(run_dir)
            rows = [json.loads(line) for line in (run_dir / "shiro_bypass_approval_queue.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["approved"], "yes")


class ShiroBypassReviewTests(unittest.TestCase):
    def test_approved_rows_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "shiro_bypass_approval_queue.jsonl").write_text(
                json.dumps({"plan_id": "1", "approved": "yes", "url": "https://a.test/login"}) + "\n"
                + json.dumps({"plan_id": "2", "approved": "no", "url": "https://b.test/login"}) + "\n",
                encoding="utf-8",
            )
            rows = load_approved_rows(run_dir)
            self.assertEqual([row["plan_id"] for row in rows], ["1"])

    def test_deny_to_open_is_bypass_likely(self):
        analysis = analyze_baseline_variant(sample("https://a.test/login", status=302, text="redirect"), sample("https://a.test/x/..;/", status=200, text="admin dashboard"))
        self.assertEqual(analysis["outcome"], "bypass_likely")
        self.assertIn("deny_to_open_status", analysis["signals"])

    def test_same_status_same_body_is_no_signal(self):
        analysis = analyze_baseline_variant(sample("https://a.test/login", status=200, text="same body"), sample("https://a.test/login/", status=200, text="same body"))
        self.assertEqual(analysis["outcome"], "no_signal")

    def test_run_review_runs_key_probe_when_rememberme_repro_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "shiro_bypass_approval_queue.jsonl").write_text(
                json.dumps({
                    "plan_id": "1", "approved": "yes", "rememberme_repro": "yes",
                    "url": "https://a.test/login",
                    "host": "a.test", "base_path": "/", "confidence": "high",
                    "rememberme": {"detected": True, "signals": ["invalid_rememberme_deleted"]},
                    "variants": [],
                }) + "\n",
                encoding="utf-8",
            )
            from shiro_bypass_review import rememberme_key_probe
            with patch("shiro_bypass_review.rememberme_key_probe", return_value={
                    "url": "https://a.test/login", "matched": True, "key": "kPH+bIxk5D2deZiIxcaaaA==",
                    "mode": "cbc", "keys_tried": 1, "keys_total": 1209,
            }), patch("shiro_bypass_review.rememberme_liveness", return_value={
                    "url": "https://a.test/login", "alive": True, "signal": "delete_me_response",
                    "status": 200, "set_cookies": ["rememberMe=deleteMe; Path=/; Max-Age=0"],
            }), patch("shiro_bypass_review.fetch_once", side_effect=[
                    sample("https://a.test/login", status=200, text="login page"),
            ]), patch("shiro_bypass_review.time.sleep", return_value=None):
                from shiro_bypass_review import run_review
                manifest = run_review(run_dir, delay=0, timeout=10)
            self.assertEqual(manifest["rememberme_liveness_confirmed"], 1)
            self.assertEqual(manifest["rememberme_key_hits"], 1)
            hits = (run_dir / "shiro_rememberme_key_hits.md").read_text(encoding="utf-8")
            self.assertIn("kPH+bIxk5D2deZiIxcaaaA==", hits)
            self.assertIn("cbc", hits)

    def test_run_review_no_key_probe_without_repro_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "shiro_bypass_approval_queue.jsonl").write_text(
                json.dumps({
                    "plan_id": "1", "approved": "yes", "rememberme_repro": "no",
                    "url": "https://a.test/login",
                    "host": "a.test", "base_path": "/", "confidence": "high",
                    "rememberme": {"detected": True, "signals": ["invalid_rememberme_deleted"]},
                    "variants": [],
                }) + "\n",
                encoding="utf-8",
            )
            with patch("shiro_bypass_review.rememberme_liveness", return_value={
                    "url": "https://a.test/login", "alive": True, "signal": "delete_me_response",
                    "status": 200, "set_cookies": ["rememberMe=deleteMe; Path=/; Max-Age=0"],
            }), patch("shiro_bypass_review.rememberme_key_probe") as mock_probe, \
                    patch("shiro_bypass_review.fetch_once", side_effect=[
                        sample("https://a.test/login", status=200, text="login page"),
                    ]), patch("shiro_bypass_review.time.sleep", return_value=None):
                from shiro_bypass_review import run_review
                manifest = run_review(run_dir, delay=0, timeout=10)
            self.assertEqual(manifest["rememberme_liveness_confirmed"], 1)
            self.assertEqual(manifest["rememberme_key_hits"], 0)
            mock_probe.assert_not_called()
            self.assertFalse((run_dir / "shiro_rememberme_key_hits.md").exists())


    def test_rememberme_key_probe_stops_at_first_confirmed_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            import shiro_bypass_review as mod
            probe_target = Path(tmp) / "keys.txt"
            probe_target.write_text(
                "2AvVhdsgUs0FSA3SDFAdag==\nkPH+bIxk5D2deZiIxcaaaA==\n", encoding="utf-8"
            )
            original = list(mod.SHIRO_KEYS_CANDIDATE_FILES)
            mod.SHIRO_KEYS_CANDIDATE_FILES = [probe_target]
            try:
                calls = {"n": 0}

                def fake_fetch(url, run_dir, timeout, follow=False, cookie="", capture_headers=False):
                    calls["n"] += 1
                    # call 1 = cbc k1(wrong), call 2 = gcm k1(wrong): both deleteMe
                    # call 3 = cbc k2(right) no deleteMe, call 4 = confirmation no deleteMe
                    # call 5 = baseline contrast random wrong key -> clean miss (deleteMe)
                    if 3 <= calls["n"] <= 4:
                        return FetchResult(
                            url=url, status=200, final_url=url, text="login",
                            set_cookies=["JSESSIONID=abc; Path=/"],
                        )
                    return FetchResult(
                        url=url, status=200, final_url=url, text="login",
                        set_cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"],
                    )

                with patch.object(mod, "fetch_once", side_effect=fake_fetch), patch("shiro_bypass_review.time.sleep", return_value=None):
                    result = rememberme_key_probe(run_dir, timeout=10, delay=0, url="https://a.test/login", key_cap=2)
            finally:
                mod.SHIRO_KEYS_CANDIDATE_FILES = original
            self.assertTrue(result["matched"])
            self.assertEqual(result["key"], "kPH+bIxk5D2deZiIxcaaaA==")
            self.assertEqual(result["mode"], "cbc")

    def test_rememberme_key_probe_confirms_when_response_has_no_delete_me(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            import shiro_bypass_review as mod
            probe_target = Path(tmp) / "keys.txt"
            probe_target.write_text("kPH+bIxk5D2deZiIxcaaaA==\n", encoding="utf-8")
            original = list(mod.SHIRO_KEYS_CANDIDATE_FILES)
            mod.SHIRO_KEYS_CANDIDATE_FILES = [probe_target]
            try:
                from shiro_bypass_review import fetch_once as real_fetch
                # first attempt cbc no deleteMe, second confirmation cbc no deleteMe,
                # then baseline contrast random wrong key -> clean miss (deleteMe)
                calls = {"n": 0}

                def fake_fetch(url, run_dir, timeout, follow=False, cookie="", capture_headers=False):
                    calls["n"] += 1
                    if calls["n"] <= 3:
                        return FetchResult(
                            url=url, status=200, final_url=url, text="login",
                            set_cookies=["JSESSIONID=abc; Path=/"],
                        )
                    return FetchResult(
                        url=url, status=200, final_url=url, text="login",
                        set_cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"],
                    )
                with patch.object(mod, "fetch_once", side_effect=fake_fetch), patch("shiro_bypass_review.time.sleep", return_value=None):
                    result = rememberme_key_probe(run_dir, timeout=10, delay=0, url="https://a.test/login", key_cap=1)
            finally:
                mod.SHIRO_KEYS_CANDIDATE_FILES = original
            self.assertTrue(result["matched"])
            self.assertEqual(result["confidence"], "confirmed")
            self.assertEqual(result["mode"], "cbc")
            self.assertEqual(result["key"], "kPH+bIxk5D2deZiIxcaaaA==")

    def test_rememberme_suspect_hit_needs_baseline_contrast(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            import shiro_bypass_review as mod
            probe_target = Path(tmp) / "keys.txt"
            probe_target.write_text("kPH+bIxk5D2deZiIxcaaaA==\n", encoding="utf-8")
            original = list(mod.SHIRO_KEYS_CANDIDATE_FILES)
            mod.SHIRO_KEYS_CANDIDATE_FILES = [probe_target]
            calls = {"n": 0}

            def fake_fetch(url, run_dir, timeout, follow=False, cookie="", capture_headers=False):
                calls["n"] += 1
                # 1: default key cbc -> suspect (empty reply, status 0, error)
                # 2: default key confirm -> suspect
                # 3,4: baseline contrast with random wrong key -> miss (200 + deleteMe)
                if calls["n"] <= 2:
                    return FetchResult(url=url, status=0, final_url=url, text="", error="curl: (52) Empty reply from server")
                return FetchResult(
                    url=url, status=200, final_url=url, text="login",
                    set_cookies=["rememberMe=deleteMe; Path=/; Max-Age=0"],
                )
            try:
                with patch.object(mod, "fetch_once", side_effect=fake_fetch), patch("shiro_bypass_review.time.sleep", return_value=None):
                    result = rememberme_key_probe(run_dir, timeout=10, delay=0, url="https://a.test/login", key_cap=1)
            finally:
                mod.SHIRO_KEYS_CANDIDATE_FILES = original
            self.assertTrue(result["matched"])
            self.assertEqual(result["confidence"], "suspect_confirmed")
            self.assertEqual(result["keys_tried"], 3)

    def test_rememberme_error_without_baseline_contrast_not_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            import shiro_bypass_review as mod
            probe_target = Path(tmp) / "keys.txt"
            probe_target.write_text("kPH+bIxk5D2deZiIxcaaaA==\n", encoding="utf-8")
            original = list(mod.SHIRO_KEYS_CANDIDATE_FILES)
            mod.SHIRO_KEYS_CANDIDATE_FILES = [probe_target]
            calls = {"n": 0}

            def fake_fetch(url, run_dir, timeout, follow=False, cookie="", capture_headers=False):
                calls["n"] += 1
                # every probe -> error without deleteMe; baseline contrast also errors
                return FetchResult(url=url, status=0, final_url=url, text="", error="curl: (28) timeout")
            try:
                with patch.object(mod, "fetch_once", side_effect=fake_fetch), patch("shiro_bypass_review.time.sleep", return_value=None):
                    result = rememberme_key_probe(run_dir, timeout=10, delay=0, url="https://a.test/login", key_cap=1)
            finally:
                mod.SHIRO_KEYS_CANDIDATE_FILES = original
            self.assertFalse(result["matched"])


if __name__ == "__main__":
    unittest.main()
