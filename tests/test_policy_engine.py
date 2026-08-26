import json
from pathlib import Path

from policy_engine import PolicyEngine
from exercise_runtime import Target


def test_policy_requires_context_for_tools():
    import toolkit_integration as toolkit
    ok, message = toolkit.run_tool("rscan", url="https://example.test")
    assert not ok
    assert "PolicyEngine" in message


def test_policy_default_denies_unknown_and_blocked(tmp_path: Path):
    engine = PolicyEngine(
        {"blocked_actions": ["password_spray"]},
        targets=[Target(url="https://example.test", host="example.test", scheme="https", port=None)],
        run_dir=tmp_path,
        entrypoint="test",
    )
    assert not engine.authorize_action("password_spray").allowed
    assert not engine.authorize_target("https://other.test").allowed
    assert engine.authorize_action("probe", "https://example.test").allowed
    assert (tmp_path / "policy_decisions.jsonl").is_file()


def test_policy_invalid_config_fails_closed():
    engine = PolicyEngine({"blocked_actions": "not-a-list"})
    assert not engine.valid
    assert not engine.authorize_action("probe").allowed
