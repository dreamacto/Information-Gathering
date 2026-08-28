from pathlib import Path
import json
from auth_preflight import build_preflight, redact_text, write_preflight


def test_preflight_matches_exact_origin_and_never_returns_other_host():
    status, auth = build_preflight([
        {"url": "https://target.test/login", "headers": {"Cookie": "sid=secret"}},
        {"url": "https://other.test/", "headers": {"Authorization": "Bearer other"}},
    ], "https://target.test/")
    assert status["status"] == "found"
    assert status["target_host"] == "target.test"
    assert auth == {"cookie": "sid=secret"}
    assert "sid=secret" not in json.dumps(status)


def test_preflight_rejects_scheme_or_port_mismatch():
    status, auth = build_preflight(
        [{"url": "http://target.test:8080/api", "headers": {"Cookie": "sid=x"}}],
        "https://target.test/api",
    )
    assert status["status"] == "not_found"
    assert auth is None


def test_preflight_write_is_metadata_only(tmp_path: Path):
    status, _ = build_preflight(
        [{"url": "https://target.test/", "headers": {"Authorization": "Bearer secret"}}],
        "https://target.test/",
    )
    status["credential_values"] = {"authorization": "Bearer secret"}
    path = tmp_path / "auth_preflight.json"
    write_preflight(path, status)
    text = path.read_text(encoding="utf-8")
    assert "Bearer secret" not in text
    assert json.loads(text)["raw_history_persisted"] is False
    assert "Bearer secret" not in redact_text("Authorization: Bearer secret")
