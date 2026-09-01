from authorized_assessment.orchestration.verifier import aggregate_verification, validate_verification_input


def passing():
    return {
        "phase": True, "context": {"valid": True}, "worker": {"status": "ok"},
        "evidence": {"gate_status": "PASS"}, "approval": {"passed": True},
        "quality": {"quality_status": "VALID"}, "dual_result": True,
        "code_result_id": "result_code", "analyst_result_id": "result_analyst",
    }


def test_all_gates_and_dual_result_are_required_for_verified():
    result = aggregate_verification(passing())
    assert result["verified"] is True
    assert result["disposition"] == "verified"
    assert result["violations"] == []


def test_missing_gate_fails_closed():
    value = passing()
    del value["quality"]
    result = aggregate_verification(value)
    assert result["verified"] is False
    assert any(v["path"] == "quality" for v in result["violations"])


def test_conflicts_preserve_nested_paths():
    value = passing()
    value["violations"] = [{"path": "quality.gate_results.evidence", "code": "conflict", "detail": "mismatch"}]
    result = aggregate_verification(value)
    assert result["verified"] is False
    assert any(v["path"] == "quality.gate_results.evidence" for v in result["violations"])


def test_dual_result_and_sensitive_fields_are_rejected():
    value = passing()
    value["dual_result"] = False
    value["credential_hint"] = "redacted"
    errors = validate_verification_input(value)
    assert any(v["code"] == "dual_result_unsatisfied" for v in errors)
    assert any(v["path"] == "credential_hint" for v in errors)
