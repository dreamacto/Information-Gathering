from authorized_assessment.orchestration.worker_output_verifier import validate_worker_outputs, verify_worker_outputs


def base(kind, rid):
    value = {"result_id": rid, "task_id": "task_demo", "worker_id": f"worker_{kind}", "worker_type": kind,
             "status": "ok", "created_at": "2026-09-01T00:00:00+00:00",
             "lineage": {"assessment_id": "asmt_demo", "correlation_id": "corr_demo", "parent_id": None},
             "gate": {"code_result_id": None, "analyst_result_id": None, "verifier_result_id": None, "dual_result_satisfied": False}}
    if kind == "analyst":
        value.update({"facts_used": [], "reasoning_summary": "summary", "alternative_explanations": [], "hypotheses": [], "unknowns": [], "coverage": {}, "not_tested": [], "next_hints": []})
    return value


def chain():
    code, analyst, verifier = base("code", "result_code"), base("analyst", "result_analyst"), base("verifier", "result_verifier")
    verifier["gate"].update({"code_result_id": "result_code", "analyst_result_id": "result_analyst", "verifier_result_id": "result_verifier", "dual_result_satisfied": True})
    verifier["disposition"] = "verified"
    return code, analyst, verifier


def test_complete_chain_passes():
    assert validate_worker_outputs(*chain()) == []
    assert verify_worker_outputs(*chain())["verified"] is True


def test_missing_analyst_field_blocks():
    code, analyst, verifier = chain()
    del analyst["hypotheses"]
    assert any("analyst_result" in error for error in validate_worker_outputs(code, analyst, verifier))


def test_reference_mismatch_blocks():
    code, analyst, verifier = chain()
    verifier["gate"]["code_result_id"] = "result_other"
    assert "verifier code reference mismatch" in validate_worker_outputs(code, analyst, verifier)


def test_non_success_or_unverified_gate_blocks():
    code, analyst, verifier = chain()
    code["status"] = "failed"
    assert "code result is not successful" in validate_worker_outputs(code, analyst, verifier)
    code["status"] = "ok"
    verifier["gate"]["dual_result_satisfied"] = False
    assert "dual result gate unsatisfied" in validate_worker_outputs(code, analyst, verifier)


def test_sensitive_output_fails_closed_without_echoing_value():
    code, analyst, verifier = chain()
    code["facts"] = ["token=do-not-echo"]
    errors = validate_worker_outputs(code, analyst, verifier)
    assert errors == ["sensitive worker output rejected"] or "sensitive worker output rejected" in errors
    assert "do-not-echo" not in " ".join(errors)


def test_code_and_analyst_only_is_valid_preverification():
    code, analyst, _ = chain()
    assert validate_worker_outputs(code, analyst) == []
