"""Tests for evidence_gate (spec 4.4 lines 1169-1186; 13.2 negatives)."""
from __future__ import annotations

import pytest

from authorized_assessment.quality.finding_quality_gate import FINDING_STATUS_STATES
from authorized_assessment.reporting.evidence_gate import (
    GATE_STATUS_STATES,
    VIOLATION_CODES,
    evaluate_evidence_gate,
    load_evidence_schema,
    validate_evidence_gate_report,
)


@pytest.fixture()
def evidence_root(tmp_path):
    root = tmp_path / "run20260829_120000"
    ev = root / "evidence"
    ev.mkdir(parents=True)
    (ev / "F-0001.html").write_text("<html>proof one</html>", encoding="utf-8")
    (ev / "F-0002.html").write_text("<html>proof two</html>", encoding="utf-8")
    (ev / "F-0003").mkdir()
    (ev / "F-0003" / "diff.txt").write_text("baseline vs anomalous", encoding="utf-8")
    return root


def confirmed_row(**overrides):
    row = {
        "finding_id": "F-0001",
        "finding_status": "confirmed",
        "evidence_ref": "evidence/F-0001.html",
        "validation_result": "verified",
        "reviewer": "operator-a",
        "reviewed_at": "2026-08-29T12:00:00+08:00",
    }
    row.update(overrides)
    return row


def candidate_row(**overrides):
    row = {
        "finding_id": "F-0002",
        "finding_status": "candidate",
        "evidence_ref": "evidence/F-0002.html",
        "validation_result": "inconclusive",
    }
    row.update(overrides)
    return row


def codes(report):
    return [v["code"] for v in report["violations"]]


def test_clean_report_passes(evidence_root):
    report = evaluate_evidence_gate(
        [confirmed_row(), candidate_row()], evidence_root
    )
    assert report["gate_status"] == "PASS"
    assert report["rows_checked"] == 2
    assert report["violations"] == []
    assert validate_evidence_gate_report(report) == []


def test_evidence_ref_as_directory_is_accepted(evidence_root):
    report = evaluate_evidence_gate(
        [confirmed_row(finding_id="F-0003", evidence_ref="evidence/F-0003")],
        evidence_root,
    )
    assert report["gate_status"] == "PASS"


def test_missing_finding_id_rejected(evidence_root):
    report = evaluate_evidence_gate([confirmed_row(finding_id="")], evidence_root)
    assert "missing_finding_id" in codes(report)
    assert report["gate_status"] == "REJECTED"


def test_evidence_ref_missing_rejected(evidence_root):
    for row in (
        confirmed_row(evidence_ref=""),
        confirmed_row(**{"evidence_ref": None}),
        {k: v for k, v in confirmed_row().items() if k != "evidence_ref"},
    ):
        report = evaluate_evidence_gate([row], evidence_root)
        assert "evidence_ref_missing" in codes(report), row


def test_evidence_path_not_found_rejected(evidence_root):
    report = evaluate_evidence_gate(
        [confirmed_row(evidence_ref="evidence/does_not_exist.html")], evidence_root
    )
    assert "evidence_path_not_found" in codes(report)
    report = evaluate_evidence_gate(
        [
            confirmed_row(
                evidence_ref=["evidence/F-0001.html", "evidence/missing.html"]
            )
        ],
        evidence_root,
    )
    assert codes(report).count("evidence_path_not_found") == 1


def test_validation_result_missing_rejected(evidence_root):
    row = {k: v for k, v in confirmed_row().items() if k != "validation_result"}
    report = evaluate_evidence_gate([row], evidence_root)
    assert "validation_result_missing" in codes(report)


def test_confirmed_requires_verified_validation_result(evidence_root):
    report = evaluate_evidence_gate(
        [confirmed_row(validation_result="inconclusive")], evidence_root
    )
    assert "validation_result_unverified_for_confirmed" in codes(report)


def test_confirmed_requires_reviewer_and_reviewed_at(evidence_root):
    report = evaluate_evidence_gate(
        [confirmed_row(reviewer="")], evidence_root
    )
    assert "reviewer_missing_for_confirmed" in codes(report)
    report = evaluate_evidence_gate(
        [confirmed_row(reviewed_at="")], evidence_root
    )
    assert "reviewed_at_missing_for_confirmed" in codes(report)
    report = evaluate_evidence_gate([candidate_row(reviewer="")], evidence_root)
    assert "reviewer_missing_for_confirmed" not in codes(report)


def test_accepted_risk_disposition_requires_reviewer(evidence_root):
    row = {
        "finding_id": "F-0009",
        "finding_status": "candidate",
        "evidence_ref": "evidence/F-0002.html",
        "validation_result": "verified",
        "disposition": "accepted_risk",
    }
    report = evaluate_evidence_gate([row], evidence_root)
    assert "reviewer_missing_for_confirmed" in codes(report)
    assert "reviewed_at_missing_for_confirmed" in codes(report)


def test_candidate_presented_as_confirmed_rejected(evidence_root):
    """13.2 负例：报告把 candidate 当 confirmed。"""
    report = evaluate_evidence_gate(
        [candidate_row(presented_as="confirmed")], evidence_root
    )
    assert "candidate_presented_as_confirmed" in codes(report)
    report = evaluate_evidence_gate(
        [candidate_row(**{"finding_status": "", "presented_as": "confirmed"})],
        evidence_root,
    )
    assert "finding_status_missing" in codes(report)
    assert "candidate_presented_as_confirmed" in codes(report)


def test_garbage_finding_status_rejected(evidence_root):
    report = evaluate_evidence_gate(
        [confirmed_row(finding_status="banana")], evidence_root
    )
    assert "finding_status_missing" in codes(report)


def test_signal_row_presented_as_signal_passes(evidence_root):
    row = {
        "finding_id": "F-0004",
        "finding_status": "signal",
        "evidence_ref": "evidence/F-0002.html",
        "validation_result": "inconclusive",
        "presented_as": "signal",
    }
    report = evaluate_evidence_gate([row], evidence_root)
    assert report["gate_status"] == "PASS"


def test_credential_key_in_row_rejected_and_value_withheld(evidence_root):
    """13.2 负例：报告含凭证（键）。违例明细不得回显凭证值。"""
    fake_value = "SESSION-PLACEHOLDER-VALUE"
    report = evaluate_evidence_gate(
        [confirmed_row(**{"session_key": fake_value})], evidence_root
    )
    assert "credential_key_detected" in codes(report)
    assert all(fake_value not in v["detail"] for v in report["violations"])


def test_credential_content_in_row_rejected_and_value_withheld(evidence_root):
    """13.2 负例：报告含凭证原文（值内容赋值模式）。"""
    fake_header = "Authorization: Bearer eyJFAKE.JWTSIGNATURE.VALUE"
    report = evaluate_evidence_gate(
        [confirmed_row(minimal_reproduction=f"step1 {fake_header} then 200")],
        evidence_root,
    )
    assert "credential_content_detected" in codes(report)
    assert all("eyJFAKE" not in v["detail"] for v in report["violations"])


def test_credential_assignment_patterns_detected(evidence_root):
    for text in (
        "Cookie: SESSIONID=placeholder",
        "token=abcdef",
        "AppSecret: 0123abcdef",
        "password: hunter2placeholder",
        "session_key: AbCdEf123456",
    ):
        report = evaluate_evidence_gate(
            [confirmed_row(impact_statement=text)], evidence_root
        )
        assert "credential_content_detected" in codes(report), text


def test_empty_source_ledger_rejected(evidence_root, tmp_path):
    """13.2 负例：空 ledger。"""
    missing = tmp_path / "no_such_ledger.csv"
    empty = tmp_path / "review_ledger.csv"
    empty.write_text("", encoding="utf-8")
    populated = tmp_path / "review_ledger_full.csv"
    populated.write_text("source_file,verdict\nx,confirmed\n", encoding="utf-8")

    report = evaluate_evidence_gate([confirmed_row()], evidence_root, source_ledger=missing)
    assert "empty_source_ledger" in codes(report)
    report = evaluate_evidence_gate([confirmed_row()], evidence_root, source_ledger=empty)
    assert "empty_source_ledger" in codes(report)
    report = evaluate_evidence_gate([confirmed_row()], evidence_root, source_ledger=populated)
    assert "empty_source_ledger" not in codes(report)
    assert report["gate_status"] == "PASS"


def test_gate_report_validator_negative_cases(evidence_root):
    report = evaluate_evidence_gate([confirmed_row()], evidence_root)

    tampered = dict(report, gate_status="PASS", violations=[{"code": "missing_finding_id", "detail": "x"}])
    errors = validate_evidence_gate_report(tampered)
    assert any("PASS gate report must not carry violations" in e for e in errors)

    tampered = dict(report, gate_status="REJECTED", violations=[])
    errors = validate_evidence_gate_report(tampered)
    assert any("REJECTED gate report must carry" in e for e in errors)

    tampered = dict(report, violations=[{"code": "made_up_code", "detail": "x"}])
    errors = validate_evidence_gate_report(tampered)
    assert any("not in schema enum" in e for e in errors)

    tampered = dict(report, violations=[{"code": "missing_finding_id"}])
    errors = validate_evidence_gate_report(tampered)
    assert any("detail must be a non-empty string" in e for e in errors)

    tampered = dict(report, session_key="placeholder")
    errors = validate_evidence_gate_report(tampered)
    assert any("credential-like key" in e for e in errors)

    tampered = dict(
        report,
        gate_status="REJECTED",
        violations=[{"code": "credential_content_detected", "detail": "leak: token=abc123"}],
    )
    errors = validate_evidence_gate_report(tampered)
    assert any(
        "credential-like assignment text is forbidden in evidence gate report" in e
        for e in errors
    )

    tampered = dict(report, rows_checked=-1)
    errors = validate_evidence_gate_report(tampered)
    assert any("rows_checked" in e for e in errors)

    tampered = {k: v for k, v in report.items() if k != "gate_status"}
    errors = validate_evidence_gate_report(tampered)
    assert any("missing required field: gate_status" in e for e in errors)


def test_schema_matches_module_constants():
    schema = load_evidence_schema()
    assert schema, "finding_evidence_schema.json missing"
    assert schema["gate_status_states"] == list(GATE_STATUS_STATES)
    assert schema["violation_codes"] == list(VIOLATION_CODES)
    assert schema["finding_status_states"] == list(FINDING_STATUS_STATES)
    assert schema["required"] == ["gate_status", "rows_checked", "violations"]
