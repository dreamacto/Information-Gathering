"""Offline evidence verification adapters.

This module adds strict, side-effect-free composition around :mod:`evidence_gate`.
It never reads evidence content; callers provide the evidence root and optional
reference hashes.  Findings are accepted only when the underlying gate passes.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping

from authorized_assessment.quality.finding_quality_gate import (
    evaluate_finding_quality,
    validate_finding_quality_report,
)
from authorized_assessment.reporting.evidence_gate import (
    evaluate_evidence_gate,
    validate_evidence_gate_report,
)


def _violation(code: str, detail: str, finding_id: str = "") -> dict[str, str]:
    return {"code": code, "finding_id": finding_id, "detail": detail}


def verify_evidence(
    rows: Iterable[Mapping[str, Any]],
    root: str | Path,
    *,
    source_ledger: str | Path | None = None,
    reference_hashes: Mapping[str, str] | None = None,
    actual_hashes: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify evidence and optional supplied hash metadata, without reading content.

    ``reference_hashes`` and ``actual_hashes`` are caller-supplied metadata maps;
    when present they must match exactly for every reference.  Values are never
    included in violations.
    """
    row_list = [dict(row) for row in rows]
    report = evaluate_evidence_gate(row_list, root, source_ledger=source_ledger)
    violations = list(report["violations"])
    if reference_hashes is not None or actual_hashes is not None:
        expected = dict(reference_hashes or {})
        observed = dict(actual_hashes or {})
        for ref in sorted(set(expected) | set(observed)):
            if ref not in expected:
                violations.append(_violation("evidence_hash_missing", f"hash reference missing for {ref}"))
            elif ref not in observed:
                violations.append(_violation("evidence_hash_missing", f"observed hash missing for {ref}"))
            elif expected[ref] != observed[ref]:
                violations.append(_violation("evidence_hash_drift", f"evidence hash drift for {ref}"))
    report = {"gate_status": "PASS" if not violations else "REJECTED", "rows_checked": len(row_list), "violations": violations}
    report["valid"] = not validate_evidence_gate_report(report)
    return report


def verify_finding_evidence(finding: Mapping[str, Any], root: str | Path, **kwargs: Any) -> dict[str, Any]:
    """Verify one finding's quality classification and evidence gate together."""
    quality = evaluate_finding_quality(finding)
    quality_errors = validate_finding_quality_report(quality)
    evidence = verify_evidence([finding], root, **kwargs)
    violations = list(evidence["violations"])
    if quality_errors:
        violations.extend(_violation("finding_quality_invalid", "finding quality report failed validation") for _ in [0])
    if finding.get("finding_status") == "confirmed" and quality.get("finding_status") != "confirmed":
        violations.append(_violation("status_conflict", "input confirmed status conflicts with quality decision", str(finding.get("finding_id", ""))))
    return {"gate_status": "PASS" if not violations else "REJECTED", "finding_id": str(finding.get("finding_id", "")), "quality": quality, "quality_errors": quality_errors, "evidence": evidence, "violations": violations}


# Explicit descriptive alias for callers using the construction-table terminology.
evaluate_evidence = verify_evidence

__all__ = ["verify_evidence", "evaluate_evidence", "verify_finding_evidence"]
