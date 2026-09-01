#!/usr/bin/env python3
"""validate_finding_quality.py —— finding quality 契约校验入口（主规范 13.3；阻塞项 B4）。

离线、零网络、仓库只读。校验三层一致性：
  1. 契约结构完整：contracts/finding_quality_schema.json 与 contracts/finding_evidence_schema.json
     （8 状态、五门、门 reason 枚举、证据十四字段、classification 枚举、2.7 十条抑制规则、
     十条状态判定规则、evidence 违例码等）；
  2. 实现常量无漂移：契约 ↔ finding_quality_gate.py / evidence_gate.py 模块常量逐项比对；
  3. 行为探针：样例 finding 必须通过判定与校验器；篡改样本（claimed confirmed 但门失败、
     未验证却 eligible、evidence gate 缺证据路径、REJECTED 零违例门报告）必须被拒——
     防止"校验器实际上不校验"。

退出码：0 全部通过；1 存在违例。--json 输出机器可读报告；--root 可指向其他根（用于负例）。
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

SCRIPT_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))
_SRC = SCRIPT_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

REQUIRED_FINDING_SCHEMA_KEYS = (
    "finding_status_states",
    "gates",
    "manual_validation_states",
    "validation_result_states",
    "reachability_evidence_types",
    "impact_categories",
    "gate_reason_enums",
    "evidence_required_fields",
    "inconclusive_indicators",
    "status_semantics",
    "status_decision_order",
    "required",
    "properties",
    "invariants",
    "classification_enums",
    "internal_priority_to_platform_severity",
    "platform_severity_default_by_impact_category",
    "exercise_result_class_by_impact_category",
    "generic_vulnerability_fields",
    "suppression_rules",
    "submission_eligibility_precedence",
)
REQUIRED_CLASSIFICATION_ENUMS = (
    "finding_class",
    "platform_severity",
    "exercise_result_class",
    "submission_eligibility",
    "impact_scope",
)
REQUIRED_SUPPRESSION_RULE_COUNT = 10
REQUIRED_DECISION_RULE_COUNT = 10
REQUIRED_IMPACT_CATEGORY_COUNT = 9
REQUIRED_EVIDENCE_FIELD_COUNT = 14
REQUIRED_GATE_COUNT = 5

REQUIRED_EVIDENCE_SCHEMA_KEYS = (
    "gate_status_states",
    "finding_status_states",
    "presented_as_forms",
    "published_finding_required_fields",
    "violation_codes",
    "gate_notes",
    "required",
    "properties",
    "invariants",
)


def _load_json(path: Path) -> tuple[object, str | None]:
    if not path.is_file():
        return None, f"missing contract file: {path.name}"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as exc:
        return None, f"unparseable contract file {path.name}: {exc}"


def check_finding_quality_schema(contracts: Path) -> list[str]:
    violations: list[str] = []
    data, err = _load_json(contracts / "finding_quality_schema.json")
    if err:
        return [err]
    assert isinstance(data, dict)
    for key in REQUIRED_FINDING_SCHEMA_KEYS:
        if key not in data:
            violations.append(f"finding_quality_schema.{key} missing")
    states = data.get("finding_status_states")
    if not isinstance(states, list) or len(states) != 8:
        violations.append(
            f"finding_quality_schema.finding_status_states must list exactly 8 states (B1 superset)"
        )
    gates = data.get("gates")
    if not isinstance(gates, list) or len(gates) != REQUIRED_GATE_COUNT:
        violations.append(
            f"finding_quality_schema.gates must list exactly {REQUIRED_GATE_COUNT} gates"
        )
    reason_enums = data.get("gate_reason_enums")
    if not isinstance(reason_enums, dict) or set(reason_enums) != set(gates or []):
        violations.append("finding_quality_schema.gate_reason_enums must cover exactly the five gates")
    evidence_fields = data.get("evidence_required_fields")
    if not isinstance(evidence_fields, list) or len(evidence_fields) != REQUIRED_EVIDENCE_FIELD_COUNT:
        violations.append(
            f"finding_quality_schema.evidence_required_fields must list exactly {REQUIRED_EVIDENCE_FIELD_COUNT} fields (spec 2.2)"
        )
    impact_categories = data.get("impact_categories")
    if (
        not isinstance(impact_categories, list)
        or len(impact_categories) != REQUIRED_IMPACT_CATEGORY_COUNT
    ):
        violations.append(
            f"finding_quality_schema.impact_categories must list exactly {REQUIRED_IMPACT_CATEGORY_COUNT} categories (spec 2.2 gate 4)"
        )
    decision_order = data.get("status_decision_order")
    if not isinstance(decision_order, list) or len(decision_order) != REQUIRED_DECISION_RULE_COUNT:
        violations.append(
            f"finding_quality_schema.status_decision_order must list exactly {REQUIRED_DECISION_RULE_COUNT} rules"
        )
    suppression = data.get("suppression_rules")
    if not isinstance(suppression, dict) or len(suppression) != REQUIRED_SUPPRESSION_RULE_COUNT:
        violations.append(
            f"finding_quality_schema.suppression_rules must list exactly {REQUIRED_SUPPRESSION_RULE_COUNT} rules (spec 2.7)"
        )
    classification = data.get("classification_enums")
    if not isinstance(classification, dict):
        violations.append("finding_quality_schema.classification_enums missing")
    else:
        for key in REQUIRED_CLASSIFICATION_ENUMS:
            if not isinstance(classification.get(key), list) or not classification[key]:
                violations.append(f"finding_quality_schema.classification_enums.{key} missing or empty")
    required = data.get("required")
    properties = data.get("properties")
    if isinstance(required, list) and isinstance(properties, dict):
        for field in required:
            if field not in properties:
                violations.append(f"finding_quality_schema.required field not in properties: {field}")
    else:
        violations.append("finding_quality_schema.required/properties missing or wrong type")
    return violations


def check_finding_evidence_schema(contracts: Path) -> list[str]:
    violations: list[str] = []
    data, err = _load_json(contracts / "finding_evidence_schema.json")
    if err:
        return [err]
    assert isinstance(data, dict)
    for key in REQUIRED_EVIDENCE_SCHEMA_KEYS:
        if key not in data:
            violations.append(f"finding_evidence_schema.{key} missing")
    gate_states = data.get("gate_status_states")
    if not isinstance(gate_states, list) or tuple(gate_states) != ("PASS", "REJECTED"):
        violations.append("finding_evidence_schema.gate_status_states must be ['PASS', 'REJECTED']")
    violation_codes = data.get("violation_codes")
    if not isinstance(violation_codes, list) or len(violation_codes) < 10:
        violations.append("finding_evidence_schema.violation_codes missing or truncated")
    required = data.get("required")
    properties = data.get("properties")
    if isinstance(required, list) and isinstance(properties, dict):
        for field in required:
            if field not in properties:
                violations.append(f"finding_evidence_schema.required field not in properties: {field}")
    else:
        violations.append("finding_evidence_schema.required/properties missing or wrong type")
    return violations


def check_finding_quality_drift(root: Path) -> list[str]:
    """契约 ↔ 实现常量逐项比对（finding_quality_gate / evidence_gate）。"""
    violations: list[str] = []
    fq, err = _load_json(root / "contracts" / "finding_quality_schema.json")
    fe, err2 = _load_json(root / "contracts" / "finding_evidence_schema.json")
    if err:
        violations.append(err)
    if err2:
        violations.append(err2)
    if err or err2:
        return violations

    try:
        from authorized_assessment.quality import finding_quality_gate as fqg
        from authorized_assessment.reporting import evidence_gate as eg
    except Exception as exc:  # noqa: BLE001 - 校验器必须报告而非崩溃
        return violations + [f"finding quality modules import failed: {exc}"]

    assert isinstance(fq, dict) and isinstance(fe, dict)

    def _drift(label: str, schema_value: object, impl_value: object) -> None:
        if schema_value != impl_value:
            violations.append(f"{label} drift: schema={schema_value!r} implementation={impl_value!r}")

    _drift(
        "finding_quality_schema.finding_status_states",
        fq.get("finding_status_states"),
        list(fqg.FINDING_STATUS_STATES),
    )
    _drift("finding_quality_schema.gates", fq.get("gates"), list(fqg.FIVE_GATES))
    _drift(
        "finding_quality_schema.manual_validation_states",
        fq.get("manual_validation_states"),
        list(fqg.MANUAL_VALIDATION_STATES),
    )
    _drift(
        "finding_quality_schema.validation_result_states",
        fq.get("validation_result_states"),
        list(fqg.VALIDATION_RESULT_STATES),
    )
    _drift(
        "finding_quality_schema.reachability_evidence_types",
        fq.get("reachability_evidence_types"),
        list(fqg.REACHABILITY_EVIDENCE_TYPES),
    )
    _drift(
        "finding_quality_schema.impact_categories",
        fq.get("impact_categories"),
        list(fqg.IMPACT_CATEGORIES),
    )
    _drift(
        "finding_quality_schema.evidence_required_fields",
        fq.get("evidence_required_fields"),
        list(fqg.EVIDENCE_REQUIRED_FIELDS),
    )
    _drift(
        "finding_quality_schema.inconclusive_indicators",
        fq.get("inconclusive_indicators"),
        list(fqg.INCONCLUSIVE_INDICATORS),
    )
    _drift(
        "finding_quality_schema.gate_reason_enums",
        fq.get("gate_reason_enums"),
        {gate: list(reasons) for gate, reasons in fqg.GATE_REASON_ENUMS.items()},
    )
    schema_rules = [item.get("rule") for item in fq.get("status_decision_order") or []]
    _drift(
        "finding_quality_schema.status_decision_order rule ids",
        schema_rules,
        list(fqg.STATUS_RULE_IDS),
    )
    enums = fq.get("classification_enums") or {}
    _drift(
        "finding_quality_schema.classification_enums.finding_class",
        enums.get("finding_class"),
        list(fqg.FINDING_CLASSES),
    )
    _drift(
        "finding_quality_schema.classification_enums.platform_severity",
        enums.get("platform_severity"),
        list(fqg.PLATFORM_SEVERITIES),
    )
    _drift(
        "finding_quality_schema.classification_enums.exercise_result_class",
        enums.get("exercise_result_class"),
        list(fqg.EXERCISE_RESULT_CLASSES),
    )
    _drift(
        "finding_quality_schema.classification_enums.submission_eligibility",
        enums.get("submission_eligibility"),
        list(fqg.SUBMISSION_ELIGIBILITIES),
    )
    _drift(
        "finding_quality_schema.classification_enums.impact_scope",
        enums.get("impact_scope"),
        list(fqg.IMPACT_SCOPES),
    )
    _drift(
        "finding_quality_schema.internal_priority_to_platform_severity",
        fq.get("internal_priority_to_platform_severity"),
        dict(fqg.INTERNAL_PRIORITY_TO_PLATFORM_SEVERITY),
    )
    _drift(
        "finding_quality_schema.platform_severity_default_by_impact_category",
        fq.get("platform_severity_default_by_impact_category"),
        dict(fqg.PLATFORM_SEVERITY_DEFAULT_BY_IMPACT_CATEGORY),
    )
    _drift(
        "finding_quality_schema.exercise_result_class_by_impact_category",
        fq.get("exercise_result_class_by_impact_category"),
        dict(fqg.EXERCISE_RESULT_CLASS_BY_IMPACT_CATEGORY),
    )
    _drift(
        "finding_quality_schema.generic_vulnerability_fields",
        fq.get("generic_vulnerability_fields"),
        list(fqg.GENERIC_VULNERABILITY_FIELDS),
    )
    _drift(
        "finding_quality_schema.suppression_rules",
        fq.get("suppression_rules"),
        {rule: dict(spec) for rule, spec in fqg.SUPPRESSION_RULES.items()},
    )

    _drift(
        "finding_evidence_schema.gate_status_states",
        fe.get("gate_status_states"),
        list(eg.GATE_STATUS_STATES),
    )
    _drift(
        "finding_evidence_schema.violation_codes",
        fe.get("violation_codes"),
        list(eg.VIOLATION_CODES),
    )
    _drift(
        "finding_evidence_schema.presented_as_forms",
        fe.get("presented_as_forms"),
        list(eg.PRESENTED_AS_FORMS),
    )
    _drift(
        "finding_evidence_schema.finding_status_states vs finding_quality_schema",
        fe.get("finding_status_states"),
        fq.get("finding_status_states"),
    )
    _drift(
        "finding_evidence_schema.finding_status_states vs evidence gate 8-state import",
        fe.get("finding_status_states"),
        list(fqg.FINDING_STATUS_STATES),
    )
    return violations


def _sample_confirmed_finding() -> dict:
    return {
        "finding_id": "F-VALIDATE-1",
        "source_run": "runs/validate_probe",
        "engagement_id": "eng-validate-probe",
        "target": "https://target.example.com",
        "asset_identity": "target.example.com (approved target)",
        "vulnerability_family": "authorization_bypass",
        "precondition": "low-privilege account",
        "minimal_reproduction": "GET /api/admin/users with low-privilege session -> 200 with other-tenant records",
        "observed_result": "cross-tenant records returned",
        "impact_statement": "unauthorized read of other tenants' objects",
        "evidence_ref": "evidence/F-VALIDATE-1.txt",
        "validation_result": "verified",
        "reviewer": "operator-a",
        "reviewed_at": "2026-08-29T12:00:00+08:00",
        "manual_validation_status": "verified",
        "authorization": {
            "in_scope": True,
            "scope_confirmed": True,
            "credentials_authorized": True,
            "approval_required": False,
        },
        "reachability": {"evidence_type": "authenticated_response"},
        "reproducibility": {
            "baseline_recorded": True,
            "anomalous_response_recorded": True,
            "repeatable": True,
            "one_time_anomaly": False,
            "minimal_steps_recorded": True,
        },
        "impact": {"category": "unauthorized_object_access", "hypothesis": "cross-tenant read"},
    }


def probe_finding_gate_behaviour() -> list[str]:
    """行为探针：判定器与校验器必须真实工作（正例过、篡改负例被拒）。"""
    violations: list[str] = []
    from authorized_assessment.quality import finding_quality_gate as fqg

    report = fqg.evaluate_finding_quality(_sample_confirmed_finding())
    if report.get("finding_status") != "confirmed":
        violations.append(f"probe: sample finding should classify confirmed, got {report.get('finding_status')!r}")
    errors = fqg.validate_finding_quality_report(report)
    if errors:
        violations.append(f"probe: clean sample report rejected by validator: {errors}")

    classification = fqg.build_finding_classification(_sample_confirmed_finding())
    if classification.get("submission_eligibility") != "eligible":
        violations.append(
            f"probe: verified sample should be eligible, got {classification.get('submission_eligibility')!r}"
        )
    errors = fqg.validate_finding_classification(classification)
    if errors:
        violations.append(f"probe: clean sample classification rejected by validator: {errors}")

    tampered = dict(report)
    tampered["gate_results"] = dict(report["gate_results"])
    tampered["gate_results"]["reproducibility"] = {"passed": False, "reasons": ["not_repeatable"]}
    if not fqg.validate_finding_quality_report(tampered):
        violations.append("probe: validator accepted a confirmed report with a failed gate (gate must reject)")

    unverified_input = {**_sample_confirmed_finding(), "manual_validation_status": "not_started"}
    unverified_classification = fqg.build_finding_classification(unverified_input)
    tampered_classification = dict(unverified_classification, submission_eligibility="eligible")
    if not fqg.validate_finding_classification(tampered_classification):
        violations.append("probe: validator accepted eligible classification for an unverified candidate (gate must reject)")
    if unverified_classification.get("submission_eligibility") != "manual_review_required":
        violations.append(
            "probe: unverified AI candidate must map to manual_review_required (spec 2.7 rule 9), "
            f"got {unverified_classification.get('submission_eligibility')!r}"
        )
    return violations


def probe_evidence_gate_behaviour() -> list[str]:
    """行为探针：evidence gate 必须放行有证据的行并拒绝缺证据的行。"""
    violations: list[str] = []
    from authorized_assessment.reporting import evidence_gate as eg

    row = {
        "finding_id": "F-VALIDATE-1",
        "finding_status": "confirmed",
        "evidence_ref": "evidence/F-VALIDATE-1.txt",
        "validation_result": "verified",
        "reviewer": "operator-a",
        "reviewed_at": "2026-08-29T12:00:00+08:00",
    }
    try:
        with tempfile.TemporaryDirectory() as tmp:
            evidence_file = Path(tmp) / "evidence" / "F-VALIDATE-1.txt"
            evidence_file.parent.mkdir(parents=True)
            evidence_file.write_text("baseline vs anomalous diff", encoding="utf-8")
            ok_report = eg.evaluate_evidence_gate([row], tmp)
            if ok_report.get("gate_status") != "PASS":
                violations.append(f"probe: evidence gate should PASS with existing evidence: {ok_report}")
            errors = eg.validate_evidence_gate_report(ok_report)
            if errors:
                violations.append(f"probe: clean evidence gate report rejected by validator: {errors}")

        bad_report = eg.evaluate_evidence_gate([row], SCRIPT_ROOT)
        if bad_report.get("gate_status") != "REJECTED":
            violations.append("probe: evidence gate must REJECT rows whose evidence path does not exist")
        elif not any(v["code"] == "evidence_path_not_found" for v in bad_report["violations"]):
            violations.append("probe: missing evidence path did not yield evidence_path_not_found")
    except OSError as exc:
        return [f"probe: temporary directory unavailable, evidence positive probe skipped: {exc}"]
    return violations


def probe_evidence_validator_negative() -> list[str]:
    from authorized_assessment.reporting import evidence_gate as eg

    violations: list[str] = []
    tampered = {"gate_status": "REJECTED", "rows_checked": 1, "violations": []}
    if not eg.validate_evidence_gate_report(tampered):
        violations.append("probe: validator accepted a REJECTED gate report with zero violations (gate must reject)")
    return violations


def collect_violations(root: Path = SCRIPT_ROOT) -> list[str]:
    contracts = root / "contracts"
    violations: list[str] = []
    violations += check_finding_quality_schema(contracts)
    violations += check_finding_evidence_schema(contracts)
    violations += check_finding_quality_drift(root)
    violations += probe_finding_gate_behaviour()
    violations += probe_evidence_gate_behaviour()
    violations += probe_evidence_validator_negative()
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="校验 finding quality 契约、常量与门行为（离线）")
    parser.add_argument("--json", action="store_true", help="输出机器可读 JSON 报告")
    parser.add_argument("--root", type=Path, default=SCRIPT_ROOT, help="项目根（默认仓库根）")
    args = parser.parse_args(argv)

    violations = collect_violations(args.root.resolve())
    if args.json:
        print(
            json.dumps(
                {"root": str(args.root), "violations": violations, "ok": not violations},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        if violations:
            print(f"[!] {len(violations)} 项 finding quality 违例：")
            for item in violations:
                print(f"  - {item}")
        else:
            print("[+] finding quality 校验通过：2 个契约结构完整，实现常量无漂移，行为探针全部符合预期")
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
