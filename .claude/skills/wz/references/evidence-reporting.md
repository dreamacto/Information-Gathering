# Evidence and reporting

## Candidate validation record

Before validation, record:

- hypothesis and affected security boundary
- target, endpoint, method, parameter, role, and precondition
- expected secure behavior
- minimum validating action and negative control
- stop condition, cleanup plan, and approval requirement

After validation, record confirmed, rejected, blocked, or approval required. A tool match without a
repeatable boundary failure remains a candidate.

## Evidence minimum

For each confirmed finding, preserve:

1. Stable finding ID and title.
2. UTC/local timestamp and target.
3. Account role or anonymous context without credentials.
4. Minimal reproducible steps.
5. Redacted request and response structure or equivalent observation.
6. Negative control or expected behavior comparison.
7. Demonstrated impact using disposable or synthetic data where possible.
8. Cleanup result and retest status.
9. SHA-256 hashes and paths for evidence files.

## Severity

Assign severity from demonstrated impact, exploitability, required access, affected scope, detectability,
and environmental controls. Separate technical severity from business priority when needed. Do not
inflate severity from a product version or theoretical exploit chain that was not validated.

## Report structure

1. Executive summary and overall risk.
2. Authorization, scope, exclusions, timing, and rules.
3. Architecture and attack-surface summary.
4. Methodology, tools, accounts, and coverage.
5. Confirmed findings ordered by business risk.
6. Rejected high-priority candidates and why they were rejected.
7. Untested, blocked, approval-gated, and not-applicable areas.
8. Cleanup, retest, residual risk, and recommended next actions.
9. Evidence index and technical appendices.

Each finding includes title, severity, affected asset, description, preconditions, evidence, impact,
root cause, remediation, verification guidance, cleanup, and references. Keep raw secrets and sensitive
data out of the report.


## Final report is DOCX (2026-08-23)

The client-facing deliverable is generated, not hand-written:

1. Reporting phase: curate `reports/findings.json` (one entry per reportable finding — merge related
   ledger rows; title quantifies impact; `commands` are complete one-line curl reproductions using
   $BASE/$TOKEN env vars; TOKEN value stays in local session files, the report writes
   `<见本地凭证文件>`) and `reports/meta.json` (intro/stats/problems/suggestions).
2. Run `python report_docx.py --meta ... --findings ... --out reports/攻防成果报告_<名>_<日期>.docx`
   (skeleton first pass: `--from-ledger <engagement>` fills titles/URLs/levels from confirmed rows).
3. The generator inserts red 【需截图 S-N】 markers automatically — every marker must be replaced
   with a real screenshot (system time visible, sensitive values redacted) before submission.
4. `final-report.md` remains internal working notes only.
