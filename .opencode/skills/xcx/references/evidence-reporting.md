# Mini-program evidence and reporting

## Evidence chain

For each confirmed finding, link:

1. Mini-program platform, identifier, version, and identity evidence.
2. Material ID and SHA-256 or dynamic session/time from which the candidate originated.
3. Client source location, screen/route, or traffic endpoint.
4. Backend host classification and authorization basis.
5. Account role, device/client version, and precondition without secrets.
6. Minimal reproducible action, negative control, and redacted result structure.
7. Demonstrated impact, cleanup, and retest status.
8. Evidence hashes and report-safe paths.

## Validation discipline

A package string is not proof that a service is live. A live endpoint is not proof that it belongs to
the operator. A platform identifier is not a credential. Client-side checks are not proof of a bypass
unless the server accepts the invalid state. A difference between two users is not an authorization
issue unless the expected boundary is established and controlled.

Use a hypothesis, expected behavior, minimum proof, negative control, stop condition, data rule,
approval need, and cleanup plan before validating a candidate. Prefer synthetic objects and designated
accounts. Stop before real-user impact, real payment, bulk access, persistent change, or sensitive-data
retention.

## Report structure

1. Executive summary and business risk.
2. Authorization, scope, platforms, AppIDs/identifiers, versions, timing, and exclusions.
3. Materials, provenance, hashes, accounts, devices, and tools.
4. Architecture and classified host/service inventory.
5. Static client coverage and findings.
6. Dynamic client and platform-flow coverage and findings.
7. Owned backend Web/API coverage and findings.
8. Business-logic coverage and findings.
9. Third-party/platform observations clearly separated from owned findings.
10. Rejected candidates, limitations, blocked and approval-gated tests.
11. Cleanup, retest, residual risk, evidence index, and appendices.

Each finding includes a stable ID, title, severity, affected platform/version/host, description,
preconditions, evidence, impact, root cause, remediation, verification guidance, cleanup, and retest.
Keep raw packages, traffic, credentials, personal data, and secrets out of the report.


## Final report is DOCX (2026-08-23)

Client-facing deliverable is generated: curate findings.json/meta.json then
`python report_docx.py`（or `--from-ledger` skeleton）. Red 【需截图 S-N】 markers must all be
replaced with real screenshots before submission; TOKEN values stay in local session files.
`final-report.md` remains internal working notes.
