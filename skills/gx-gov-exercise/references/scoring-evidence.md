# Scoring And Evidence

Use this reference when turning a verified result into a report or platform submission.

## Minimum Evidence

Each submitted result should include:

- Approved target name, URL/IP, defense unit, and asset ownership.
- Clear operation path from entry point to proof.
- Screenshots with visible current system date/time.
- Video recording time range that matches the written steps.
- Tool name/version or manual method used.
- Impact statement mapped to a scoring category.
- Sensitive-data handling statement: proof only, no export/download/storage.

## Common Scoring Buckets

- Domain control: domain admin or DNS/website control proof.
- Application permission: ordinary or admin application access.
- Host permission: shell/container/host proof; stop once permission is proven.
- Database credential or SQL injection: account level and proof, not data dump.
- Network boundary: proof of access to isolated network area, not uncontrolled scanning.
- AI application: prompt injection proof, model app permission, model host permission, or sensitive model-data leakage proof.
- Public big screen: admin permission/control proof without modifying public content.
- 0-day or non-public N-day: independent writeup with impact, affected products, trigger conditions, and safe reproduction notes.

## Approval Gate

Require platform/high-risk approval before:

- Credential spraying or brute force.
- Command execution beyond harmless proof.
- File upload validation.
- Database login validation.
- Webshell, C2, tunnel, proxy, or persistence tooling.
- Internal network scanning.
- Any action that could change data, service state, password, files, or configuration.

## Report Shape

Use the generated files:

- `reports/evidence_index.md` for screenshots and video ranges.
- `reports/daily_report_draft.md` for daily summary.
- `reports/platform_submission_template.json` for platform fields and path nodes.
- `approval_required.md` for any step that must wait.

