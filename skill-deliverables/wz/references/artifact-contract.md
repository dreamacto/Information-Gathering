# Website engagement artifact contract

## Required root artifacts

| Path | Purpose |
|---|---|
| `engagement.json` | Target, authorization, timing, rules, workspace version |
| `scope.csv` | Every target or discovered asset and its scope state |
| `phase_status.json` | Required phase, status, reason, timestamps, artifact references |
| `review_ledger.csv` | Candidate and finding disposition without deleting history |
| `notes/tool-inventory.md` | Available tools, versions, configuration, missing capabilities |
| `notes/coverage.md` | Test-matrix coverage and limitations |
| `notes/safety-controls.md` | Rate limits, read-only automation mode, write-approval gates, stop thresholds |
| `artifacts/endpoint-inventory.csv` | Methods, routes, parameters, auth, roles, source, status |
| `evidence/index.csv` | Evidence IDs, finding IDs, timestamps, hashes, sensitivity, paths |
| `reports/攻防成果报告_<engagement>_<日期>.docx` | **Final deliverable（主交付，2026-08-23 起）**：由 `python report_docx.py --meta reports/meta.json --findings reports/findings.json` 生成（或 `--from-ledger` 出骨架再补）；红色【需截图】标注补齐前报告未完成 |
| `reports/final-report.md` | Working notes（过程稿，供 findings.json 取材，不再作为对外交付物） |

The initializer creates empty templates for these artifacts. Populate them with structured data as the
engagement progresses. Additional tool outputs belong under `artifacts/` or `logs/`, not beside the
contract files.

## Scope states

Use `in_scope`, `confirmation_required`, `out_of_scope`, `third_party`, `platform_shared`, or `invalid`.
Record source, ownership rationale, permitted actions, and last confirmation time. Only `in_scope`
entries may receive active requests.

## Phase status rules

Use `pending`, `in_progress`, `complete`, `blocked`, or `not_applicable`. A required phase is complete
only when its expected artifact or reason is recorded. `not_applicable` requires a feature-based reason;
`blocked` requires the exact missing account, approval, tool, target, or environment fact.

## Review ledger rules

Each active row needs a stable ID, priority, category, asset, endpoint, status, summary, source,
validation plan, result, and evidence reference where applicable. Confirmed rows must reference
redacted evidence. Rejected rows must state the false-positive reason. Approval-gated rows must name
the exact action and authorization needed.

## Evidence layout

- `evidence/raw/`: restricted original evidence; never attach directly to a report.
- `evidence/redacted/`: minimized screenshots, requests, responses, and transcripts.
- `evidence/index.csv`: mapping, timestamp, hash, sensitivity, retention, and report reference.

Never store passwords, full tokens, session cookies, private keys, unnecessary personal data, or bulk
business data. Prefer field names, counts, status, length, hashes, and controlled test records.

## Closure state

The engagement is closed only when the user-supplied initial target basis is recorded and scope states
are resolved; required phases are complete or justified not applicable; active ledger rows are disposed;
confirmed findings have evidence; cleanup is complete or justified; safety controls and write-approval
decisions are recorded; retest is recorded; and the final report exists.
