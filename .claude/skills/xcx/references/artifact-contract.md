# Mini-program engagement artifact contract

## Required root artifacts

| Path | Purpose |
|---|---|
| `engagement.json` | Authorization, timing, rules, input hash, workspace version |
| `miniapp.json` | Platform, name, AppID/identifier, operator, version, identity status/evidence |
| `materials.csv` | Original packages, source, cache, images, traffic, hashes, provenance, analysis result |
| `artifacts/package-inventory.csv` | Main/subpackages, hashes, extractor/version, extraction result, output directory |
| `artifacts/decoding-ledger.csv` | Local decoding attempts, tools, inputs, recovered clues, failures, output paths |
| `artifacts/source-map.csv` | Recovered/supplied source files and their material/package/internal-path origin |
| `hosts.csv` | Every discovered host/service, ownership, scope state, source, permitted action |
| `endpoints.csv` | Client/backend routes, methods, parameters, auth, roles, state change, test result |
| `phase_status.json` | Coverage phase, applicability, status, reason, artifacts, timestamps |
| `review_ledger.csv` | Candidate/finding disposition and evidence links |
| `notes/tool-inventory.md` | Available tools, versions, configuration, missing capabilities |
| `notes/coverage.md` | Matrix coverage, accounts, devices, versions, limitations |
| `notes/safety-controls.md` | Rate limits, read-only automation mode, write-approval gates, stop thresholds |
| `evidence/index.csv` | Evidence IDs, finding IDs, timestamps, hashes, sensitivity, paths |
| `reports/final-report.md` | Final client/backend/platform-separated report |

## Material states

Use `pending`, `analyzed`, `failed`, `superseded`, or `not_applicable`. Preserve original hashes and
paths. Do not overwrite an old package with a new version; add a material row and record relationships.
A package is `analyzed` only after its package inventory, unpack/decompile result, recovered source map,
and explicit unreadable/unsupported areas are recorded. URL or string extraction alone is insufficient.

## Host scope states

Use `unclassified`, `in_scope`, `confirmation_required`, `third_party`, `platform`, `out_of_scope`,
or `invalid`. Record ownership rationale and source. Only `in_scope` entries may receive active backend
requests. Every active `unclassified` or `confirmation_required` host prevents full closure unless the
report clearly records a justified external blocker and the phase remains blocked.

## Phase and review states

Use phase states `pending`, `in_progress`, `complete`, `blocked`, or `not_applicable`. Use review states
`candidate`, `needs_manual_validation`, `approval_required`, `confirmed`, `rejected`, `accepted_risk`,
`fixed`, `retest_failed`, or `retest_passed`.

Never erase superseded material, hosts, endpoints, or candidates. Mark rows inactive where the schema
supports it and retain source references and human dispositions.

## Sensitive storage

- Keep originals and unredacted traffic under `materials/original/` or `evidence/raw/` with restricted access.
- Analyze copies under `materials/working/`.
- Put report-safe artifacts under `evidence/redacted/`.
- Keep credentials and current sessions under `sessions/`; exclude this directory from sharing and version control.

Do not store full login codes, tokens, cookies, open identifiers tied to people, phone numbers,
addresses, messages, order details, payment data, personal files, or unnecessary business responses.

## Closure state

Close only when the user-supplied initial target basis is recorded; identity and version limitations
are explicit; initial decoding is complete or justified; package, subpackage, unpack/decompile, and
source-reconstruction results are recorded; materials have results; hosts are classified; applicable
client and backend phases are complete; candidates are disposed; confirmed findings have evidence;
safety controls and write-approval decisions are recorded; cleanup/retest are recorded; and the final
report exists.
