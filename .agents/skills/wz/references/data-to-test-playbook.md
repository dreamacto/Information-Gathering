# Data-to-test playbook

Use this reference when turning discovered routes, parameters, JavaScript, traffic, roles, and workflow
states into concrete, bounded tests. The goal is to avoid generic payload spraying and to preserve a
read-only, low-rate, evidence-minimizing assessment.

## Start from recovered facts

For every candidate test, record this chain in `review_ledger.csv` or a linked note:

`source -> extracted fact -> hypothesis -> payload family -> expected secure behavior -> observation -> disposition`

Use the source that produced the fact: browser traffic, JavaScript, API documentation, HTML forms,
schema files, error messages, redirects, role-specific pages, robots/sitemap, historical URLs, or
operator-provided notes. Do not promote a fact to a finding until the boundary and impact are validated.

## Convert data shapes into test ideas

| Recovered data | Test direction | Safe default |
|---|---|---|
| `id`, `userId`, `accountId`, `tenantId`, `orgId` | Object and tenant authorization, predictable IDs, horizontal access | Compare own objects across authorized test roles; do not access real third-party data |
| `role`, `permission`, `isAdmin`, `status` | Function authorization and state-transition controls | Check visible affordances and rejected server-side calls with read-only methods first |
| Pagination, filters, sorting, export flags | Overbroad reads, hidden records, bulk export gates, rate controls | Use tiny page sizes and counts; avoid bulk download |
| File keys, preview URLs, download endpoints | File retrieval authorization, path/key guessing, content-type handling | Request only disposable or operator-provided files |
| Redirect URLs, callback URLs, webhooks | SSRF/open redirect/callback trust boundaries | Use harmless canary URLs only when approved; otherwise document as gated |
| Search, template, report, import fields | Injection, parser behavior, expensive queries | Prefer benign markers and syntax probes; stop on errors or latency |
| Auth/session headers, CSRF fields, CORS headers | Session lifecycle, CSRF/CORS/cache behavior | Record presence, expiry, and policy differences without storing secret values |
| WebSocket channels or realtime topics | Channel authorization and message validation | Subscribe only to own channels and low-volume flows |
| GraphQL operations or schemas | Field/object authorization, introspection exposure, batching | Query minimal fields and own objects first |

## Build a small matrix before active testing

For each endpoint or workflow, identify:

- Actors: anonymous, own user, second test user, low-privilege role, admin role when supplied.
- Objects: own object, second test user's object, nonexistent object, boundary object, public object.
- Tenant or organization: own tenant, second authorized tenant when supplied, invalid tenant.
- Method and state: safe read, state-changing method, precondition state, completed state, repeated action.
- Expected secure behavior: allow, deny, same-user only, same-tenant only, one-time only, server-side validation.

Run only the cells needed to prove or reject the hypothesis. Mark unavailable cells as `blocked` or
`approval_required` with the exact missing account, role, object, or approval.

## Choose payload families by context

Use payload families, not blind lists:

- Authorization: ID substitution, role comparison, tenant boundary, hidden function call, method override.
- Input handling: type confusion, length boundary, delimiter/encoding edge, benign syntax probe, reflected marker.
- File handling: filename normalization, extension/MIME mismatch, preview/download authorization, size boundary.
- Server-side fetch or callback: approved canary URL, scheme/host allowlist check, redirect behavior.
- Business logic: duplicate submit, replay, sequence skip, quota edge, entitlement mismatch, price/status mismatch.
- Client-side: reflected/stored rendering context, postMessage origin, DOM sink, source map exposure.

Prefer positive and negative controls. A useful control is often more valuable than a larger payload set.

## Turn application-map inventories into bounded tests

The `artifacts/application-map/` inventories produced by the five application-mapping subphases
(graphql/websocket/file-surface/auth-surface/webhook) are the inputs to the later testing phases. Apply
the same fact chain (`source -> extracted fact -> hypothesis -> ... -> disposition`) to each inventory
row and keep every follow-up bounded:

| Inventory row shape | Test direction | Safe default |
|---|---|---|
| `graphql-manifest.json` operations | Field/object authorization, introspection exposure, alias/batching abuse, depth and complexity | Minimal own-object queries first; batched or aliased operations only with the operator aware |
| `websocket-inventory.csv` channels | Handshake auth, origin validation, channel/topic authorization, message validation and replay | Subscribe to own channels at low volume; record frames without replaying other users' traffic |
| `file-surface-inventory.csv` rows | Retrieval authorization, path/key guessing, overwrite behavior, MIME/extension boundaries | Request disposable or operator-provided files only; never bulk-download |
| `auth-surface-inventory.csv` rows | Session lifecycle, account enumeration, lockout behavior, recovery abuse, token lifecycle | Record policy differences and timing signals without storing secret values |
| `webhook-inventory.csv` rows | Callback source/signature/timestamp validation, replay acceptance, SSRF trust boundary | Static review and approved canary URLs only; document as gated otherwise |

A row recorded `not_applicable` in the inventory needs no test — that decision, with its reason, is the
deliverable for that surface. Rows recorded `blocked`, `approval_required`, `needs_manual_validation`,
or `inconclusive` carry the reason and next step; do not re-derive or silently drop them when planning.

## Keep testing bounded

- Configure low concurrency, delays, short queues, response-size limits, and backoff before automation.
- Keep automated runs read-only unless a named write or state change has explicit operator approval.
- Stop after minimum proof. Do not export bulk data, retain sensitive values, or keep unnecessary responses.
- Redact or summarize secrets and sensitive records in prompts, ledgers, screenshots, and reports.
- If a test would create, modify, delete, upload, transact, execute code, or access non-disposable data, record it as
  `approval_required` until the operator approves the exact action and cleanup plan.

## Record dispositions

Use these outcomes consistently:

- `rejected`: the boundary behaved securely or the candidate was a false positive.
- `needs_manual_validation`: evidence is incomplete but the branch is safe to continue later.
- `approval_required`: the next step is state-changing, sensitive, high-volume, or out of current scope.
- `confirmed`: the finding has minimal, redacted evidence and demonstrated impact.
- `accepted_risk`, `fixed`, `retest_failed`, `retest_passed`: use only after operator or retest evidence supports it.
