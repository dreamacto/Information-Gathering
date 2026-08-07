# Data-to-test playbook

Use this reference when converting recovered mini-program code, platform APIs, request wrappers, traffic,
fields, roles, and workflow states into concrete tests. Keep client, platform, owned backend, and third-party
services separate. Testing remains low-rate and read-only by default.

## Start from recovered facts

For every candidate test, record this chain in `review_ledger.csv` or a linked note:

`source -> extracted fact -> hypothesis -> payload family -> expected secure behavior -> observation -> disposition`

Useful sources include decoded QR or share links, AppID or platform identifiers, package manifests, app
configuration, route tables, request wrappers, constants, storage keys, cloud-function names, captured
traffic, webviews, platform plugin declarations, and role-specific screens.

## Decode and triage before dynamic testing

Use local/offline decoding first:

- QR or share link: recover platform, AppID, path, scene/query parameters, and distribution clues.
- Package/cache/source: recover manifests, pages, subpackages, components, request base URLs, storage keys, and
  feature flags.
- Traffic export: recover hosts, paths, methods, auth hints, object IDs, roles, content types, and state-changing
  endpoints.
- Webview URLs: separate browser-origin behavior from native mini-program behavior.

Record successful and failed decoding attempts in `artifacts/decoding-ledger.csv`.

## Convert data shapes into test ideas

| Recovered data | Test direction | Safe default |
|---|---|---|
| `openid`, `unionid`, phone, member ID | Identity binding and personal-data exposure | Do not store raw identifiers; use masked values, length, and hashes |
| `userId`, `tenantId`, `orgId`, `shopId`, `schoolId` | Object and tenant authorization | Compare only authorized test users and tenants |
| `code`, `session_key`, token, signature, nonce, timestamp | Login exchange, replay, signature verification, token lifecycle | Record metadata and rejection behavior without retaining secret values |
| `page`, `path`, `scene`, share parameters | Deep-link authorization and hidden workflow access | Open own/test links first; avoid third-party records |
| `cloudFunction`, `env`, storage bucket | Cloud ownership, function authorization, storage ACLs | Classify ownership before active backend calls |
| Order, coupon, points, refund, entitlement state | Business state-transition and replay logic | Use sandbox or disposable test data only |
| Upload/download/preview keys | File authorization and storage boundaries | Use operator-provided or disposable files only |
| Plugin, map, payment, analytics, customer service SDK | Platform or third-party boundary | Classify; do not actively test unless in scope |

## Build a compact role and object matrix

For each recovered endpoint, cloud function, page, or webview workflow, identify:

- Actors: anonymous launch, own test user, second test user, low-privilege role, privileged role when supplied.
- Objects: own object, second test user's object, nonexistent object, public object, expired or completed object.
- Tenant or organization: own tenant, second authorized tenant when supplied, invalid tenant.
- Client route and backend endpoint: route parameters, request wrapper defaults, state-changing flags.
- Expected secure behavior: allow, deny, same-user only, same-tenant only, one-time only, server-side validation.

Only run the cells needed to prove or reject a hypothesis. Mark unavailable cells as `blocked` or
`approval_required` with the exact missing account, role, device, backend scope, sandbox, or approval.

## Choose payload families by context

Use context-specific payload families:

- Authorization: ID substitution, role comparison, tenant boundary, hidden page or function call.
- Session/auth: replay of stale code/token metadata, logout invalidation, timestamp/nonce handling, signature mismatch.
- Input handling: type confusion, length boundary, delimiter/encoding edge, benign syntax probe, reflected marker.
- File handling: filename normalization, extension/MIME mismatch, preview/download authorization, size boundary.
- Business logic: duplicate submit, sequence skip, coupon/points/price mismatch, order/refund entitlement.
- Webview/bridge: origin checks, deep-link trust, postMessage/native bridge exposure, URL parameter trust.
- Cloud/storage: function permission boundary, storage object ACL, environment separation.

Do not send a generic payload list blindly. Prefer paired positive and negative controls.

## Keep testing bounded

- Configure low concurrency, delays, short queues, response-size limits, and backoff before automation.
- Keep automated runs read-only unless a named write or state change has explicit operator approval.
- Stop after minimum proof. Do not export bulk data, retain sensitive identifiers, or keep unnecessary responses.
- Redact or summarize cookies, tokens, login codes, phone numbers, open identifiers, addresses, messages, order details,
  payment data, and business records in prompts, ledgers, screenshots, and reports.
- If a test would create, modify, delete, upload, transact, execute code, change account/session state, or affect a real
  user, record it as `approval_required` until the operator approves the exact action and cleanup plan.

## Record dispositions

Use these outcomes consistently:

- `rejected`: the boundary behaved securely or the candidate was a false positive.
- `needs_manual_validation`: evidence is incomplete but the branch is safe to continue later.
- `approval_required`: the next step is state-changing, sensitive, high-volume, or out of current scope.
- `confirmed`: the finding has minimal, redacted evidence and demonstrated impact.
- `accepted_risk`, `fixed`, `retest_failed`, `retest_passed`: use only after operator or retest evidence supports it.
