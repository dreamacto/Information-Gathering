# Website assessment workflow

## Contents

1. Intake and preflight
2. Discovery and mapping
3. Security testing
4. Validation and closure
5. Resume logic

## 1. Intake and preflight

### Authorization

Use the user-supplied website or domain as the initial authorization basis and convert it into an
explicit scope table. If no separate authorization reference is supplied, record
`user_supplied_initial_target`; do not pause to ask for proof of the original target. Include allowed
hosts, schemes, ports, paths, APIs, accounts, roles, source addresses, window, rate, prohibited actions,
approval-gated actions, data rules, recording rules, and emergency contact.

Normalize redirects and aliases without automatically expanding scope. Place discovered assets in one
of: `in_scope`, `confirmation_required`, `third_party`, `platform_shared`, or `invalid`.

### Safety and reproducibility

- Synchronize the system clock and begin required recording.
- Record public egress addresses if required by the rules.
- Set concurrency, delay, retry, timeout, redirect, body-size, queue-size, and backoff limits before
  any active request. Use low rates by default and stop on service degradation, error spikes, latency
  changes, or signs that normal users could be affected.
- Keep automation read-only by default. Do not create, update, delete, upload, import, export,
  transact, change credentials/sessions/accounts, create webhooks/jobs, execute commands, or persist
  access without first explaining the exact action and receiving explicit operator approval.
- Establish a service-health baseline and stop thresholds.
- Create separate storage for raw evidence and redacted evidence.
- Prepare test accounts, role matrix, test data, and cleanup identifiers.

### Tool capability map

Inventory available tools and map them to DNS, TLS, HTTP probing, crawling, browser automation,
proxy capture, API clients, source review, content discovery, template scanning, screenshots, hashing,
and reporting. Record missing capabilities before execution.

## 2. Discovery and mapping

### Passive context

Collect public ownership and architecture clues, DNS records, certificate names, registration context,
historical URLs where allowed, public code or documentation references, and technology hints. Treat
all discovered names as candidates until scope is confirmed.

**Mandatory tool wiring (2026-08-23; conditional-reuse rule added same day)**: when the operator
has confirmed domain-level authorization (root domain registered, or explicit wildcard like
*.example.com), the passive context step resolves subdomains as follows:

**Step 0 — single-target mode (2026-08-25): do not silently treat historical review as current coverage.** When the
engagement was started from a post-run review recommendation (深挖推荐.md / the prompt-dispatcher
website prompt) or the operator supplied a single host as the whole scope, the host is an initial
scope anchor only. WZ must still record and execute its own required phases; the recommendation
may be kept as a `historical_lead`, but it cannot mark discovery, mapping, authorization, input,
business_logic, or validation complete.

Default behavior in this mode:

- Scope starts anchored to the supplied host (record `source=single_target_anchor`), subject to current authorization.
- Do NOT run dictionary enumeration for the parent domain unless the operator explicitly asks
  ("expand siblings" / "把兄弟子域也带上"). Record the skip decision and reason in the phase note
  (negative space); this is a scope choice, not proof that the current site was fully tested.
- If mid-flow evidence surfaces sibling hosts, add them as `confirmation_required` and surface them to the operator; do not probe.

**Step 1 — current-engagement-only discovery:** WZ must not automatically read or import
`runs/*`, `postrun_review`, FH verdicts, or historical reports. A recent run may only be used
when the operator explicitly provides a selected historical lead; such material remains
`historical_lead` and `unverified`, and does not mark any WZ phase complete. If the operator
wants to import it, use the isolated run-import path and preserve lineage; never append it
silently to the current endpoint inventory.

**Step 2 — enumerate only when uncovered:** if no current engagement coverage exists and the
operator has authorized sibling expansion, run the built-in dictionary enumeration instead of
hand-written spot checks:

```
python subdomain_bruteforce_controlled.py --targets <root-domain-list.txt> --out-dir <engagement>/artifacts/subdomain --delay 2 --concurrency 3
```

The tool already auto-anchors to the registered parent (www.example.com -> example.com) and
suffix-filters results to in-domain hosts only. Post-processing rules:

- Resolved in-domain subdomains go into `scope.csv` as `in_scope` with `source=subdomain_dns`
  (domain-level authorization covers them); third-party or out-of-domain hits stay
  `confirmation_required` and are never probed.
- Sync every new host into `notes/target-model.md` and the endpoint inventory the same phase.
- If the tool is unavailable or the operator explicitly wants passive-only for this target, record
  that decision and the reason in the phase note (negative space) — silent omission is forbidden;
  discovering hosts mid-flow via JS chains (like api.example.com surfacing in a later phase) after
  skipping enumeration is exactly the failure this rule prevents.

### Active low-rate discovery

For confirmed assets, collect DNS resolution, reachable schemes and ports, redirects, status, title,
TLS metadata, server behavior, body fingerprints, favicon/hash where useful, and service-health changes.
Run active discovery with the configured low-rate profile and pause on target instability. Resolve
wildcard DNS and soft-404 behavior before trusting enumeration results.

### Application mapping

Map navigation, anonymous and authenticated routes, forms, parameters, cookies, headers, JavaScript,
source maps, API bases, API schemas, GraphQL endpoints, WebSockets, file operations, redirects,
background jobs, webhooks, administrative surfaces, error behavior, and role-dependent features.

Build an endpoint inventory with method, host, path, parameters, content type, auth requirement, roles,
state-changing behavior, source, and last test result. Capture authenticated traffic only with approved
accounts and redact secrets at ingestion.

**Application mapping subphases (2026-08-29; applicability first)**: keep `application_mapping` as one
top-level phase and audit it through five subphases — `graphql_mapping`, `websocket_mapping`,
`file_surface_mapping`, `auth_surface_mapping`, `webhook_mapping`. Before testing a surface, answer the
applicability questions: does the surface exist, are input points or endpoints known, is authorized
material available, is a low-risk check allowed, and is there a successful response to learn from. Only
`applicable` surfaces enter testing; a surface judged not applicable must still be recorded as
`status=not_applicable` with a non-empty reason — silent omission is forbidden, and `not_applicable`
requires the recorded applicability decision (`applicable=not_applicable`), not an unverified claim.

Record the result of every subphase in `phase_status.json` under the `application_mapping` phase's
`substatuses` map, using exactly one of the six substatus values: `tested`, `not_applicable`, `blocked`,
`approval_required`, `needs_manual_validation`, `inconclusive`. Each subphase writes its artifact under
`artifacts/application-map/` — `graphql-manifest.json`, `websocket-inventory.csv`,
`file-surface-inventory.csv`, `auth-surface-inventory.csv`, `webhook-inventory.csv` — and every artifact
row carries at least the seven contract fields: `applicable`, `status`, `source`, `asset`,
`endpoint_or_surface`, `reason`, `evidence_ref`. A `tested` row needs a non-empty `evidence_ref` that
resolves to a file inside the workspace. The mapping phase may only be marked complete when all five
substatuses are recorded and provable from their artifacts; a subphase that cannot proceed keeps the
phase open as `blocked`/`in_progress` with the substatus recording why.

## 3. Security testing

### Baseline automation

Run low-impact, read-only configuration and exposure checks first. Pin scope, rate, and templates.
Preserve raw structured output. Review every match manually. Run intrusive or state-changing templates
only when their exact behavior is permitted and the operator has approved the action.

### Manual and browser testing

Use the test matrix to cover anonymous, authenticated, role-separated, API, client-side, and business
logic behavior. Compare requests across users and roles with one variable changed at a time. Check
both positive and negative paths, direct requests, alternate methods/content types, and stale sessions.
Keep browser/API automation read-only unless a specific write action has been approved.

### Impact validation

Create a candidate before validation. Define the hypothesis, expected secure behavior, minimum test,
stop condition, data-handling rule, and cleanup plan. Confirm only when repeatable evidence shows a
security boundary failure and meaningful impact. Otherwise reject with reason or retain as gated.

For code execution, data access, file writes, transactions, account changes, internal access, or
service-impacting behavior, obtain exact approval and stop at minimum proof. Never use production data
as a trophy or retain sensitive values.

## 4. Validation and closure

### False-positive review

Exclude wildcard DNS, soft 404s, generic gateways, uniform error pages, login redirects, WAF blocks,
cached responses, unstable content, safe encoding, non-executable reflection, version-only matches,
and behavior without a crossed boundary.

### Evidence

For confirmed findings, preserve a timestamp, target, account role, request description, redacted
response structure, minimal steps, impact, cleanup result, and evidence hash/reference. Keep raw data
restricted and provide redacted report artifacts.

### Cleanup and retest

Remove test accounts, files, objects, webhooks, tokens, jobs, and other artifacts when authorized and
required. Revoke sessions and verify restoration. Retest fixes with the original minimal proof and a
nearby negative control. Record `retest_passed`, `retest_failed`, or `not_retested`.

### Final report

Include executive summary, scope, rules, methodology, coverage, findings, rejected high-priority
candidates, limitations, gated tests, cleanup, retest, residual risk, evidence index, and appendices.

## 5. Resume logic

1. Read `engagement.json`, `scope.csv`, `phase_status.json`, and `review_ledger.csv`.
2. Confirm that the target and recorded scope match the current task; do not reopen authorization for
   the original user-supplied target.
3. Check process logs and artifact timestamps before rerunning anything.
4. Resume the first incomplete required phase; do not discard completed raw outputs.
5. Revalidate scope and service health before active requests.
6. Preserve prior human dispositions when regenerating inventories or ledgers.
7. Same-asset site extension (2026-08-23): when the task is a different site of an already-tested
   asset, resume that asset's workspace (`init_engagement.py <site-host> --resume <workspace>` —
   requires the parent domain's domain-level authorization on record). The site joins the same
   scope.csv (source=same_asset_site_extension); ledger item IDs are **site-scoped**
   (`<host-short>-L<N>`, starting at 1 per site, because reports are delivered per site), and
   `notes/target-model.md` stays the single accumulating snapshot for the whole asset. Never start
   a parallel workspace for the same asset.
