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
