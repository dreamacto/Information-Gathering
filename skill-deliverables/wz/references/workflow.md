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

**Step 1 — reuse before re-scan**: first check `runs/*/subdomains_resolved.jsonl` and
`runs/*/targets_with_auto_subdomains.txt` for hosts under the engagement's root domain, generated
within the last 7 days. If a recent one-click run already enumerated this domain (status=resolved
rows exist), IMPORT those hosts into `scope.csv` (source=run_subdomain_import, in_scope under
domain authorization) and SKIP re-enumeration — record the reused run directory and row count in
the phase note. Re-scanning what a recent run already covered is redundant work.

**Step 2 — enumerate only when uncovered**: if no recent coverage exists (no run, older than 7
days, or that run enumerated zero resolved hosts), run the built-in dictionary enumeration
instead of hand-written spot checks:

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
