---
name: test-miniapp-full-cycle
description: Conduct an authorized, end-to-end security assessment of one mini-program from a name, AppID, QR image, package, unpacked source, device cache, traffic export, or entry URL through identity confirmation, static and dynamic client analysis, backend ownership classification, API and web testing, authentication and business-logic review, bounded impact validation, evidence, cleanup, retesting, and final reporting. Use when an AI must assess a WeChat, Alipay, Douyin, Baidu, Quick App, or other mini-program completely rather than stop at package extraction or endpoint discovery.
---

# Test One Mini-Program from Intake to Closure

Take one authorized mini-program from any practical starting artifact to a defensible final report.
Keep the client, platform, owned backend, and third-party services separate. Do not treat a package URL,
traffic host, static secret pattern, or scanner result as a confirmed finding.

## Load the right references

- Read [references/workflow.md](references/workflow.md) before starting or resuming.
- Read [references/test-matrix.md](references/test-matrix.md) while planning static, dynamic, API,
  platform, and business coverage.
- Read [references/data-to-test-playbook.md](references/data-to-test-playbook.md) when converting
  recovered code, platform APIs, request wrappers, traffic, fields, roles, and workflows into tests.
- Read [references/package-analysis.md](references/package-analysis.md) whenever a package, cache
  directory, unpacked tree, bundle, or source archive is available.
- Read [references/artifact-contract.md](references/artifact-contract.md) before classifying hosts,
  auditing outputs, or closing.
- Read [references/evidence-reporting.md](references/evidence-reporting.md) for finding validation,
  sensitive-data minimization, severity, cleanup, and the final report.

## Accept the supplied mini-program, then establish identity and platform

1. Treat the mini-program supplied by the user as the confirmed current target. Do not ask the user to
   prove again that this initial target may be tested. When no separate authorization reference is
   supplied, record the basis as `user_supplied_initial_target`.
2. Record any supplied accounts, devices, test window, source addresses, transaction rules, prohibited
   actions, data handling, recording, and contact without blocking on unspecified optional metadata.
3. First attempt local, offline decoding of the supplied information or artifact. Decode QR images,
   parse entry/share links, inspect identifiers, unpack package/cache material, parse traffic exports,
   and recover manifests or source clues before moving to dynamic testing. Record successes, partial
   recoveries, tool versions, and failures.
4. Identify the platform: WeChat, Alipay, Douyin, Baidu, Quick App, or other. Do not force WeChat
   assumptions onto another platform.
5. Establish the mini-program name, AppID or equivalent identifier, operating entity, version,
   distribution source, and identity evidence. Mark ambiguity explicitly.
6. Treat domains, cloud functions, plugins, webviews, identity providers, payment providers, maps,
   analytics, customer service, CDNs, and vendors as separate assets until ownership and scope are clear.
7. Set a low-rate, non-disruptive execution profile before any active request or dynamic interaction.
   Use conservative concurrency, delays, retry limits, timeouts, response-size limits, and backoff; stop
   immediately when the target slows down, errors spike, or normal work could be affected.
8. Automated testing is read-only by default. Before any write or state-changing action, explain the
   action, expected effect, risk, evidence value, and cleanup plan, then wait for the operator's
   explicit approval. This includes create, update, delete, upload, import, export, transaction,
   password/account/session changes, webhook/job creation, command execution, and persistence.
9. Require explicit approval for destructive, persistent, high-volume, credential-spraying,
   transaction-changing, data-exporting, code-execution, device-compromising, or third-party actions.

## Create a portable engagement workspace

Run the initializer before analysis:

```text
<python> scripts/init_miniapp_engagement.py <input> --output <work-dir> \
  --platform auto
```

Input may be a name, AppID, QR image, package, package/cache directory, unpacked source, HAR/XML/TXT
traffic export, or entry URL. The initializer performs no network access and creates resumable identity,
material, host, endpoint, phase, ledger, evidence, and report artifacts.

## Discover tools and choose the execution path

1. Inventory package parsers, decompilers, source analyzers, emulators/devices, platform developer tools,
   intercepting proxies, certificate tooling, runtime instrumentation, browser automation, API clients,
   crawlers, scanners, screenshot tools, and reporting utilities already available.
2. Record tool versions, supported platforms, configuration, output paths, and missing capabilities.
3. Prefer original packages and read-only copies. Hash every supplied material before transformation.
4. Do not download tools, install certificates, modify a device, bypass pinning, repack a client, or
   instrument a process silently. Confirm that the action is permitted and use a designated test device.
5. Configure decoders, crawlers, proxies, device automation, and API clients for read-only behavior,
   low request rates, small queues, and stop-on-error/backoff before running them.
6. Select only the branches relevant to the input and platform, but record every branch as complete,
   blocked, approval required, or not applicable with reason.

## Execute the complete workflow

Follow `references/workflow.md`. At minimum, cover:

1. Authorization, identity, platform, material provenance, hashing, preflight, recording, and stop rules.
2. Initial local decoding of supplied information, QR/link/package/cache/source/traffic artifacts, and
   any recovered identifiers, manifests, routes, endpoints, or package clues.
3. Package inventory, unpacking/decompilation, main/subpackage recovery, source reconstruction,
   beautification and bounded deobfuscation, manifest/config review, route and component inventory,
   embedded host and API extraction, secret-pattern triage, storage, crypto, logging, debug, update,
   and integrity review.
4. Controlled dynamic setup, proxy capture, launch/login/session flows, screen and route mapping,
   request inventory, error behavior, background traffic, and platform API usage.
5. Classification of every host and service as `in_scope`, `confirmation_required`, `third_party`,
   `platform`, `out_of_scope`, or `invalid` before active backend testing.
6. Authentication code exchange, token/session lifecycle, replay controls, signatures, nonce/timestamp,
   account binding, logout, recovery, role, tenant, object, and function authorization.
7. API and web behavior, input handling, file transfer, server-side fetches, client storage, webviews,
   JavaScript bridges, deep links, plugins, cloud functions/storage, and third-party SDK boundaries.
8. Business state transitions, duplicate submission, concurrency, quotas, approvals, invitations,
   orders, prices, coupons, points, payments, refunds, sharing, and entitlement logic using disposable
   data and non-financial test modes where authorized.
9. Candidate validation, false-positive removal, minimal impact proof, evidence, cleanup, retest,
   and final reporting.

For each confirmed owned backend, execute the full website/API assessment process. Invoke
`$test-website-full-cycle` when available; otherwise apply the same scope, mapping, testing,
validation, evidence, cleanup, and reporting requirements directly. Do not make this skill depend on
a particular repository or scanner.

For every active test, record `source -> extracted fact -> hypothesis -> payload family -> expected
secure behavior -> observation -> disposition`. Select payloads from the recovered parameter type,
request context, role, workflow state, and server behavior; do not send a generic payload list blindly.

## Maintain inventories and ledgers

Maintain:

- `phase_status.json` for coverage.
- `materials.csv` for provenance and analysis state.
- `artifacts/decoding-ledger.csv` for local decoding attempts, recovered clues, and failures.
- `artifacts/package-inventory.csv` for every main package, subpackage, extractor, and result.
- `artifacts/source-map.csv` for every recovered or supplied source file and its origin.
- `hosts.csv` for ownership and scope classification.
- `endpoints.csv` for client and backend routes, methods, auth, roles, and test status.
- `review_ledger.csv` for candidates and findings.
- `evidence/index.csv` for minimized evidence.
- `notes/safety-controls.md` for rate limits, read-only mode, write-approval gates, and stop thresholds.

Use phase statuses `pending`, `in_progress`, `complete`, `blocked`, or `not_applicable`. Use review
statuses `candidate`, `needs_manual_validation`, `approval_required`, `confirmed`, `rejected`,
`accepted_risk`, `fixed`, `retest_failed`, or `retest_passed`.

When package material exists, do not mark static analysis complete after strings/URL extraction alone.
Attempt unpacking/decompilation, enumerate all subpackages, reconstruct readable source as far as the
available tools permit, and record every success and failure. Never remove a host because it is
inconvenient. Classify it. Never delete a candidate to make the engagement appear complete.

Keep `package_inventory`, `package_unpack_decompile`, and `source_reconstruction` as separate required
phases whenever package material exists. A failed extractor leaves the package branch blocked; it does
not make the branch not applicable.

## Protect accounts, devices, transactions, and data

1. Use designated test accounts, devices, phone numbers, identities, tenants, and payment sandboxes.
2. Keep package originals, credentials, session tokens, platform login codes, open identifiers,
   private keys, and raw traffic in restricted local storage.
3. Redact cookies, tokens, secrets, personal data, order details, addresses, messages, files, and
   business response values before they enter logs, prompts, screenshots, ledgers, or reports.
4. Stop after minimum proof. Do not complete real payments, affect another user, retain sensitive data,
   or leave test files, accounts, orders, webhooks, sessions, or cloud objects behind.
5. Treat every automated branch as read-only unless the operator has explicitly approved a named
   write/state-changing action in the current task. Do not infer approval from general authorization.
6. Record branches not exercised because an account, role, device, approval, backend scope, or sandbox
   was unavailable. “Not tested” is not “not vulnerable.”

## Validate and close

Run the read-only auditor throughout the engagement:

```text
<python> scripts/audit_miniapp_engagement.py <work-dir>
```

Do not close until identity is resolved or explicitly limited, initial decoding is complete or justified,
every supplied package and subpackage has an unpack/decompile result, recovered source is indexed, all
materials have a result, every host is classified, every in-scope backend has full coverage, required
phases are complete or justified not applicable, active candidates are disposed, confirmed findings have
redacted evidence, safety controls and write-approval decisions are recorded, cleanup and retest are
recorded, and `reports/final-report.md` exists.

The final response must identify the mini-program and platform, materials and hashes, tested versions
and accounts, classified backends, client and backend coverage, findings, rejected candidates,
unresolved gates, cleanup, retest, evidence, report paths, and residual risk.
