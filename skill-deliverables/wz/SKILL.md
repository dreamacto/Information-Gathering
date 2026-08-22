---
name: wz
description: Advance phases of an authorized website, web application, domain, or API assessment. After each phase, write the cursor and handoff-complete records to disk, then ASK the operator whether to continue in this session or hand off — if handoff, emit a self-contained prompt for the new session. Sessions still hard-stop at approval-gated phases, heavy phases, or 70% context budget. Use when an AI is given a website or domain and must push the current phase.
---

## Highest-priority hard constraints (project discipline)

These override every other instruction in this skill. At session start, read only `ROE.md` and `AGENT_MANIFEST.md` plus the contract for the current phase; load references on demand.

1. **Session window: advance until a stop point, ask at every phase boundary.** You may advance multiple lightweight phases in one session (scope → subdomain → alive_probe → fingerprint style), but after EVERY phase you MUST do three things before anything else: (i) update the phase cursor on disk, (ii) update the target model and phase record (constraint 2), (iii) ASK the operator: "本阶段已完成——继续本会话，还是交接新会话？" If the operator wants a new session, emit a self-contained handoff prompt (constraint 3); if not, continue in this session. Hard stops remain: (a) an approval-gated phase (credential_testing / exploitability / approval_gate), (b) a heavy phase (authenticated_session_review / weak_credential_review / report), or (c) 70% context budget. Never run past a hard stop without explicit operator confirmation.
2. **Phase records must be handoff-complete.** The whole point of stopping early is a fresh session with full reasoning capacity — that only works if the new session can reconstruct target understanding from disk alone. Every phase must leave behind: (a) an updated `notes/target-model.md` — the single evolving snapshot of the target (in-scope host map with roles, tech stack per host, entry points, auth topology, and EVERY attack surface ever considered with its status: open / ruled-out-with-reason / blocked-on-approval — this file is cumulative and never shrinks); (b) a phase note recording what was tested, what was NOT tested and why (the negative space), and evidence cited as `path:line`. Negative results and ruled-out surfaces carry the same weight as findings: omitting them is how the next session misses attack surface. (c) an append-only `notes/operator_tasks.md` recording pending operator actions (token capture, seed records, cleanup of marker data, scope confirmations) with status and what each unlocks; the end-of-phase summary and every handoff prompt must surface the open items.
3. **Handoff prompts are built from disk facts only.** When the operator chooses a new session, emit a prompt that navigates (never summarizes from chat memory): phase_status.json cursor → notes/target-model.md → review_ledger.csv → endpoint inventory → notes/safety-controls.md, plus the next phase name, current priority items, and the standing hard constraints (read-only default, rate limits, approval gates). A new session reading the prompt plus those files must be able to continue with zero knowledge of this conversation.
4. **Read only what the current phase needs.** Do not pre-load all references; open a reference only when the phase calls for it.
5. **Raw artifacts stay on disk.** Responses, HAR, JS, or scan output never enter the conversation — cite `path:line` only.
6. **Tool results are used then cleared.** Do not accumulate tool output in context.
7. **Progress lives on disk, not in memory.** The resume cursor and next step are written out; the next session does not rely on this conversation.
8. **70% context budget: wrap up and recommend handoff.** At 70%, finish the current phase record (constraint 2), write all state to disk, and emit the handoff prompt (constraint 3) with a recommendation to open a new session. Continuing past 70% requires the operator's explicit confirmation after your warning; do not silently continue.
9. **Refuse end-to-end requests.** If the operator asks you to “do the whole assessment in one session” or “complete everything at once”, decline and explain the session-window rule: phases advance under constraint 1 (ask-based handoff at each boundary, records written every phase), and approval-gated or heavy phases always stop. A bulk request does not override the approval gates or the record/handoff obligations — only the operator's per-phase continue/hand-off choices set the session length.

## Session scope (stage gate)

This skill is one stage of a larger engagement. Treat each session as advancing phases under the ask-based handoff policy: read the current contract, do the work, update the status file and target model, then ask the operator continue-or-handoff. References are loaded on demand, not all at once.

# Test One Website from Intake to Closure

Take one authorized website from a supplied target to a defensible final report. Treat automation as
coverage support, not as the conclusion. Keep candidate discovery, validation, evidence, cleanup,
and retest connected in one resumable engagement workspace.

## Load the right references

- Read [references/workflow.md](references/workflow.md) before starting or resuming an engagement.
- Read [references/test-matrix.md](references/test-matrix.md) while planning and recording coverage.
- Read [references/data-to-test-playbook.md](references/data-to-test-playbook.md) when turning routes,
  parameters, schemas, JavaScript, traffic, roles, and workflow states into concrete tests.
- Read [references/artifact-contract.md](references/artifact-contract.md) before auditing or closing.
- Read [references/evidence-reporting.md](references/evidence-reporting.md) when validating findings,
  collecting evidence, assigning severity, or writing the report.

## Accept the supplied target and fix the initial scope

1. Treat the website or domain supplied by the user as the confirmed current target. Do not ask the
   user to prove again that this initial target may be tested. When no separate authorization reference
   is supplied, record the basis as `user_supplied_initial_target`.
2. Record any supplied testing window, exclusions, source IP requirements, rate limits, account rules,
   data-handling rules, and emergency contact without blocking on facts the user did not require.
3. Do not assume that sibling domains,
   discovered subdomains, vendors, CDNs, identity providers, payment providers, or cloud tenants are
   included.
4. Stop active requests when a discovered target is outside the supplied scope, the stated window is
   closed, service health degrades,
   or the next step would exceed the rules of engagement.
5. Set a low-rate, non-disruptive execution profile before any active request. Use conservative
   concurrency, delays, retry limits, timeouts, response-size limits, and backoff; stop immediately
   when the target slows down, errors spike, or normal work could be affected.
6. Automated testing is read-only by default. Before any write or state-changing action, explain the
   action, expected effect, risk, evidence value, and cleanup plan, then wait for the operator's
   explicit approval. This includes create, update, delete, upload, import, export, transaction,
   password/account/session changes, webhook/job creation, command execution, and persistence.
7. Require explicit approval for destructive, persistent, high-volume, credential-spraying,
   data-exporting, command-execution, lateral-movement, social-engineering, or denial-of-service steps.
   Track such branches as `approval_required`; do not erase them from coverage.

## Create a portable engagement workspace

Run the bundled initializer before testing:

```text
python scripts/init_engagement.py <target> --output <work-dir> \
  --allowed-host <host>
```

Use `--resume` only for the same engagement. The initializer performs no network access and creates
the scope, phase-status, review-ledger, evidence, notes, logs, artifact, and report structure described
in the artifact contract.

## Discover the available execution environment

1. Inspect existing repositories, binaries, browser automation, intercepting proxies, DNS/HTTP tools,
   crawlers, API clients, static analyzers, template scanners, and reporting utilities.
2. Record tool names, versions, configuration, request limits, and output paths in the workspace.
3. Prefer mature local tools and native structured output. Do not download a replacement silently.
4. Map tools to capabilities, not brand names. If a tool is unavailable, use an equivalent tool or
   manual method and record the limitation.
5. Read every selected tool's help and active-test settings before use. Disable templates or modules
   that exceed the engagement rules.
6. Configure scanners, crawlers, browsers, and API clients for read-only behavior, low request rates,
   small queues, and stop-on-error/backoff before running them.

## Execute one phase

Do exactly four things, then ask:

1. Read `phase_status.json` (or the run's status file) to find the current phase — the one marked
   `pending` or `in_progress` next in order, or the phase the operator named.
2. Advance that single phase only. Use `references/workflow.md` as the phase dictionary to see what this
   phase covers; do not start any later phase.
3. Update `phase_status.json` with this phase's result, plus the phase note and `notes/target-model.md`
   (handoff-complete, per constraint 2).
4. Tell the operator which phase is next, and ASK: continue in this session, or hand off? If handoff,
   emit the self-contained handoff prompt per constraint 3.

Do not convert a fingerprint, status code, scanner match, response difference, reflected marker, or
version string directly into a finding. Validate the security boundary and demonstrable impact.

For every active test, record the chain `source -> extracted fact -> hypothesis -> payload family ->
expected secure behavior -> observation -> disposition`. Use context-specific canaries and paired
positive/negative controls from the data-to-test playbook; do not spray every payload at every field.

## Maintain two ledgers

Maintain `phase_status.json` for coverage and `review_ledger.csv` for candidates/findings.

Use these phase statuses only:

- `pending`
- `in_progress`
- `complete`
- `blocked`
- `not_applicable`

Give every `not_applicable` or `blocked` phase a specific reason. Use these review statuses only:

- `candidate`
- `needs_manual_validation`
- `approval_required`
- `confirmed`
- `rejected`
- `accepted_risk`
- `fixed`
- `retest_failed`
- `retest_passed`

Never delete an old row to make the engagement look complete. Mark stale rows inactive and retain
their history or source reference.

## Handle authenticated and higher-impact branches

1. Use designated test accounts and the minimum number of roles needed to examine boundaries.
2. Keep secrets in an excluded local session store; never place passwords, cookies, tokens, API keys,
   or sensitive response values in prompts, logs, screenshots, ledgers, or reports.
3. Prefer read-only and reversible checks. Stop after the minimum evidence proves or disproves impact.
4. Treat every automated branch as read-only unless the operator has explicitly approved a named
   write/state-changing action in the current task. Do not infer approval from general authorization.
5. For writes, uploads, transactions, password changes, account creation, data access, code execution,
   internal pivoting, or persistence, confirm the exact allowed action and cleanup requirement first.
6. Record skipped or gated tests so the final report distinguishes “not vulnerable” from “not tested.”

## Validate and close

Run the read-only auditor throughout the engagement:

```text
python scripts/audit_engagement.py <work-dir>
```

Do not close until all required phases are `complete` or justified `not_applicable`, every active
candidate has a disposition, every confirmed finding has a redacted evidence reference, safety controls
and write-approval decisions are recorded, cleanup is recorded, retest status is explicit, and
`reports/final-report.md` exists.

The final response must identify the target and scope, tested and untested areas, confirmed findings,
rejected candidates, unresolved gates, evidence and report paths, cleanup performed, and residual risk.
If a single user action remains, finish all independent work first and request only that action.
