---
name: xcx
description: Advance phases of an authorized mini-program assessment. After each phase, write the cursor and handoff-complete records to disk, then ASK the operator whether to continue in this session or hand off — if handoff, emit a self-contained prompt for the new session. Sessions still hard-stop at approval-gated phases, heavy phases, or 70% context budget. Start from a name, AppID, QR, package, unpacked source, device cache, traffic export, or entry URL, or a specified phase. Use when an AI must push the current phase of a WeChat, Alipay, Douyin, Baidu, Quick App, or other mini-program — not assess it completely in one sitting.
---

## Highest-priority hard constraints (project discipline)

These override every other instruction in this skill. At session start, read only `ROE.md` and `AGENT_MANIFEST.md` plus the contract for the current phase; load references on demand.

1. **Session window: advance until a stop point, ask at every phase boundary.** You may advance multiple lightweight phases in one session (scope → subdomain → alive_probe → fingerprint style), but after EVERY phase you MUST do three things before anything else: (i) update the phase cursor on disk, (ii) update the target model and phase record (constraint 2), (iii) ASK the operator: "本阶段已完成——继续本会话，还是交接新会话？" If the operator wants a new session, emit a self-contained handoff prompt (constraint 3); if not, continue in this session. Hard stops remain: (a) an approval-gated phase (credential_testing / exploitability / approval_gate), (b) a heavy phase (authenticated_session_review / weak_credential_review / report), or (c) the context budget ladder (constraint 8). Never run past a hard stop without explicit operator confirmation.
2. **Phase records must be handoff-complete.** Every phase must leave behind: (a) an updated `notes/target-model.md` — the single evolving snapshot of the target (in-scope host map with roles, tech stack per host, entry points, auth topology, and EVERY attack surface ever considered with its status: open / ruled-out-with-reason / blocked-on-approval — cumulative, never shrinks); (b) a phase note recording what was tested, what was NOT tested and why (the negative space), and evidence cited as `path:line`. Negative results and ruled-out surfaces carry the same weight as findings: omitting them is how the next session misses attack surface. (c) an append-only `notes/operator_tasks.md` recording pending operator actions (token capture, seed records, cleanup of marker data, scope confirmations) with status and what each unlocks; the end-of-phase summary and every handoff prompt must surface the open items.
3. **Handoff prompts are built from disk facts only.** When the operator chooses a new session, emit a prompt that navigates (never summarizes from chat memory): phase_status.json cursor → notes/target-model.md → review_ledger.csv → endpoint/package inventory → notes/safety-controls.md, plus the next phase name, current priority items, and the standing hard constraints. A new session reading the prompt plus those files must be able to continue with zero knowledge of this conversation.
4. **Read only what the current phase needs.** Do not pre-load all references; open a reference only when the phase calls for it.
5. **Raw artifacts stay on disk.** Responses, HAR, JS, or scan output never enter the conversation — cite `path:line` only.
6. **Tool results are used then cleared.** Do not accumulate tool output in context.
7. **Progress lives on disk, not in memory.** The resume cursor and next step are written out; the next session does not rely on this conversation.
8. **Context budget ladder (2026-08-23; replaces the flat 70% rule; absolute tokens so it is window-agnostic).** (a) *Recommend-handoff line* — when context reaches ~120K tokens (heavy-reasoning phases: review verdicts, planning, complex debugging) or ~150K (light script-driven phases: scope/subdomain/alive_probe/fingerprint), finish the current phase record (constraint 2) and recommend handoff at the phase boundary under constraint 1's ask. (b) *Must-wrap line* — at min(200K tokens, 70% of the window), wrap immediately regardless of boundary: write all state to disk and emit the handoff prompt; continuing past it requires the operator's explicit confirmation. On the current 1M-class window these lines sit at ~12-15% and ~20% of the bar.
9. **Refuse end-to-end requests.** If the operator asks you to “do the whole assessment in one session” or “complete everything at once”, decline and explain the session-window rule: phases advance under constraint 1 (ask-based handoff at each boundary, records written every phase), and approval-gated or heavy phases always stop. A bulk request does not override the approval gates or the record/handoff obligations.

## Session scope (stage gate)

This skill is one stage of a larger engagement. Treat each session as advancing phases under the ask-based handoff policy: read the current contract, do the work, update the status file and target model, then ask the operator continue-or-handoff. References are loaded on demand, not all at once.

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
python scripts/init_miniapp_engagement.py <input> --output <work-dir> \
  --platform auto
```

Input may be a name, AppID, QR image, package, package/cache directory, unpacked source, HAR/XML/TXT
traffic export, or entry URL. The initializer performs no network access and creates resumable identity,
material, host, endpoint, phase, ledger, evidence, and report artifacts.

## Discover tools and choose the execution path

**⚠️ 本项目已有成熟的小程序批量解密工具，禁止每次临时写脚本！**

1. **优先使用** `tools/miniapp_extract/extract_encrypted_wxapkg_domains.py`
   - 批量解码：`python tools/miniapp_extract/extract_encrypted_wxapkg_domains.py --root "<缓存根目录>"`
   - 单包解码：`python tools/miniapp_extract/extract_encrypted_wxapkg_domains.py --root "<缓存根目录>/<appid>"`
   - 输出 CSV：URL、API路径、域名、解析状态
   - 详见 `references/package-analysis.md` 第 2.1 节
2. Record tool versions, supported platforms, configuration, output paths, and missing capabilities.
3. Prefer original packages and read-only copies. Hash every supplied material before transformation.
4. Do not download tools, install certificates, modify a device, bypass pinning, repack a client, or
   instrument a process silently. Confirm that the action is permitted and use a designated test device.
5. Configure decoders, crawlers, proxies, device automation, and API clients for read-only behavior,
   low request rates, small queues, and stop-on-error/backoff before running them.
6. Select only the branches relevant to the input and platform, but record every branch as complete,
   blocked, approval required, or not applicable with reason.

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

For each confirmed owned backend, when this phase is a backend assessment phase, apply the same scope,
mapping, testing, validation, evidence, cleanup, and reporting requirements as the website/API process.
Do not make this skill depend on a particular repository or scanner.

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
python scripts/audit_miniapp_engagement.py <work-dir>
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
