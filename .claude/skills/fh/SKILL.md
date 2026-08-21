---
name: fh
description: Review and close the outputs produced by the authorized one-click web assessment workflows in D:\PythonSource\PythonProjects\PythonProject4\runs after running 一键完整流程_含弱口令.bat or 一键已有子域名后流程_含弱口令.bat. Use when an AI must extract every valuable target from run_summary, run_health, 00_重要_人工复核入口 queues, weak-credential queues, API/product/SQLi/XSS/Shiro candidates, mini-program extraction outputs, evidence queues, approval gates, and final report material, then review targets one by one without sampling or rerunning unsafe active tests.
---

## Highest-priority hard constraints (project discipline)

These override every other instruction in this skill. At session start, read only `ROE.md` and `AGENT_MANIFEST.md` plus the contract for the current phase; load references on demand.

1. **One session, one batch.** Review one batch of targets, then stop and record where you stopped. Do not try to clear the entire queue in one sitting.
2. **Read only what the current phase needs.** Do not pre-load all references; open a reference only when the phase calls for it.
3. **Raw artifacts stay on disk.** Responses, HAR, JS, or scan output never enter the conversation — cite `path:line` only.
4. **Tool results are used then cleared.** Do not accumulate tool output in context.
5. **Progress lives on disk, not in memory.** The resume cursor and next step are written out; the next session does not rely on this conversation.
6. **Stop at 70% context budget.** Wrap up, write state to disk, and tell the operator to open a new session.

# Review One-Click Workflow Outputs

Use this skill after the operator has run one of these local workflows:

- `D:\Desktop\一键完整流程_含弱口令.bat`
- `D:\Desktop\一键已有子域名后流程_含弱口令.bat`

The normal output root is `D:\PythonSource\PythonProjects\PythonProject4\runs`.

This skill is for post-run review, not for new exploitation. Work from existing artifacts first. Do not
claim a vulnerability because a scanner, fingerprint, fixed path, status code, reflection marker, or queue
row exists. The primary workflow is target-by-target review: extract all valuable targets from the output
directory, then review them in order. Do not sample a few targets and do not batch-confirm a whole queue.

## Load the right references

- Read [references/output-map.md](references/output-map.md) before interpreting run files.
- Read [references/review-playbook.md](references/review-playbook.md) before confirming, rejecting, or reporting candidates.

## Create a review workspace

Run the initializer before detailed review:

```text
python scripts/init_postrun_review.py
```

By default it selects the newest non-empty run under `D:\PythonSource\PythonProjects\PythonProject4\runs`.
When the selected run is a parallel batch such as `*_b001`, it includes sibling batches from the same
parallel launch. To review a specific run or runs root:

```text
python scripts/init_postrun_review.py <run-dir-or-runs-root>
```

The script performs no network access. It creates a review workspace containing:

- `review_plan.md`: ordered review plan and health summary.
- `target_review_queue.csv`: every extracted valuable target, sorted for one-by-one review.
- `target_review_index.md`: markdown index of the target queue.
- `target_reviews/`: one detailed review page per target.
- `review_ledger.csv`: source files to review, counts, safe default, approval gate, and status.
- `findings_ledger.csv`: reportable-finding template.
- `approval_gates.md`: actions that must not run without explicit operator approval.
- `run_inventory.json`: detected run directories, manual hubs, and key source files.

When the same output directory is reused, the initializer refreshes only its generated review files and
`target_reviews/` dossier directory so stale targets do not remain in the queue. Use a new `--output` path if
manual notes in a previous review workspace must be preserved.

If the operator gives a run path directly, review that path. If they only say "latest", use the script
default. Do not ask for an output directory unless they want one; the script chooses a default.

## Review in this order

1. Open `review_plan.md`, `target_review_queue.csv`, `target_review_index.md`, `run_health.json` or
   `reports/run_health.md`, and `run_summary.json`.
2. Check target count, valuable-target count, probe success, missing tools, repeated-error backoff, failed
   stages, and empty outputs.
3. Review in batches instead of all at once. Each session reviews one batch (5-10 contiguous targets by
   `review_order`); write each verdict to `verdicts/<review_order>.json`; the completed batch is the resume
   cursor. If the queue is longer than one sitting, stop at a specific `target_id` and record the next target
   to resume. (Batch files that self-contain the verdict schema are produced by `fh_review_dispatch.py` once
   W6 lands; until then, pick a contiguous `review_order` range and stop where you stopped.)
4. For each target, open its matching `target_reviews/<order>_<host>.md` and complete that target's checklist:
   scope, source files, category-specific signals, safe read-only plan, approval gates, evidence, disposition,
   cleanup, and retest notes.
5. Confirm scope using `targets.csv`, `targets.json`, `new_assets_pending_apply.txt`,
   `subdomains_for_scope_confirmation.txt`, and mini-program backend pending lists.
6. Start with `00_重要_人工复核入口/README_先看这里.md` when present, but use it as evidence for the current
   target rather than as a replacement for target-by-target review.
7. Review priority/reportable candidates first:
   `04_可报告候选_TOP.*`, `reports/priority_review.md`, `priority_targets.json`,
   `verified_exposures.*`, `impact_candidates.jsonl`, and `candidate_exposures.jsonl`.
8. Review authentication and business API queues:
   `01_需要你登录拿Cookie.*`, `02_业务API只读复核队列.*`, `manual_auth_queue.*`,
   `api_candidates.jsonl`, `api_interesting.jsonl`, `api_confirmed.jsonl`,
   `authenticated_api_results.jsonl`, and `authenticated_impact_candidates.jsonl`.
9. Review gated security branches:
   weak credentials, product-specific vulnerabilities, SQL injection, XSS, Shiro, upload/file handling,
   authorization/IDOR, and mini-program backend candidates.
10. Build reportable evidence only after manual validation. Use screenshots, timestamps, minimal requests,
   response metadata, hashes, field names, and redacted snippets. Do not store passwords, cookies, tokens,
   personal data, business records, or downloaded sensitive files.
11. Update `target_review_queue.csv` and `findings_ledger.csv` with `confirmed`, `rejected`, `duplicate`,
    `out_of_scope`, `needs_login`,
   `approval_required`, `blocked`, or `accepted_risk`.
12. Finish with `reports/daily_report_draft.md`, `reports/evidence_index.md`,
    `reports/screenshot_queue.md`, and `reports/platform_submission_template.json` when present.

## Rate and automation controls

The initializer performs no network access. During review, automatic work is offline/read-only by default.
If a live read-only confirmation is necessary, review one target at a time with this profile:

- Concurrency: 1 target and 1 request stream.
- Delay: at least 3 seconds between requests to the same host.
- Budget: at most 10 read-only follow-up requests per target unless the operator explicitly extends it.
- Methods: GET/HEAD/schema or browser observation only; avoid bodies and state-changing endpoints.
- Stop immediately on service slowness, error spikes, CAPTCHA, lockout warnings, rate limits, or normal-user impact.

Before any write or state-changing action, explain the exact action, expected effect, risk, evidence value,
and cleanup plan, then wait for the operator's explicit approval.

## Approval gates

Keep these as approval-required, never automatic:

- Weak-password attempts, brute force, credential spraying, account lockout-sensitive checks, and login attempts
  beyond explicitly approved low-volume manual checks.
- SQLMap, time-based SQLi, union/data extraction, stacked queries, database access, and any data dump.
- RCE, deserialization, Log4j/JNDI/callback payloads, Shiro rememberMe exploitation, webshells, tunnels,
  persistence, command execution, and post-exploitation.
- Uploads, deletes, imports, exports, transactions, password/account/session changes, and workflow approvals.
- Active testing of new domains, subdomains, mini-program backends, third-party services, supply-chain paths,
  or platform/shared services before ownership and scope are confirmed.

When a candidate needs one of these actions, record the exact action, target, reason, expected evidence,
risk, and cleanup plan in `approval_gates.md` or `review_ledger.csv`, then wait for explicit operator approval.

## Closure criteria

Do not close until:

- Run health and stage failures are understood.
- All pending/new assets are either in scope, out of scope, third party, platform/shared, or blocked with a reason.
- Every row in `target_review_queue.csv` has a disposition or an explicit blocker.
- Every non-empty manual queue has a disposition through the relevant target review.
- Every confirmed finding has minimized redacted evidence, video/screenshot time reference where required,
  cleanup state, and retest or retest limitation.
- Every weak credential, SQLi, XSS, Shiro, product-vulnerability, upload, authenticated, or mini-program branch
  is either safely reviewed, rejected, blocked, or approval-required.
- The final daily/report draft includes only manually verified findings and explicitly lists residual risk.

The final response must summarize reviewed run directories, run health, top candidates, confirmed findings,
rejected false positives, approval gates, new-scope blockers, evidence/report paths, and next actions.
