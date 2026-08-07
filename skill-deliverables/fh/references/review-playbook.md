# Post-run review playbook

The review goal is to turn workflow output into a defensible set of confirmed findings, rejected candidates,
approval gates, and next actions. Move slowly. Every valuable target needs scope, boundary, evidence, impact,
cleanup, and retest reasoning.

## Target-by-target rule

Use `target_review_queue.csv` as the primary queue. Review targets in ascending `review_order`; do not sample,
do not pick only a few interesting rows, and do not batch-confirm an entire category. Each target has a matching
`target_reviews/<order>_<host>.md` file. Complete that target's scope check, source-file review, category-specific
checks, approval-gate decision, evidence notes, and disposition before moving to the next target.

If the queue is too long for one sitting, preserve the order and record the next `target_id` to resume. A target
can be skipped only by giving it a disposition such as `out_of_scope`, `duplicate`, `blocked`, `needs_login`, or
`approval_required`.

## Status vocabulary

Use these statuses in `target_review_queue.csv`, `review_ledger.csv`, and `findings_ledger.csv`:

- `pending`: not reviewed yet.
- `confirmed`: manually validated with minimized evidence and impact.
- `rejected`: false positive, duplicate, noise, inaccessible, or expected behavior.
- `duplicate`: already covered by a stronger finding.
- `out_of_scope`: asset or action is outside current authorization.
- `needs_login`: requires an authorized account/session handoff.
- `approval_required`: next step is gated by rules or risk.
- `blocked`: missing tool, network, account, scope decision, or environment condition.
- `accepted_risk`: operator accepted it after validation.

## Review rhythm

For each target, record:

```text
target -> source files -> candidate categories -> scope state -> safe read-only check -> observation -> disposition
```

Prefer a complete sequential review of target dossiers over broad re-scanning. When a branch would require active
testing, first decide whether existing artifacts can confirm or reject it.

Any live follow-up must be read-only and low-rate:

- Review one target at a time.
- Use concurrency 1 and at least 3 seconds between requests to the same host.
- Use at most 10 read-only follow-up requests per target unless the operator extends the budget.
- Use GET/HEAD/schema checks or browser observation only.
- Stop on slowness, error spikes, CAPTCHA, lockout, rate limits, or normal-user impact.

Any write, upload, delete, import, export, transaction, account/session/password change, command execution,
callback payload, exploit template, or persistence must be explained and explicitly approved before execution.

## Health review

Start with `run_health` and `run_summary`.

Check:

- Probe coverage and success ratio. Low probe success may mean network/VPN/DNS failure, not secure targets.
- Verified versus false-positive counts. High false positives mean fixed-path detections need manual truth checks.
- Missing tools. Do not mark branches as covered when a required tool was absent.
- Rate-limit skips and repeated-error backoff. Revisit only with lower rate or after fixing environment.
- Empty files. Empty candidate files are a result, but empty probe or discovery output may indicate failure.
- Parallel batches. Compare all sibling `b001/b002/b003` summaries before drawing project-wide conclusions.

## Scope review

Before any follow-up request:

1. Confirm the target exists in `targets.csv` or `targets.json`.
2. Check `new_assets_pending_apply.txt`, `subdomains_for_scope_confirmation.txt`,
   `authenticated_new_assets_pending.txt`, `miniapp_source_new_assets_pending.txt`, and
   `wechat_pending_extra_assets.txt`.
3. Classify every new host as `in_scope`, `confirmation_required`, `third_party`, `platform_shared`, `out_of_scope`,
   or `invalid`.
4. Do not actively test `confirmation_required`, third-party, platform/shared, or supply-chain assets.

## Priority candidates

Review `04_可报告候选_TOP.*`, `priority_targets.json`, and `reports/priority_review.md` first.

For each item:

- Prefer reasons starting with `verified_`, `api_endpoint_json_confirmed`, `openapi_json_with_paths`,
  `source_map_reference`, `js_sensitive_keyword`, `authenticated_*`, or `xss_reflection_*`.
- Treat score as ordering only. It is not severity and not confirmation.
- Cross-check source files: `verified_exposures`, `impact_candidates`, `api_candidates`, `manual_auth_queue`,
  and `xss_reflection_checks`.
- Merge duplicates by host, URL/path, vulnerability class, and same security boundary.
- Reject fixed-path hits when the response is a generic 404/403/login page, CDN block page, WAF page, or unrelated title.

## API and business logic

Use `02_业务API只读复核队列.*`, `api_candidates.jsonl`, `api_interesting.jsonl`, `api_confirmed.jsonl`,
`authenticated_api_results.jsonl`, and `authenticated_impact_candidates.jsonl`.

Safe checks:

- Inspect methods, paths, parameter names, JSON field names, status codes, content type, length, and schema shape.
- Confirm whether an endpoint is documentation, mock data, unauthenticated metadata, or real business data.
- Compare anonymous versus authenticated behavior only with operator-supplied sessions.
- Use counts, field names, and hashes instead of storing values.

Approval-required:

- Export, download, delete, upload, submit, approve, SMS, password, account, order, payment, refund, import, or job endpoints.
- Bulk enumeration, tenant switching, or object access involving real third-party records.

## Login and authenticated review

Use `01_需要你登录拿Cookie.*`, `manual_auth_queue.*`, and `auth_sessions.template.json`.

Rules:

- The operator logs in manually where authorized.
- Raw cookies, Authorization headers, passwords, and tokens stay in local-only session files.
- Do not paste secrets into prompts, reports, screenshots, ledgers, or shared artifacts.
- Authenticated follow-up stays read-only and same-host unless new assets are separately confirmed.
- Register accounts only when explicitly allowed. Never change passwords or business data.

## Weak credentials

Use `03_弱口令人工确认队列_不自动跑.*` and `weak_credential_manifest.json`.

Review order:

1. Confirm the host is in scope and the rules allow weak-credential checks.
2. Check CAPTCHA, lockout, warning prompts, MFA, and account-safety signals.
3. If approved, use the smallest product-aware common-pair set and stop on CAPTCHA, rate limit, warning, lockout, or first success.
4. Record only metadata: target, product, account type, result, timestamp, screenshot, and redacted proof.

Do not run credential spraying, brute force, broad password lists, or repeated attempts.

## Product vulnerability candidates

Use `04B_产品漏洞候选队列.*`, `product_triage_summary.json`, `product_vuln_candidate_queue.csv`, and
`product_vuln_candidates.jsonl`.

Safe evidence:

- Version banners, dependency disclosure, documentation paths, error pages, JS package names, response headers,
  product-specific static pages, and vendor advisories.
- Known affected version plus reachable product surface may justify a candidate, but confirm exploitability only when rules allow.

Approval-required:

- Fastjson/Log4j/Struts2 callbacks, deserialization payloads, RCE checks, JNDI, DNSLog, memory shells, upload-based checks,
  and product exploit templates.

## SQL injection

Review `sqli_high_probability.*` first, then `sqli_candidates.jsonl`, then `sqli_500_or_error_anomalies.txt`.

Manual confirmation:

- Compare baseline, baseline repeat, quote probe, boolean true, and boolean false.
- Stronger evidence needs stable boolean difference, DB error signatures, or consistent parameter-bound behavior.
- 403, WAF block pages, 500, status changes, and content-length changes alone are not enough.

Approval-required:

- SQLMap, time-based tests, union select, stacked queries, data extraction, database fingerprinting beyond minimal proof,
  and any write or dump.

## XSS

Use `04C_XSS反射候选队列.*`, `xss_candidates.jsonl`, `xss_reflection_checks.jsonl`,
`xss_reflection_candidates.txt`, and `xss_manual_review.md`.

Manual confirmation:

- Confirm the marker appears in an executable browser context, not just source text, JSON, a blocked page, or escaped HTML.
- Capture DOM context, parameter, browser URL, timestamp, and redacted screenshot.
- Prefer inert markers and browser inspection. Do not submit stored payloads or affect other users without approval.

## Shiro

Use `12_Shiro候选判断.md`, `shiro_manual_queue.csv`, `shiro_triage_results.jsonl`, and `shiro_detected.txt`.

Safe review:

- Check rememberMe cookie behavior, product clues, Java/OA/login context, and response differences.
- Manual tool validation must be single-target and approved. Do not run broad ShiroAttack2 scans.

## Upload, file handling, and exposures

Use `09_文件上传安全测试.md`, `candidate_exposures`, `verified_exposures`, and upload/file-related API rows.

Safe review:

- Identify upload endpoints, accepted file metadata, public retrieval path, auth requirement, and cleanup requirement.
- Do not upload, overwrite, delete, or retrieve sensitive files without approval.
- For exposed configs, logs, heap dumps, source maps, Swagger, Druid, Actuator, phpinfo, ELMAH, Tomcat manager, and similar,
  prove access with minimal metadata and screenshots. Do not download large files or secrets.

## Authorization and IDOR

Use `10_越权和接口泄露复核.md`, API queues, authenticated candidates, and JS-discovered object/tenant parameters.

Safe review:

- Build a small matrix: anonymous, own test user, second authorized test user, low role, admin role if provided.
- Test only disposable or operator-provided objects.
- Record expected secure behavior before observing.

Approval-required:

- Accessing real third-party records, bulk enumeration, exports, destructive actions, or state transitions.

## Mini-program outputs

For `wxapkg_extract`, miniapp analysis folders, or `wechat_*` outputs:

1. Read `summary.json` and package parse summaries.
2. Separate code noise from real domains and URLs.
3. Classify hosts before testing.
4. Convert real in-scope hosts and API paths into `$xcx` or `$wz` workflows.
5. If extraction is strings-only, record static-coverage limitations.

## Evidence and reporting

Use `reports/screenshot_queue.md`, `evidence/screenshots/README_截图说明.md`, `reports/evidence_index.md`,
`reports/daily_report_draft.md`, and `reports/platform_submission_template.json`.

For each confirmed finding, include:

- Target, URL/path, affected parameter or function, account/role used, and scope basis.
- Minimal reproduction steps and expected/actual behavior.
- Impact stated from demonstrated evidence, not scanner language.
- Screenshot/video timestamp with current date/time visible where required.
- Redacted evidence path and hash.
- Cleanup performed or why none was needed.
- Retest result or retest blocker.

Do not report candidates that remain `pending`, `needs_login`, `approval_required`, `blocked`, or `out_of_scope`.
