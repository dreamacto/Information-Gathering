---
name: fh
description: Review and close the outputs produced by the authorized one-click web assessment workflows in D:\PythonSource\PythonProjects\PythonProject4\runs after running 一键完整流程_含弱口令.bat, 一键已有子域名后流程_含弱口令.bat, or 一键保守全流程_尽量多信息_避WAF.bat. Use when an AI must extract every valuable target from run_summary, run_health, P0-P3 candidate confidence, target dossiers, fingerprint deepening queues, 00_重要_人工复核入口 queues, weak-credential queues, API/product/SQLi/XSS/Shiro candidates, mini-program extraction outputs, evidence queues, approval gates, and final report material, then review targets one by one without sampling or rerunning unsafe active tests.
---

## Highest-priority hard constraints (project discipline)

These override every other instruction in this skill. At session start, read only `ROE.md` and `AGENT_MANIFEST.md` plus the contract for the current phase; load references on demand.

0. **规则优先级**：所有规则的适用顺序以 `docs/RULE_PRECEDENCE.md` 为唯一事实源（与 `contracts/rule_precedence.json` 由测试强制同步）；规则冲突不得静默选择，必须记入 `context_conflicts` 并回读更高级别源。

1. **One batch per review unit, ask at every batch boundary.** Review one batch of targets, write all verdicts and the resume cursor to disk, then ASK the operator: "本批次已完成——继续本会话审下一批，还是交接新会话？" If handoff, emit a self-contained handoff prompt that navigates the next session to run_dir/postrun_review/ (batch files, verdicts, queue, TOP) — never summarize from chat memory. If continue, proceed with the next batch. Do not try to clear the entire queue without the operator's per-batch choices.
2. **Read only what the current phase needs.** Do not pre-load all references; open a reference only when the phase calls for it.
3. **Raw artifacts stay on disk.** Responses, HAR, JS, or scan output never enter the conversation — cite `path:line` only.
4. **Tool results are used then cleared.** Do not accumulate tool output in context.
5. **Progress lives on disk, not in memory.** The resume cursor and next step are written out; the next session does not rely on this conversation.
6. **Context budget ladder (2026-08-23; absolute tokens).** Recommend handoff after the current batch when context reaches ~120K tokens (~12% of a 1M-class window); must wrap at min(200K tokens, 70% of window): write verdicts and resume cursor to disk, emit the handoff prompt. Continuing past the must-wrap line requires the operator's explicit confirmation; do not silently continue.

# fh: One-Click Workflow Post-Run Review

Use this skill after the operator has run one of these local workflows:

- `D:\Desktop\一键完整流程_含弱口令.bat`
- `D:\Desktop\一键已有子域名后流程_含弱口令.bat`
- `D:\Desktop\一键保守全流程_尽量多信息_避WAF.bat`

The normal output root is:

```text
D:\PythonSource\PythonProjects\PythonProject4\runs
```

This skill is for post-run review, not for new exploitation. Work from existing artifacts first. Do not claim a vulnerability because a scanner, fingerprint, fixed path, status code, reflection marker, P0/P1 label, or queue row exists. The primary workflow is target-by-target review: extract all valuable targets from the output directory, then review them in order. Do not sample a few targets and do not batch-confirm a whole queue.

## Core Rules

- Use Chinese when reporting back to the operator.
- Treat P0/P1/P2/P3 as review priority only, not vulnerability severity and not confirmation.
- Distinguish clearly between `自动候选`, `二次复测稳定`, `人工已确认`, `误报/拒绝`, `需要登录`, `需要审批`, and `超出范围`.
- Never output raw Cookie, Token, Authorization, password, session, ID card, phone number, patient name, business record value, or downloaded sensitive content.
- When sensitive fields appear, describe field names and evidence type only; remind the operator to redact values.
- Do not suggest or run batch exploitation, brute force, SQLMap, key cracking, RCE payloads, callback payloads, uploads, deletes, exports, downloads, account changes, password changes, persistence, tunnels, webshells, or post-exploitation.
- If live follow-up is necessary, use one target at a time, concurrency 1, at least 3 seconds between requests to the same host, and at most 10 read-only follow-up requests per target unless the operator extends the budget.
- Stop on service slowness, error spikes, CAPTCHA, account lockout warnings, rate limits, or normal-user impact.

## AI 结论模板（实施规格 §11，结论呈现层词表；判定落盘词表另见 contracts/workflow_schema.json 的 review_statuses）

任何漏洞判断必须先按本模板组织，再写其它内容。只有全部成立门满足时才能使用 confirmed：

```text
对象类型：signal | candidate | confirmed | inconclusive
授权状态：confirmed | confirmation_required | blocked
可触达性：reachable | unverified | unreachable
复现状态：reproducible | partial | not_reproduced
影响类别：none | low | medium | high | critical
影响对象：用户/租户/业务对象/权限/数据/网络边界/服务可用性
证据完整性：complete | partial | missing
结论：
下一步：
```

四问否决规则（任一回答"否"，不得称 confirmed）：

1. 是否有明确的授权资产和允许的测试动作？
2. 是否有真实可触达的端点、功能或数据流？
3. 是否有可重复的异常行为或越权结果？
4. 是否能说明对企业造成了非琐碎的安全影响并提供证据？

细微发现处置（以下统一为 signal 或 candidate，必须写清"为什么不升级为漏洞：缺少哪一项成立门"）：
Banner/版本/框架名、robots/sitemap/OpenAPI 文档存在、目录文件名猜测命中、500/异常堆栈但无敏感信息、
反射但未执行、前端隐藏功能、代码中的 eval/模板语法/XML parser/危险 sink、JWT 可解码、响应中内部
主机名但不可访问、单次超时或 403、用户访问自己的对象、无敏感数据的字段过多、无法证明有效性的疑似密钥。

漏洞成立最小链条（中间只有"推测"时状态不得超过 candidate）：

```text
入口/资产 → 攻击者可控输入或低权限身份 → 服务端缺陷/边界缺失 → 可复现结果 → 对企业的具体影响 → 最小必要证据
```

## First Files To Read

If the operator gives a specific run directory, use it. If they say "latest", choose the newest non-empty run under `runs`. If a selected run is a parallel batch such as `*_b001`, include sibling batches from the same timestamp and label.

Read these first when present:

1. `run_summary.json`
2. `run_health.json` or `reports/run_health.md`
3. `00_重要_人工复核入口/README_先看这里.md`
4. `00_重要_人工复核入口/00_P0-P3候选总表.md`
5. `candidate_confidence.csv` or `candidate_confidence.jsonl`
6. `target_dossiers/index.md`
7. `reports/second_pass_review.md`
8. `reports/candidate_confidence.md`
9. `reports/priority_review.md`
10. `reports/screenshot_queue.md`
11. `reports/daily_report_draft.md`
12. `reports/evidence_index.md`
13. `reports/fingerprint_deepening.md`

Then read relevant source files based on the candidates found:

- Priority/exposures: `priority_targets.json`, `verified_exposures.jsonl`, `candidate_exposures.jsonl`, `false_positive_exposures.jsonl`
- API/JS: `api_discovery.jsonl`, `api_candidates.jsonl`, `api_interesting.jsonl`, `api_confirmed.jsonl`, `impact_candidates.jsonl`
- Authenticated review: `manual_auth_queue.*`, `authenticated_api_results.jsonl`, `authenticated_impact_candidates.jsonl`, `authenticated_new_assets_pending.txt`
- Second pass: `second_pass_manifest.json`, `second_pass_results.jsonl`, `second_pass_confirmed.jsonl`
- Fingerprint deepening: `fingerprint_deepening_plan.jsonl`, `fingerprint_deepening_safe_queue.csv`, `fingerprint_deepening_approval_queue.csv`, `fingerprint_tool_command_queue.csv`, `fingerprint_tool_matrix.json`, `fingerprint_deepening_manifest.json`
- Weak credentials: `weak_credential_manifest.json`, `weak_credential_attempts.jsonl`, `weak_credential_successes.jsonl`, `weak_credential_skips.jsonl`
- Product-specific: `product_triage_summary.json`, `product_triage_queue.csv`, `product_vuln_candidate_queue.csv`, `product_vuln_candidates.jsonl`, `reports/product_vuln_candidate_queue.md`
- SQLi: `sqli_high_probability.*`, `sqli_candidates.jsonl`, `sqli_500_or_error_anomalies.txt`, `sqli_triage_manifest.json`
- XSS: `xss_candidates.jsonl`, `xss_reflection_checks.jsonl`, `xss_reflection_candidates.txt`, `xss_manual_review.md`
- Shiro: `shiro_candidates.jsonl`, `shiro_manual_queue.csv`, `shiro_triage_results.jsonl`, `shiro_detected.txt`
- Mini-program: `wechat_*`, `miniapp_source_*`, `burp_miniapp_*`, `wxapkg_*`, package `summary.json` files

## Optional Review Workspace

If available, run the offline initializer before detailed review:

```text
python scripts/init_postrun_review.py
```

It selects the newest non-empty run by default and performs no network access. For a specific run or runs root:

```text
python scripts/init_postrun_review.py <run-dir-or-runs-root>
```

Expected generated files:

- `review_plan.md`: ordered review plan and health summary
- `target_review_queue.csv`: every extracted valuable target, sorted for one-by-one review
- `target_review_index.md`: markdown index of the target queue
- `target_reviews/`: one detailed review page per target
- `review_ledger.csv`: source files to review, counts, safe default, approval gate, and status
- `findings_ledger.csv`: reportable-finding template
- `approval_gates.md`: actions that must not run without explicit operator approval
- `run_inventory.json`: detected run directories, manual hubs, and key source files

If this initializer does not yet understand newer outputs, still read `candidate_confidence.*`, `target_dossiers/`, and `second_pass_*` manually and merge them into the review.

## Output Map

Not every run has every file. Empty files are still useful because they prove that a branch ran and produced no candidates.

### Manual Hub

When present, start with `00_重要_人工复核入口/README_先看这里.md`, but use it as evidence for the current target rather than as a replacement for target-by-target review.

| Hub file | Purpose |
|---|---|
| `00_P0-P3候选总表.*` | Offline merged candidate confidence queue. Priority only, not proof |
| `00B_目标画像索引.*` | Index of host dossiers generated from all candidate families |
| `01_需要你登录拿Cookie.*` | Login/session handoff queue. Cookies stay local-only |
| `02_业务API只读复核队列.*` | Business/API schema candidates for read-only review |
| `03_弱口令人工确认队列_不自动跑.*` | Weak-credential candidates; manual gate only |
| `04_可报告候选_TOP.*` | Highest-priority reportable-candidate queue |
| `04B_产品漏洞候选队列.*` | Product/framework vulnerability candidates, usually queue-only |
| `04C_XSS反射候选队列.*` | Reflected-marker XSS candidates, not confirmed executable XSS |
| `04D_指纹后深入分支.*` | Product/framework follow-up routes, local tool/template candidates, and approval gates |
| `05_认证态复核命令.md` | How to continue authenticated read-only review after operator session handoff |
| `06_弱口令显式复核命令.md` | Explicit weak-credential command guidance; never default |
| `07_小程序人工搜索与Burp导入.md` | Mini-program search, source, and Burp-import follow-up |
| `08_SQL注入手工确认.md` | SQLi manual confirmation rules |
| `09_文件上传安全测试.md` | Upload/file handling gates |
| `10_越权和接口泄露复核.md` | Authz/IDOR/API leakage review |
| `11_Fastjson_Log4j_Struts2候选判断.md` | Product-vuln candidate triage |
| `12_Shiro候选判断.md` | Shiro candidate triage |
| `13_XSS候选手工确认.md` | XSS manual confirmation |

### New Priority Artifacts

| File | Meaning | How to use |
|---|---|---|
| `candidate_confidence.csv/jsonl` | P0-P3 merged candidates from API, SQLi, XSS, product, weak credential, auth, exposure, and second-pass sources | Sort by priority, then manually review target by target |
| `reports/candidate_confidence.md` | Human-readable summary of the merged queue | Use for quick overview and counts |
| `target_dossiers/index.md` | Host-level dossier index | Open hosts with P0/P1 or high candidate counts first |
| `target_dossiers/<host>.md` | Per-host context: target rows, top candidates, fingerprint, API, second-pass, weak credential notes | Use as the working page for that host |
| `second_pass_manifest.json` | Counts and limits for second-pass triage | Confirm whether SQLi/XSS/API retesting ran |
| `second_pass_results.jsonl` | All second-pass results | Use `stable=true` as higher review priority only |
| `second_pass_confirmed.jsonl` | Candidates that stayed stable under the second lightweight check | Prioritize, but still manually confirm before reporting |
| `reports/second_pass_review.md` | Human-readable second-pass summary | Use before raw JSONL if time is short |
| `fingerprint_deepening_plan.jsonl` | Product/framework follow-up route for each fingerprint | Use to decide what to review next after a product/framework is identified |
| `fingerprint_deepening_safe_queue.csv` | Safe offline/read-only next checks | Prefer this before any command preview |
| `fingerprint_deepening_approval_queue.csv` | Actions/templates requiring explicit approval | Do not execute; record as approval gate |
| `fingerprint_tool_command_queue.csv` | Manual command previews for selected read-only templates | Review template and target first; never run full-scope by default |
| `fingerprint_tool_matrix.json` | Local tool inventory and external import candidates | Use for tool availability and audit trail |

## Run-Level Aggregation Order (spec 8.3)

Before per-target review begins, verify the run-level gates in this fixed order; a failing
earlier gate blocks later interpretations:

```text
run_quality_gate
scope_reconciliation
candidate_deduplication
source_coverage_check
authentication_queue_review
authorization_queue_review
injection_queue_review
ssrf_queue_review
product_queue_review
miniapp_queue_review
evidence_gate
report_lifecycle
cleanup_audit
```

- An `INCONCLUSIVE` run quality gate must not produce a negative (all-clear) conclusion.
- Fixed-path signals never enter the main vulnerability queue.
- A `confirmed` finding without evidence is automatically demoted to `needs_manual_validation`.
- Duplicate candidates merge into one finding, keeping the first-seen and last-validated timestamps.
- The same phenomenon appearing in multiple runs never raises severity by itself; only proven
  impact, permission boundary, or business outcome does.

## Review Order

1. Open `run_summary.json`, `run_health`, `00_重要_人工复核入口/README_先看这里.md`, `candidate_confidence.*`, and `target_dossiers/index.md`.
2. Check target count, valuable-target count, probe success, missing tools, repeated-error backoff, failed stages, empty outputs, P0/P1/P2/P3 counts, and second-pass stable counts.
3. Review P0/P1 targets first, but still use target-by-target discipline. Do not convert P0/P1 into confirmed findings without manual validation.
4. Review in batches instead of all at once. Each session reviews one batch (5-10 contiguous targets by `review_order`); write each verdict to `verdicts/<review_order>.json`; the completed batch is the resume cursor. If the queue is longer than one sitting, stop at a specific `target_id` and record the next target to resume. Batch files that self-contain the verdict schema are produced by `fh_review_dispatch.py --prepare` (W6, now live). Review exactly ONE batch file per session and write verdicts to `verdicts/<review_order>.json`. If no review workspace exists, build a working queue from `candidate_confidence.csv` and `target_dossiers/index.md` first.
5. For each target, open its matching target dossier or generated `target_reviews/<order>_<host>.md` and complete: scope, source files, category-specific signals, safe read-only plan, approval gates, evidence, disposition, cleanup, and retest notes.
6. Confirm scope using `targets.csv`, `targets.json`, `new_assets_pending_apply.txt`, `subdomains_for_scope_confirmation.txt`, `authenticated_new_assets_pending.txt`, `miniapp_source_new_assets_pending.txt`, and `wechat_pending_extra_assets.txt`.
7. Review priority/reportable candidates: `04_可报告候选_TOP.*`, `reports/priority_review.md`, `priority_targets.json`, `verified_exposures.*`, `impact_candidates.jsonl`, and `candidate_exposures.jsonl`.
8. Review fingerprint deepening queues: `04D_指纹后深入分支.*`, `reports/fingerprint_deepening.md`, safe queue, approval queue, and command-preview queue.
9. Review authentication and business API queues: `01_需要你登录拿Cookie.*`, `02_业务API只读复核队列.*`, `manual_auth_queue.*`, `api_candidates.jsonl`, `api_interesting.jsonl`, `api_confirmed.jsonl`, `authenticated_api_results.jsonl`, and `authenticated_impact_candidates.jsonl`.
10. Review gated security branches: weak credentials, product-specific vulnerabilities, SQL injection, XSS, Shiro, upload/file handling, authorization/IDOR, and mini-program backend candidates.
11. Build reportable evidence only after manual validation. Use screenshots, timestamps, minimal requests, response metadata, hashes, field names, and redacted snippets.
12. Update review ledgers or working notes with one of these statuses: `pending`, `confirmed`, `rejected`, `duplicate`, `out_of_scope`, `needs_login`, `approval_required`, `blocked`, or `accepted_risk`.
13. Finish with `reports/daily_report_draft.md`, `reports/evidence_index.md`, `reports/screenshot_queue.md`, and `reports/platform_submission_template.json` when present.

## Per-Target Review Template

For each target or host, record:

```text
target -> source files -> candidate categories -> scope state -> safe read-only check -> observation -> disposition
```

Use this structure in the response or notes:

```markdown
### <host>

- 入口/指纹:
- 最高优先级候选:
- API/业务字段:
- SQLi/XSS/Shiro/产品候选:
- 弱口令/登录态线索:
- 作用域状态:
- 证据缺口:
- 建议手工复核:
- 当前处置: pending / confirmed / rejected / needs_login / approval_required / blocked / out_of_scope
```

If the queue is too long for one sitting, preserve the order and record the next `target_id` or host to resume.

## Candidate Interpretation

### P0-P3 Candidate Confidence

- P0: review immediately; often includes second-pass-stable, weak-credential success candidates, strong exposure evidence, or high-value authenticated/API signals.
- P1: high-value manual review; likely business API, medium/high confidence XSS/SQLi, product-vulnerability candidate, or login/auth boundary signal.
- P2: useful lead; review after P0/P1 or when the same host already has stronger signals.
- P3: low-confidence, manual-only, noisy, or context-dependent lead.

Do not use P0/P1/P2/P3 as severity. Severity must be assigned only after manual validation and demonstrated impact.

### Second-Pass Results

- `second_pass_confirmed.jsonl` means the same low-risk check stayed stable; prioritize it.
- SQLi second pass repeats tiny differential GET probes; it does not enumerate databases or dump data.
- XSS second pass uses one new inert marker; it does not prove executable XSS.
- API second pass stores status, length, hash, and schema metadata only.
- Stable second-pass signals are stronger candidates, not confirmed vulnerabilities.

### Fingerprint Deepening

- `04D_指纹后深入分支` and `fingerprint_deepening_plan.jsonl` answer what to review after a product/framework is identified.
- Safe queue means offline/read-only/manual review first: product page, version clues, response metadata, public schema, field names, status, and hashes.
- Approval queue means the next action may involve active templates, credentials, sensitive files/data, state changes, callback checks, or command execution. Do not run it automatically.
- Command previews are convenience notes only. Review the template, target scope, rate, and approval state before using any command.
- Tool inventory is not a recommendation to download or run everything. Newly imported active tools need operator approval and audit.

## Category Playbooks

### Health and Scope

Check:

- Probe coverage and success ratio. Low success may mean network/VPN/DNS failure, not secure targets.
- Verified versus false-positive counts. High false positives mean fixed-path detections need manual truth checks.
- Missing tools. Do not mark branches as covered when a required tool was absent.
- Rate-limit skips and repeated-error backoff. Revisit only with lower rate or after fixing environment.
- Empty files. Empty candidate files are a result, but empty probe or discovery output may indicate failure.
- Parallel batches. Compare all sibling `b001/b002/b003` summaries before drawing project-wide conclusions.

Before any follow-up request, classify every new host as `in_scope`, `confirmation_required`, `third_party`, `platform_shared`, `out_of_scope`, or `invalid`. Do not actively test `confirmation_required`, third-party, platform/shared, or supply-chain assets.

### API and Business Logic

Use `02_业务API只读复核队列.*`, `candidate_confidence.*`, `target_dossiers/*`, `api_candidates.jsonl`, `api_interesting.jsonl`, `api_confirmed.jsonl`, `authenticated_api_results.jsonl`, and `authenticated_impact_candidates.jsonl`.

Safe checks:

- Inspect methods, paths, parameter names, JSON field names, status codes, content type, length, and schema shape.
- Confirm whether an endpoint is documentation, mock data, unauthenticated metadata, or real business data.
- Compare anonymous versus authenticated behavior only with operator-supplied sessions.
- Use counts, field names, and hashes instead of storing values.

Approval-required:

- Export, download, delete, upload, submit, approve, SMS, password, account, order, payment, refund, import, or job endpoints.
- Bulk enumeration, tenant switching, or object access involving real third-party records.

### Login and Authenticated Review

Use `01_需要你登录拿Cookie.*`, `manual_auth_queue.*`, and `auth_sessions.template.json`.

Rules:

- The operator logs in manually where authorized.
- Raw cookies, Authorization headers, passwords, and tokens stay in local-only session files.
- Do not paste secrets into prompts, reports, screenshots, ledgers, or shared artifacts.
- Authenticated follow-up stays read-only and same-host unless new assets are separately confirmed.
- Register accounts only when explicitly allowed. Never change passwords or business data.

### Weak Credentials

Use `03_弱口令人工确认队列_不自动跑.*`, `weak_credential_manifest.json`, `weak_credential_attempts.jsonl`, `weak_credential_successes.jsonl`, and `weak_credential_skips.jsonl`.

Review order:

1. Confirm the host is in scope and the rules allow weak-credential checks.
2. Check CAPTCHA, lockout, warning prompts, MFA, and account-safety signals.
3. Prefer product-aware/default-credential surfaces over broad login pages.
4. If approved, use the smallest product-aware common-pair set and stop on CAPTCHA, rate limit, warning, lockout, or first success.
5. Record only metadata: target, product, account type, result, timestamp, screenshot, and redacted proof.

Do not run credential spraying, brute force, broad password lists, or repeated attempts.

### Product Vulnerability Candidates

Use `04B_产品漏洞候选队列.*`, `product_triage_summary.json`, `product_vuln_candidate_queue.csv`, and `product_vuln_candidates.jsonl`.

Safe evidence:

- Version banners, dependency disclosure, documentation paths, error pages, JS package names, response headers, product-specific static pages, and vendor advisories.
- Known affected version plus reachable product surface may justify a candidate, but confirm exploitability only when rules allow.

Approval-required:

- Fastjson/Log4j/Struts2 callbacks, deserialization payloads, RCE checks, JNDI, DNSLog, memory shells, upload-based checks, and product exploit templates.

### SQL Injection

Review `sqli_high_probability.*` first, then `second_pass_confirmed.jsonl` SQLi rows, `sqli_candidates.jsonl`, and `sqli_500_or_error_anomalies.txt`.

Manual confirmation:

- Compare baseline, baseline repeat, quote probe, boolean true, and boolean false.
- Stronger evidence needs stable boolean difference, DB error signatures, or consistent parameter-bound behavior.
- 403, WAF block pages, generic error pages, 500, status changes, and content-length changes alone are not enough.

Approval-required:

- SQLMap, time-based tests, union select, stacked queries, data extraction, database fingerprinting beyond minimal proof, and any write or dump.

### XSS

Use `04C_XSS反射候选队列.*`, `xss_candidates.jsonl`, `xss_reflection_checks.jsonl`, `xss_reflection_candidates.txt`, `xss_manual_review.md`, and second-pass XSS rows.

Manual confirmation:

- Confirm the marker appears in an executable browser context, not just source text, JSON, a blocked page, or escaped HTML.
- Capture DOM context, parameter, browser URL, timestamp, and redacted screenshot.
- Prefer inert markers and browser inspection. Do not submit stored payloads or affect other users without approval.

### Shiro

Use `12_Shiro候选判断.md`, `shiro_manual_queue.csv`, `shiro_triage_results.jsonl`, and `shiro_detected.txt`.

Safe review:

- Check rememberMe cookie behavior, product clues, Java/OA/login context, and response differences.
- Manual tool validation must be single-target and approved.
- Do not run broad ShiroAttack2 scans, key brute force, serialized payloads, or RCE checks.

### Upload, File Handling, and Exposures

Use `09_文件上传安全测试.md`, `candidate_exposures`, `verified_exposures`, and upload/file-related API rows.

Safe review:

- Identify upload endpoints, accepted file metadata, public retrieval path, auth requirement, and cleanup requirement.
- Do not upload, overwrite, delete, or retrieve sensitive files without approval.
- For exposed configs, logs, heap dumps, source maps, Swagger, Druid, Actuator, phpinfo, ELMAH, Tomcat manager, and similar, prove access with minimal metadata and screenshots. Do not download large files or secrets.

### Authorization and IDOR

Use `10_越权和接口泄露复核.md`, API queues, authenticated candidates, and JS-discovered object/tenant parameters.

Safe review:

- Build a small matrix: anonymous, own test user, second authorized test user, low role, admin role if provided.
- Test only disposable or operator-provided objects.
- Record expected secure behavior before observing.

Approval-required:

- Accessing real third-party records, bulk enumeration, exports, destructive actions, or state transitions.

### Mini-Program Outputs

For `wxapkg_extract`, miniapp analysis folders, or `wechat_*` outputs:

1. Read `summary.json` and package parse summaries.
2. Separate code noise from real domains and URLs.
3. Classify hosts before testing.
4. Convert real in-scope hosts and API paths into website/API review candidates only after ownership is known.
5. If extraction is strings-only, record static-coverage limitations.

Raw extraction lists such as `domains.txt`, `wxapkg_domains_all.csv`, `urls.txt`, and `third_party_or_need_confirm.txt` are source-review evidence, not automatic valuable targets.

## Approval Gates

Keep these as approval-required, never automatic:

- Weak-password attempts, brute force, credential spraying, account lockout-sensitive checks, and login attempts beyond explicitly approved low-volume manual checks.
- SQLMap, time-based SQLi, union/data extraction, stacked queries, database access, and any data dump.
- RCE, deserialization, Log4j/JNDI/callback payloads, Shiro rememberMe exploitation, webshells, tunnels, persistence, command execution, and post-exploitation.
- Uploads, deletes, imports, exports, transactions, password/account/session changes, and workflow approvals.
- Active testing of new domains, subdomains, mini-program backends, third-party services, supply-chain paths, or platform/shared services before ownership and scope are confirmed.

When a candidate needs one of these actions, record the exact action, target, reason, expected evidence, risk, and cleanup plan in `approval_gates.md` or review notes, then wait for explicit operator approval.

## Evidence and Reporting

Use `reports/screenshot_queue.md`, `evidence/screenshots/README_截图说明.md`, `reports/evidence_index.md`, `reports/daily_report_draft.md`, and `reports/platform_submission_template.json`.

For each confirmed finding, include:

- Target, URL/path, affected parameter or function, account/role used, and scope basis.
- Minimal reproduction steps and expected/actual behavior.
- Impact stated from demonstrated evidence, not scanner language.
- Screenshot/video timestamp with current date/time visible where required.
- Redacted evidence path and hash.
- Cleanup performed or why none was needed.
- Retest result or retest blocker.

Do not report candidates that remain `pending`, `needs_login`, `approval_required`, `blocked`, or `out_of_scope`.

## Recommended Response Template

```markdown
## 本轮概览

- Run dir:
- 目标数:
- P0/P1/P2/P3:
- 二次复测稳定:
- 目标画像数:
- 健康/失败阶段:

## 优先复核队列

| 优先级 | 类型 | Host | 目标/参数 | 为什么先看 | 下一步 |
| --- | --- | --- | --- | --- | --- |

## 重点目标画像

### <host>

- 入口/指纹:
- API/业务字段:
- SQLi/XSS/产品候选:
- 弱口令/登录态线索:
- 证据缺口:
- 建议手工复核:

## 审批门槛

| 动作 | 目标 | 为什么需要审批 | 可替代的安全动作 |
| --- | --- | --- | --- |

## 不建议现在做

- 不跑批量 SQLMap。
- 不爆破弱口令或 Shiro key。
- 不调用导出/下载/删除/审批/短信/支付/改密接口。
- 不发送 RCE、反序列化、JNDI、OGNL、webshell、回连 payload。
```

## Closure Criteria

Do not close until:

- Run health and stage failures are understood.
- All pending/new assets are either in scope, out of scope, third party, platform/shared, or blocked with a reason.
- Every row in the working target queue has a disposition or an explicit blocker.
- Every non-empty manual queue has a disposition through the relevant target review.
- Every P0/P1 second-pass-stable candidate has been reviewed or assigned a blocker.
- Every confirmed finding has minimized redacted evidence, video/screenshot time reference where required, cleanup state, and retest or retest limitation.
- Every weak credential, SQLi, XSS, Shiro, product-vulnerability, upload, authenticated, or mini-program branch is either safely reviewed, rejected, blocked, or approval-required.
- The final daily/report draft includes only manually verified findings and explicitly lists residual risk.

The final response must summarize reviewed run directories, run health, top candidates, confirmed findings, rejected false positives, approval gates, new-scope blockers, evidence/report paths, and next actions.
