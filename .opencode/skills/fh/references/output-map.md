# Output map

Use this map to understand files produced by the local one-click workflows. Not every run has every file.
Empty files are still useful because they prove that a branch ran and produced no candidates.

## Workflow entrypoints

`一键完整流程_含弱口令.bat` runs:

```text
one_click_workflow.py --mode full --targets <target-file>
```

The wrapper enables low-rate full discovery unless disabled by flags. Typical run directory:

```text
runs/YYYYMMDD_HHMMSS_one_click_full_weak
```

`一键已有子域名后流程_含弱口令.bat` runs `parallel_flow_runner.py` with up to three batches and these
branches enabled: probe, fingerprint, tool fingerprint, high-value paths, API discovery/confirmation,
SQLi triage, Shiro triage, XSS reflection triage, and weak-credential review queue generation. Typical run
directories:

```text
runs/YYYYMMDD_HHMMSS_one_click_subdomains_parallel_b001
runs/YYYYMMDD_HHMMSS_one_click_subdomains_parallel_b002
runs/YYYYMMDD_HHMMSS_one_click_subdomains_parallel_b003
```

Treat sibling batch directories as one logical run when they share the same timestamp and label.

## Generated review workspace

`scripts/init_postrun_review.py` creates a review workspace without network access. If reused with the same
`--output`, it refreshes generated files and `target_reviews/` so stale target dossiers do not remain. Its
primary outputs are:

| File | Meaning | How to use |
|---|---|---|
| `target_review_queue.csv` | Every valuable host extracted from run outputs, sorted for sequential review | Main queue. Review every row in order; do not sample or batch-confirm |
| `target_review_index.md` | Markdown index of the target queue | Quick navigation to each target review page |
| `target_reviews/*.md` | One detailed checklist per target | Complete the target's scope, source-file, safe-check, evidence, approval, cleanup, and retest notes |
| `review_plan.md` | Health summary plus target-first review plan | Start here, then move to the first target |
| `review_ledger.csv` | Source files and queue files that fed the review | Use for traceability and source-file disposition |
| `findings_ledger.csv` | Confirmed/rejected finding template | Fill only after target-level manual validation |
| `approval_gates.md` | Gated actions collected by category | Do not execute these actions without explicit operator approval |
| `run_inventory.json` | Detected run directories, manual hubs, counters, and workspace metadata | Use for auditability |

## Health and scope files

| File | Meaning | Review action |
|---|---|---|
| `run_summary.json` | Main counters, branch flags, output paths, next steps | Read first; use counts to decide which queues matter |
| `run_health.json`, `reports/run_health.md` | Probe ratio, false-positive pressure, missing depth, login backlog | Fix interpretation before validating findings |
| `runtime_inventory.json` | Python/Java/tool paths and missing tools | Explain missing branches; do not silently assume coverage |
| `workflow_plan.md`, `workflow_snapshot.json`, `tool_strategy_*` | What the workflow planned and selected | Use when outputs look empty or inconsistent |
| `targets.csv`, `targets.json` | Normalized original targets | Confirm scope before active follow-up |
| `new_assets_pending_apply.txt` | New assets needing target application/confirmation | Do not actively test until approved |
| `subdomains_for_scope_confirmation.txt` | Auto-discovered subdomains needing scope confirmation | Classify before use |
| `subdomains_for_next_run.txt` | Candidates for a later approved run | Not proof of current scope |
| `rate_limit_skips.jsonl` | Backoff or repeated-error skips | Revisit only at lower rate or after environment fix |

## Manual review hub

When present, start with `00_重要_人工复核入口/README_先看这里.md`.

| Hub file | Purpose |
|---|---|
| `01_需要你登录拿Cookie.*` | Login/session handoff queue. Cookies stay in local session files and out of reports |
| `02_业务API只读复核队列.*` | Business/API schema candidates for read-only review |
| `03_弱口令人工确认队列_不自动跑.*` | Weak-credential candidates; manual gate only |
| `04_可报告候选_TOP.*` | Highest-priority reportable-candidate queue |
| `04B_产品漏洞候选队列.*` | Product/framework vulnerability candidates, usually queue-only |
| `04C_XSS反射候选队列.*` | Reflected-marker XSS candidates, not confirmed executable XSS |
| `05_认证态复核命令.md` | How to continue authenticated read-only review after operator session handoff |
| `06_弱口令显式复核命令.md` | Explicit weak-credential command guidance; never default |
| `07_小程序人工搜索与Burp导入.md` | Mini-program search, source, and Burp-import follow-up |
| `08_SQL注入手工确认.md` | SQLi manual confirmation rules |
| `09_文件上传安全测试.md` | Upload/file handling gates |
| `10_越权和接口泄露复核.md` | Authz/IDOR/API leakage review |
| `11_Fastjson_Log4j_Struts2候选判断.md` | Product-vuln candidate triage |
| `12_Shiro候选判断.md` | Shiro candidate triage |
| `13_XSS候选手工确认.md` | XSS manual confirmation |

## Candidate families

| Family | Primary files | Notes |
|---|---|---|
| Priority and exposures | `priority_targets.json`, `reports/priority_review.md`, `verified_exposures.jsonl`, `candidate_exposures.jsonl`, `false_positive_exposures.jsonl` | `verified_` means the workflow found stronger evidence, not automatic reportability |
| API and JS | `api_discovery.jsonl`, `api_candidates.jsonl`, `api_interesting.jsonl`, `api_confirmed.jsonl`, `impact_candidates.jsonl` | Keep to read-only schema/field/count validation |
| Authenticated review | `manual_auth_queue.*`, `auth_sessions.template.json`, `authenticated_api_results.jsonl`, `authenticated_impact_candidates.jsonl`, `authenticated_new_assets_pending.txt` | Sessions are local-only; do not log raw secrets |
| Weak credentials | `weak_credential_manifest.json`, `weak_credential_attempts.jsonl`, `weak_credential_successes.jsonl`, `weak_credential_skips.jsonl` | Attempts are approval-gated; stop on CAPTCHA, lockout, warning, or success |
| Product-specific | `product_triage_summary.json`, `product_triage_queue.csv`, `product_vuln_candidate_queue.csv`, `product_vuln_candidates.jsonl`, `reports/product_vuln_candidate_queue.md` | Queue-only unless safe version evidence proves impact |
| SQL injection | `sqli_high_probability.*`, `sqli_candidates.jsonl`, `sqli_500_or_error_anomalies.txt`, `sqli_triage_manifest.json` | 500/status/length differences are weak signals |
| XSS | `xss_candidates.jsonl`, `xss_reflection_checks.jsonl`, `xss_reflection_candidates.txt`, `xss_manual_review.md` | Inert reflection is a candidate, not executable XSS |
| Shiro | `shiro_candidates.jsonl`, `shiro_manual_queue.csv`, `shiro_triage_results.jsonl`, `shiro_detected.txt` | Single-target manual tool use is approval-gated |
| Mini-program | `wechat_*`, `miniapp_source_*`, `burp_miniapp_*`, `wxapkg_*`, package `summary.json` files | Classify backend ownership before testing |
| Evidence/report | `reports/screenshot_queue.*`, `evidence/screenshots/*`, `reports/evidence_index.md`, `reports/daily_report_draft.md`, `reports/platform_submission_template.json` | Only redacted/minimized evidence goes to reports |

## Mini-program extraction outputs

Extraction-only runs may look like:

```text
runs/YYYYMMDD_HHMMSS_wxapkg_extract
runs/<name>_miniapp_analysis
```

Important files include:

| File | Review action |
|---|---|
| `summary.json` | Confirm AppID/name/version, package count, domain/API counts, strings-only limitation |
| `wxapkg_package_parse_summary.csv` | Check whether parsing was `extracted`, `partial`, `failed`, `unsupported`, or `strings_only` |
| `wxapkg_domains_all.csv`, `domains.txt` | Separate real hosts from code-noise like `array.prototype.*` or image filenames |
| `wxapkg_urls.csv`, `urls.txt` | Extract real URLs and webviews |
| `wxapkg_api_paths.csv`, `api_paths.txt` | Convert paths to API hypotheses only after host ownership is known |
| `miniapp_targets_for_project.txt` | Candidate backends for later approved website/API review |
| `third_party_or_need_confirm.txt` | Scope blocker list |

If parsing is strings-only, do not claim full static coverage. Record the limitation and continue with recovered
clues only.

Raw extraction lists such as `domains.txt`, `wxapkg_domains_all.csv`, `urls.txt`, and
`third_party_or_need_confirm.txt` are source-review evidence, not automatic valuable targets. Only explicitly
in-scope suffix matches, WeChat auth-domain exports, approved subdomain scan targets, and Mini Program/Burp API
candidate files should enter the sequential target queue.
