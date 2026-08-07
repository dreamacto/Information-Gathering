---
name: gx-gov-exercise
description: Controlled workflow for authorized Guangxi government exercise target lists. Use when given domains, URLs, live target tables, or scan outputs for this exercise and asked to plan, run, verify, classify, or report results with scope checks, low-rate reconnaissance, truth verification, approval gates, evidence indexing, and scoring/report drafts.
---

# Guangxi Government Exercise Workflow

## Operating Posture

Default project prompt: reply in Chinese; assume work is for authorized SRC targets, open-source security research, blue-team/attack-defense exercises, or approved white-hat testing; use Windows conventions and prefer `curl` for web requests; do not create unrelated documents; analyze exploitability and limiting conditions deeply. When a valid, submit-ready finding is confirmed, generate an attack-result DOCX from the configured template, use team name `观叶识微`, insert available screenshots, and mark missing screenshot slots with `【需截图】`.

Treat every target as production. Default to check-only and low-risk reconnaissance. Do not run credential spraying, brute force, webshell/C2/tunnel tooling, destructive writes, sensitive data export, or internal scanning unless the user provides explicit approval evidence and the exercise platform has approved the action.

Use the project runner before ad hoc tools:

```powershell
<tianhu-python> .\gov_exercise_runner.py --targets <target-file>
```

Then escalate only by adding explicit flags:

```powershell
<tianhu-python> .\gov_exercise_runner.py --targets <target-file> --probe --fingerprint --limit 10 --delay 3
<tianhu-python> .\gov_exercise_runner.py --targets <target-file> --probe --fingerprint --high-value-paths --limit 10 --delay 3
<tianhu-python> .\gov_exercise_runner.py --targets <target-file> --probe --fingerprint --high-value-paths --api-discovery --api-confirm --delay 3
<tianhu-python> .\gov_exercise_runner.py --targets <target-file> --probe --fingerprint --high-value-paths --shiro-triage --api-discovery --api-confirm --sqli-triage --wechat-miniapp --wechat-live --wechat-max-js 3 --delay 3
<tianhu-python> .\gov_exercise_runner.py --targets <target-file> --resume-run-dir <run-dir> --probe --fingerprint --high-value-paths --api-discovery --api-confirm --delay 3
<tianhu-python> .\gov_exercise_runner.py --targets <target-file> --resume-run-dir <run-dir> --auth-review --auth-cookie-file <local-session-json> --auth-max-js 20 --auth-max-endpoints 30 --delay 3
<tianhu-python> .\tool_assisted_triage.py --run-dir <run-dir> --source priority --tool nuclei --limit 20 --rate-limit 1 --concurrency 1
<tianhu-python> .\evidence_builder.py <run-dir>
```

## Workflow

1. Import the domain/URL table, normalize URLs, deduplicate, and write `targets.csv` and `targets.json`.
2. Check runtime and tools. Prefer the Tianhu bundled Python/Java configured in `gov_exercise_config.json`.
3. Write `workflow_plan.md`, `tool_strategy_plan.md`, `workflow_snapshot.json`, `tool_strategy_snapshot.json`, `compliance_checklist.json`, and `approval_required.md`.
4. For live probing, use low-rate HTTP GET only. Record status, final URL, title, Server, Content-Type, body sample hash, and sample length.
5. Classify targets into `cat_java.txt`, `cat_net.txt`, `cat_php.txt`, `cat_oa.txt`, `cat_ai.txt`, `cat_bigscreen.txt`, `cat_login.txt`, `cat_api.txt`, and `cat_other.txt`.
6. For JS/API discovery, use `--api-discovery` to fetch homepage, robots, sitemap, OpenAPI/Swagger hints, same-host JavaScript, source map references, and high-value API route candidates. Outputs are `api_discovery.jsonl`, `api_candidates.jsonl`, and `impact_candidates.jsonl`.
7. For API endpoint confirmation, use `--api-confirm` after discovery. Confirm only bounded, GET-like endpoints and record status/hash/type/JSON shape, not response bodies.
7a. For Apache Shiro triage, use `--shiro-triage` after probing/fingerprinting. It tests Java/login/OA seeds by default with baseline GET plus an invalid `rememberMe` cookie probe, then writes `shiro_candidates.jsonl`, `shiro_detected.txt`, and `shiro_manual_queue.csv`. Use ShiroAttack2 only later for one authorized candidate at a time; do not brute force keys, send serialized payloads, execute commands, upload files, or install memory shells in the default flow.
8a. For SQL injection triage, use `--sqli-triage` after JS/API discovery. It tests only discovered parameterized GET URLs, uses five curl requests per parameter by default, skips risky write/download/upload paths, and writes `sqli_candidates.jsonl`, `sqli_high_probability.jsonl`, `sqli_high_probability.txt`, and `sqli_500_or_error_anomalies.txt`. HTTP 500/status changes are weak leads only; high probability requires a DB error signature after payloads or a stable boolean true/false differential. Use `sqlmap` later only on one approved candidate URL at a time with risk=1, level=1, technique BE, delay, and no dump/destructive options.
8. Always review `manual_auth_queue.csv` after discovery. The runner lists login pages, auth endpoints, and likely registration routes, but never registers accounts or tries passwords.
9. After an operator registers/logs in where authorized, use a local `auth_sessions.local.json` with `--auth-review --auth-cookie-file`. The authenticated branch reads cookies in memory, stays on the authorized host, and stores only status, length, hash, JSON field names, and risk labels.
10. Treat download/export/upload/delete/update/account-action routes as manual candidates. Do not trigger them automatically or persist response values and files.
11. For high-value path checks, test only existence and metadata for known sensitive paths. Do not submit write payloads or download data.
12. Run truth verification before claiming anything: compare with the homepage hash, response length, Content-Type, status, title, and expected keywords. Split output into `verified_exposures.jsonl` and `false_positive_exposures.jsonl`.
13. For mature tool confirmation, use `tool_assisted_triage.py` on a bounded candidate source. It is dry-run by default and writes `tool_assisted_triage_plan.json`; use `--execute` only after reviewing scope, tags, rate, and time window.
14. Review `priority_targets.json`, `reports/priority_review.md`, `run_health.json`, and `reports/run_health.md` first after every background run. They rank likely high-value targets and describe scan quality.
15. Stop at the approval gate for medium/high-risk steps. Generate evidence and scoring drafts instead of auto-exploitation.
16. Build reports with `evidence_builder.py` after screenshots or manual notes are added. If `confirmed_findings.json/jsonl` or verified exposures exist, it also generates an attack-result DOCX from the configured template. Missing screenshots must be marked in the DOCX with `【需截图】` and the exact screenshot needed.

## Truth Verification Rules

Read [references/truth-verification.md](references/truth-verification.md) when deciding whether a candidate path is real or a false positive.

The short version:

- Same hash as homepage means likely SPA or fallback page.
- Login, 401, 403, 404, redirect-only, and generic error pages are not findings by themselves.
- A candidate needs both structural difference and semantic evidence.
- Store proof metadata and screenshots, not sensitive data.

## Rate Control

Read [references/rate-control.md](references/rate-control.md) before any live target action.

Keep concurrency at 1 by default, add per-host delay and jitter, back off on 429/5xx, and stop after repeated host errors. Prefer passive discovery and metadata-only checks before any template scan, crawler, directory scan, or port scan.

## Tool Strategy

Use `tool_strategy.json` as the source of truth. The default pattern is one primary tool plus one backup tool, where the backup is only for sampling, blind-spot coverage, or confirmation. Do not run two active tools full-scope by default.

Custom scripts are not authoritative validators by default. Treat scripts such as `vuln_sqli_pure.py`, `vuln_lfi.py`, `vuln_rce.py`, `vuln_ssti.py`, upload helpers, and weak-password helpers as candidate screeners, wrappers, or evidence organizers. Once a candidate is worth validating, use a mature tool or manual request review as the primary validator, with explicit approval for medium/high-risk proof.

Examples:

- Subdomains: OneForAll primary, subfinder/certificate transparency as passive backup.
- Liveness: runner HTTP probe primary, httpx for failure/edge-case sampling.
- Fingerprint: runner rules primary, EHole/TideFinger/P1finger for high-value confirmation.
- JS/API discovery: `api_discovery.py` primary, katana/PackerFuzzer/API-Explorer for important-target blind-spot coverage under same-host scope and low rate.
- Vulnerability templates: nuclei primary, afrog only for confirmed candidates.
- Shiro: `shiro_triage.py` is the default low-impact screener for Java/login/OA targets. ShiroAttack2 is manual single-target validation only; command execution, memory shell, upload, and persistence features are approval-gated and disabled by default.
- SQL injection: `sqli_triage.py` is the default low-impact candidate screener for discovered parameterized URLs. `vuln_sqli_pure.py` is backup/manual review. `sqlmap` is the primary validation tool for one approved candidate URL at a time with risk=1, level=1, technique BE, delay, and no dumping/destructive options.
- LFI/RCE/SSTI/upload/weak-password helpers: candidate screening or approved single-target assistance only; final validation requires mature tooling, manual request review, or an approved minimal proof.
- Reports: evidence_builder is the only primary report generator.

## Scoring And Evidence

Read [references/scoring-evidence.md](references/scoring-evidence.md) before drafting a submission.

Every submitted result needs target consistency, evidence files, current system date/time visible in screenshots, video time range, impact description, and a scoring-rule mapping. Extra assets need target application before testing.

## Files To Prefer

- `gov_exercise_workflow.json`: machine-readable phase list and gates.
- `tool_strategy.json`: one-primary-one-backup tool strategy.
- `gov_exercise_config.json`: runtime/tool paths and blocked actions.
- `gov_exercise_runner.py`: safe runner for target import, probe, classification, path checks, truth verification.
- `api_endpoint_confirm.py`: bounded read-only API endpoint confirmation.
- `shiro_triage.py`: low-impact Apache Shiro rememberMe feature triage that outputs manual ShiroAttack2 review queues.
- `sqli_triage.py`: curl-based low-impact SQL injection triage that outputs high-probability and 500/error anomaly lists.
- `authenticated_session_review.py`: manual login/registration handoff and bounded authenticated JS/API metadata review.
- `result_prioritizer.py`: offline high-value target queue builder.
- `run_health.py`: offline scan-quality metrics.
- `evidence_builder.py`: report and platform submission drafts.
