# Project Audit And Tooling Plan

Generated for the current pentest/vulnerability-research workspace.

## Executive Summary

The project already contains many useful modules: target generation, subdomain collection, liveness probing, directory scanning, JS/API analysis, nuclei/afrog wrappers, SQLi/LFI/RCE/SSTI probes, result database, and report generation.

The main gap is not tool count. The main gap is orchestration discipline:

- Legacy scripts mix safe reconnaissance, verification, exploitation, weak password spraying, post-exploitation, and reporting in the same workspace.
- Rate limits are inconsistent across modules.
- Several legacy files hard-code `D:/Desktop` outputs and external tool paths.
- Some config/source files show encoding damage in comments and Chinese labels.
- Evidence handling and scoring are improving through the new runner, but legacy flows do not yet write the same audit artifacts.

Use `gov_exercise_runner.py` as the default entrypoint for live targets. Treat older exploit-oriented scripts as manual modules behind approval gates.

Custom vulnerability scripts should be treated as candidate screeners or orchestration helpers, not authoritative validators. For example, `vuln_sqli_pure.py` can flag parameter-difference candidates, but `sqlmap` plus manual request review is the primary SQL injection validation path. Apply the same rule to LFI/RCE/SSTI/upload/weak-password helpers: screen first, then validate a small approved target set with mature tooling, manual review, or a minimal proof.

## Tool Strategy

The project now uses `tool_strategy.json`:

```text
Run one primary tool by default.
Use one backup tool only for sampling, blind-spot coverage, or confirmation.
Do not run two active tools full-scope by default.
```

This keeps traffic low while preserving coverage and confidence. Every new run writes `tool_strategy_plan.md` and `tool_strategy_snapshot.json`.

## Local Findings

### High Priority

1. Centralize rate control.
   - New config: `gov_exercise_config.json -> rate_control`.
   - New behavior: single-thread live probe, per-host delay, jitter, 429/5xx backoff, repeated-error stop.
   - Remaining work: legacy modules such as `dir_scanner.py`, `school_info_collector.py`, `credential_spray.py`, `vuln_dispatcher.py`, and `vuln_sqli_pure.py` should import the same rate controller or be called only through the controlled runner.

2. Separate safe workflow from high-risk workflow.
   - Safe: import, normalize, passive discovery, metadata probe, fingerprint, path existence, truth verification, evidence/report drafts.
   - Gated: credential spraying, broad directory brute force, intrusive nuclei templates, SQL injection exploitation, file upload validation, command execution, database login checks, webshell/C2/tunnels, internal scanning.
   - Candidate-only: custom scripts such as `vuln_sqli_pure.py`, `vuln_lfi.py`, `vuln_rce.py`, `vuln_ssti.py`, upload helpers, and weak-password helpers should only produce candidates unless an approval gate explicitly moves one target into minimal validation.

3. Remove or wrap hard-coded external output paths.
   - `scanner.py` writes several outputs to `D:/Desktop`.
   - Prefer `runs/<timestamp>/...` so every run is reproducible and reviewable.

4. Fix runtime and encoding drift.
   - System `python`/`py` are unavailable in this shell.
   - `.venv` exists but does not run reliably.
   - Tianhu bundled Python works and is now preferred in `gov_exercise_config.json`.
   - Several older files display mojibake; avoid editing them until replaced or re-encoded carefully.

### Medium Priority

1. Normalize output schemas.
   - Prefer JSONL for per-target findings.
   - Include `target`, `host`, `stage`, `tool`, `status`, `evidence`, `verification_score`, and `approval_required`.

2. Add target allowlist enforcement to legacy wrappers.
   - Any wrapper that accepts `--url`, `--domain`, or `--project` should check against the active run target snapshot.

3. Add passive-first asset discovery.
   - For vulnerability research, start with passive sources and historical data before active probing.

4. Add resumability per phase.
   - `batch_runner.py` has progress tracking; the new runner should eventually support phase-level resume inside each run directory.

## Recommended Complete Workflow

```text
Domain table
  -> Scope and allowlist validation
  -> Runtime/tool inventory
  -> Passive subdomain discovery
  -> Low-rate liveness probe
  -> Fingerprint and category archive
  -> Low-rate crawler/API/JS metadata extraction
  -> High-value path existence check
  -> Truth verification
  -> Risk/approval gate
  -> Minimal validation only when authorized
  -> Evidence index and screenshots
  -> Score mapping and report draft
```

## Rate Control Policy

Default production-safe settings:

- Concurrency: 1.
- Delay: 2 seconds per request.
- Per-host interval: at least 2 seconds.
- Jitter: 25 percent.
- Backoff: sleep 10 seconds on 429, 500, 502, 503, 504.
- Stop: stop that host after 5 repeated errors.
- Broad scans: require approval and use tool-native rate flags.

When using external tools, prefer these controls:

- `httpx`: set rate limit, retries, timeout, JSON output.
- `katana`: set depth, scope, rate limit, and max crawl duration.
- `naabu`: set top ports or a small port list, rate, timeout, and retries.
- `nuclei`: set rate limit, concurrency, template allowlist, severity/tags, JSONL output.
- `ffuf`: set rate, delay, timeout, and recursion limits.

## Tianhu Tools Worth Reusing

Low-risk or controlled discovery:

- OneForAll: passive/aggregated subdomain discovery.
- EHole, TideFinger, P1finger, MFinder, VEO: fingerprint confirmation.
- DirSearch: directory/path discovery, but only with low threads and small wordlists.
- PackerFuzzer and VueScan: front-end/webpack/API route discovery.
- API-T00L / API-Explorer: API analysis, preferably manual or offline.
- httpx if present in `gui_scan/fcke`: liveness and metadata.
- nuclei and afrog: template-based validation with rate limit, scope, and template filtering.
- Yakit/Burp/Fiddler/Reqable: manual proxy analysis and evidence capture.

Approval-gated or manual-only:

- SQLMap, SuperSQLInjection, MDUT, Oracle/PostgreSQL tools.
- OA exploit suites, RuoYi tools, Shiro/Fastjson/WebLogic/JBoss/Struts tools.
- Fscan, Kscan, Goby, Rscan when scanning beyond a single web target.
- Week-Passwd and credential spray tooling.
- WebShell managers/generators, C2 tools, FRP/Suo5/V2Ray/Neo-reGeorg, Mimikatz, privilege escalation and lateral movement tools.

## External Tools To Add

Prioritize tools that improve discovery, verification, and evidence without increasing risk:

- ProjectDiscovery `subfinder`: passive subdomain enumeration.
- OWASP Amass: attack-surface mapping and asset discovery.
- ProjectDiscovery `httpx`: HTTP metadata probing with structured output.
- ProjectDiscovery `katana`: controlled crawler for routes, JS, and API endpoints.
- ProjectDiscovery `naabu`: fast port scanner; use only with low rates and approved port lists.
- ProjectDiscovery `nuclei`: template-based scanner; keep severity/tag/template filters tight.
- `ffuf`: web fuzzing; use only with low rate and small curated wordlists.
- Gitleaks or TruffleHog: local/source/JS secret detection.
- OWASP ZAP Automation Framework: passive baseline and repeatable report generation.
- Dalfox: XSS validation, gated and only after candidate parameters are confirmed.
- garak: LLM app checks for AI-target workflows.

## Next Implementation Steps

1. Add a shared `rate_control.py` and gradually migrate legacy scripts to it.
2. Add `--allowlist <targets.json>` checks to all legacy scripts that touch live targets.
3. Add `tool_profiles.json` for safe command templates with rate flags.
4. Add a `--dry-run` mode for wrappers that prints exact commands and expected output files.
5. Add run-level SQLite import so `results_db.py` consumes `runs/*/*.jsonl`.
6. Add screenshot/evidence attachment helpers that never store sensitive data.
