# Project Re-Audit 2026-07-09

This audit looked at whether the project can be used as a long-running, tool-integrated, real-environment pentest workflow without routinely missing high-value targets. The review was offline only; no live targets were probed.

## Bottom Line

The project now has a much better controlled runner than the older scripts, but the repository still contains several legacy entrypoints that are noisy, hardcoded, or too aggressive for production use. The main improvement direction is not "run every exploit by default"; it is to make read-only depth much stronger, then automatically reduce results into a ranked review queue.

The most important fixes made in this pass:

- Expanded `gov_exercise_runner.py` high-value path coverage.
- Fixed truth verification so candidate body keyword hits are counted without saving sensitive response bodies.
- Added `result_prioritizer.py` to produce `priority_targets.json` and `reports/priority_review.md`.
- Added `api_endpoint_confirm.py` for bounded read-only confirmation of high-priority API endpoints.
- Added `run_health.py` for offline scan-quality metrics.
- Hooked the priority reducer into the main runner summary stage.
- Added `--api-discovery` support to `extra_subdomain_batch_runner.py`.
- Documented the new priority outputs in `GOV_EXERCISE_RUNNER.md` and the project skill.

## Findings

### 1. Old `scanner.py` Should Not Be A Main Entrypoint

`scanner.py` is a legacy pipeline. It has hardcoded `D:/Desktop` paths, uses `shell=True`, writes outputs outside the run directory, and can run nmap, afrog, nuclei, dirsearch, weak credential checks, and exploitability checks from one command path.

Keep it only as historical reference. Use `gov_exercise_runner.py` for background runs.

### 2. Truth Verification Was Too Shallow

The previous scoring looked at status, title, content type, final URL, hash, and length, but not body keyword hits. That can miss real OpenAPI JSON, Actuator JSON, config files, and Druid JSON because the proof words are often only in the body.

Fixed by adding body keyword detection to `probe_one(..., marker_keywords=...)`. The runner stores only keyword names, hash, status, and length, not response body text.

### 3. High-Value Path Coverage Was Too Small

The earlier path set was good as a seed but too small for real targets. It now includes broader Spring Boot Actuator, Druid JSON, Swagger/Knife4j, Git/SVN, .NET config, PHP info/composer, and Java config paths.

This is still bounded and low-rate, but much less likely to miss obvious exposures.

### 4. API/JS Discovery Was Not In Batch Runs

The single runner supported `--api-discovery`, but the batch runner did not pass it through. That means large background batches could still run the old shallow flow.

Fixed by adding `--api-discovery`, `--api-use-katana`, and `--api-max-js` to `extra_subdomain_batch_runner.py`.

### 5. Results Needed Automatic Priority Reduction

Large runs can produce hundreds or thousands of candidate rows. Without ranking, high-value targets get buried.

Added `result_prioritizer.py`. It reads:

- `verified_exposures.jsonl`
- `candidate_exposures.jsonl`
- `false_positive_exposures.jsonl`
- `impact_candidates.jsonl`
- `api_candidates.jsonl`
- `fingerprints.jsonl`
- `tool_triage_nuclei_impact.jsonl`

It writes:

- `priority_targets.json`
- `reports/priority_review.md`

It ignores candidate rows already marked false-positive for the same base/path.

### 6. Tool Integration Is Fragmented

There are several overlapping wrappers: `scanner.py`, `toolkit_integration.py`, `pentest_pipeline.py`, `nuclei_wrapper.py`, and the newer `tool_assisted_triage.py`.

Recommended source of truth:

- Main background workflow: `gov_exercise_runner.py`
- JS/API depth: `api_discovery.py`
- Mature tool confirmation: `tool_assisted_triage.py`
- Result ranking: `result_prioritizer.py`
- Report drafts: `evidence_builder.py`

The older wrappers should not be used for unattended production scans until they are refactored into the same run directory, rate control, and approval model.

## Remaining Improvements

1. Continue improving technology-aware template routing.
   `tool_assisted_triage.py` currently supports nuclei in a conservative tag set. It should choose template groups from fingerprint categories, for example Spring/Druid/Swagger/Git/IIS/PHP/OA.

2. Add a unified tool registry.
   `gov_exercise_config.json` and `config.py` still overlap. Long-term, `gov_exercise_config.json` should become the stable registry for background automation; `config.py` can remain for legacy Tianhu paths.

3. Add target ownership confidence.
   For extra subdomains, keep a scored `scope_confidence` field based on suffix, ICP/org keywords, TLS certificate org, page title, and redirect chain. This reduces manual review load without blindly trusting passive data.

4. Add stronger legacy script containment.
   `scanner.py`, `pentest_pipeline.py`, and `toolkit_integration.py` should print a warning pointing to `gov_exercise_runner.py`, or be moved under `legacy/` after confirming nothing depends on them.

## Recommended Default Command

```powershell
<python.exe> .\gov_exercise_runner.py --targets <target-file> --probe --fingerprint --high-value-paths --api-discovery --api-confirm --delay 3
```

For batch lists:

```powershell
<python.exe> .\extra_subdomain_batch_runner.py --targets <target-file> --runner-python <python.exe> --workspace D:\PythonSource\PythonProjects\PythonProject4 --batch-size 300 --delay 3 --api-discovery --api-confirm
```

After a run, review this first:

```text
<run-dir>\reports\priority_review.md
```
