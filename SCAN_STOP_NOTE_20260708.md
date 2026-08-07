# Scan Stop Note - 2026-07-08

## Stop Status

- Stopped by user request because the exercise window was ending.
- Active Python scan processes were stopped:
  - `22716` - child scan process
  - `36756` - batch controller process
- Follow-up check showed no remaining `python` scan process.
- `extra_subdomain_batch_status.json` was updated to `stopped_by_user`.

## Scope Used

- Original target inputs:
  - `D:\Desktop\targets_scan.txt`
  - `D:\Desktop\targets_v2.txt`
- Combined/dedup target file:
  - `D:\PythonSource\PythonProjects\PythonProject4\combined_targets_20260708_093713.txt`
- Approved extra subdomain batch file:
  - `D:\PythonSource\PythonProjects\PythonProject4\extra_subdomains_approved_for_scan_20260708_1318.txt`
- Extra subdomain batch directory:
  - `D:\PythonSource\PythonProjects\PythonProject4\extra_subdomain_batches_20260708_130945`

## Completed Main Work

- Original main target run completed:
  - `D:\PythonSource\PythonProjects\PythonProject4\runs\20260708_093737_targets_full_20260708_093736`
- OneForAll passive subdomain collection completed and was filtered/reviewed.
- Approved extra subdomain scan was started but stopped during batch 1.

## Extra Subdomain Batch Progress At Stop

- Batch controller status before stop:
  - `current_batch`: `1`
  - `batch_count`: `3`
  - `batch_size`: `400`
- Batch 1 run directory:
  - `D:\PythonSource\PythonProjects\PythonProject4\runs\20260708_130945_extra_subdomains_b001_20260708_130945`
- Batch 1 files at stop:
  - `probe_results.jsonl`: `400`
  - `fingerprints.jsonl`: `400`
  - `candidate_exposures.jsonl`: `1676`
  - `verified_exposures.jsonl`: `27`
  - `false_positive_exposures.jsonl`: `1649`
- Batch 2 and batch 3 had not started.

## Findings Reviewed

### Low Value / Not Accepted By Scoring

- `https://www.cabis.gov.cn/web.config`
  - Real `web.config` file download.
  - Contains IIS/default document/static content/handler/request filtering config.
  - No credentials, keys, database connection strings, internal addresses, or direct exploit path found.
  - User reported scoring did not accept this without further exploitable impact.

- `https://api-asc.fcgtvb.com/web.config`
  - Real downloadable `web.config`.
  - Deep read-only triage showed only IIS rewrite/system.webServer markers.
  - No sensitive fields found.

### Confirmed Low Value / No Further Impact

- `https://www.gnnzfw.cn:8082/druid/index.html`
  - Druid Monitor login page exposed.
  - `basic.json`, `datasource.json`, and `sql.json` redirect to the login page.
  - No unauthenticated Druid data confirmed.

### False Positives / Unified Error Pages

- `https://edu.bgxf.gov.cn/web.config`
  - Returns the same frontend HTML page, not a config file.
- `https://bqfq.sthjt.gxzf.gov.cn`
  - Apparent `.git`, `web.config`, Swagger, Actuator, and Druid hits were unified access-denied or 404 pages.
- `https://www.gxbaas.cn`
  - Most sensitive paths return the same frontend page.
  - Druid JSON endpoints return `{"error":"Not Found"}`.
- `https://prevent.cftzqinzhou.com:8090`
  - Previously confirmed not to expose real Swagger/OpenAPI content.

## Deep Triage Artifacts

- Deep triage target list:
  - `D:\PythonSource\PythonProjects\PythonProject4\deep_triage_targets_20260708.txt`
- Deep triage results:
  - `D:\PythonSource\PythonProjects\PythonProject4\deep_triage_curl_results_20260708.jsonl`
- Deep triage script:
  - `D:\PythonSource\PythonProjects\PythonProject4\deep_readonly_triage_curl.py`

## Next Recommended Direction

- Do not prioritize plain `web.config` exposure unless it contains secrets, connection strings, keys, internal hosts, or another clear exploit chain.
- Next phase should focus on fewer targets with real impact proof:
  - JS/API endpoint extraction from alive apps.
  - Real OpenAPI JSON with paths and unauthenticated sensitive interfaces.
  - Authorization bypass / IDOR checks using harmless read-only requests.
  - Backup/source archive discovery with strict low rate.
  - Real Actuator/Druid JSON exposure, not login pages.
  - Login portals only when authorized for weak-password testing.

## Resume Notes

- The approved extra subdomain scan was stopped before batch 2.
- To resume later, start from:
  - `D:\PythonSource\PythonProjects\PythonProject4\extra_subdomain_batches_20260708_130945\batch_002.txt`
- Batch 1 should be treated as partially completed for high-value path scanning but completed for probe and fingerprint.
