# Rate Control

Use this reference before any live action against production websites.

## Defaults

- Default concurrency: 1.
- Default delay: 2 seconds between requests.
- Per-host minimum interval: 2 seconds.
- Jitter: 25 percent.
- Back off on 429, 500, 502, 503, and 504.
- Stop a stage for a host after repeated errors.

## Per-Phase Guidance

- Passive subdomain enumeration: prefer passive sources; respect provider API rate limits.
- HTTP probe: status/title/header/hash only; avoid storing full bodies by default.
- Crawling: set depth and max pages per domain; keep same-domain scope.
- Directory/path checks: small high-value path list first; avoid broad wordlists on production unless approved.
- Port scan: only after scope approval; use small port sets and low packet rates.
- Vulnerability templates: restrict by technology and severity; avoid intrusive templates unless approved.

## Stop Conditions

Stop or pause when:

- Target responds with 429 or repeated 5xx.
- Response time degrades materially during the run.
- WAF/captcha/rate-limit page appears.
- The target owner or platform asks for pause.
- Evidence is sufficient for the approved objective.

