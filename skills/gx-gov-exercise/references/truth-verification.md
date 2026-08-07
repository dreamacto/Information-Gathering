# Truth Verification

Use this reference when a path looks sensitive but may be a SPA fallback, generic error page, or login redirect.

## Candidate Signals

Treat a candidate as stronger when several are true:

- HTTP status is 200 and stable across repeated low-rate checks.
- The body sample hash differs from the homepage hash.
- The response length differs materially from the homepage.
- Content-Type differs from the homepage in a way that matches the path.
- Expected keywords appear in metadata or a small body sample.
- The page title is not a generic homepage, login page, or error page.

## False Positive Signals

Treat a candidate as weak or false when any are true:

- Same body sample hash as homepage.
- 301/302-only behavior to a login page.
- 401, 403, or 404 without additional proof.
- Generic title such as login, not found, error, portal, or welcome.
- Large SPA shell response that is identical across arbitrary paths.
- WAF block page or rate-limit page.

## Decision Rule

Do not claim a finding from path existence alone. Prefer:

1. Candidate path metadata.
2. Homepage comparison.
3. Expected keyword or structure.
4. Screenshot with system date/time.
5. Manual reviewer note explaining why it is not a fallback.

If evidence is mixed, keep it in `candidate_exposures.jsonl` or `false_positive_exposures.jsonl` and do not submit.

