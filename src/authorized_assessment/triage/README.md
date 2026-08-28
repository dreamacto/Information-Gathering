# Triage stages

- `readonly_endpoint_confirm.py`: bounded, read-only endpoint confirmation; it may make network requests and requires an approved scope.
- `deep_readonly_triage.py`: bounded read-only configuration, Git, OpenAPI, Actuator, and Druid candidate triage; it may make network requests and requires an approved scope.
- `second_pass_triage.py`: bounded repeat checks for existing SQLi/XSS/API candidates; it may make network requests and remains candidate screening, not exploitation.
- `sqli.py`: package facade for the SQLi candidate stage; the root implementation remains canonical to preserve request-adapter monkeypatching.
- `xss.py`: package facade for the XSS candidate stage; the root implementation remains canonical to preserve request-adapter monkeypatching.
- `header_reflection.py`: package facade for the header reflection stage.
- `shiro.py`: package facade for the Shiro candidate stage; its single-target/approval boundaries remain unchanged.

Active testing, credentials, writes, exploitation, OOB callbacks, and destructive actions remain outside this package migration and retain their existing approval boundaries.
