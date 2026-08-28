# Artifact services

- `manifest.py` creates and verifies SHA-256 manifests for local run artifacts.
- `deletion_audit.py` records controlled local deletions and protects sessions/raw evidence.
- `fingerprint_ingest.py` merges run fingerprints into the local cumulative library without network access.

The repository-root modules remain compatibility entrypoints. New imports should use `authorized_assessment.artifacts`.
