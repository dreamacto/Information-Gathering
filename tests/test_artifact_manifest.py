from pathlib import Path
import json
from artifact_manifest import create_manifest, verify_manifest
from deletion_audit import record_delete


def test_manifest_detects_changes(tmp_path: Path):
    (tmp_path / 'evidence').mkdir()
    target = tmp_path / 'evidence' / 'ok.txt'
    target.write_text('one', encoding='utf-8')
    create_manifest(tmp_path)
    assert verify_manifest(tmp_path)['status'] == 'sealed'
    target.write_text('two', encoding='utf-8')
    assert 'evidence/ok.txt' in verify_manifest(tmp_path)['changed']


def test_delete_audit_records_hash(tmp_path: Path):
    target = tmp_path / 'temporary.txt'
    target.write_text('temporary', encoding='utf-8')
    event = record_delete(target, tmp_path, 'test cleanup', actor='test')
    assert not target.exists()
    row = json.loads((tmp_path / 'deletion_audit.jsonl').read_text(encoding='utf-8'))
    assert row['sha256_before'] == event['sha256_before']


def test_delete_audit_protects_sensitive_paths(tmp_path: Path):
    target = tmp_path / 'sessions'
    target.mkdir()
    secret = target / 'local.json'
    secret.write_text('secret', encoding='utf-8')
    try:
        record_delete(secret, tmp_path, 'test')
    except PermissionError:
        pass
    else:
        raise AssertionError('sensitive deletion must be rejected')
