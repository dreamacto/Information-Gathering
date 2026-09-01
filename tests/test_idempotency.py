from authorized_assessment.runtime.idempotency import IdempotencyStore, fingerprint, normalize_operation_key
import pytest

def test_accept_replay_and_conflict(tmp_path):
    s=IdempotencyStore(tmp_path/'ops.json')
    a=s.record(' op-1 ','payload',result_id='x',summary='ok',now=1)
    assert a['status']=='accepted'
    assert s.record('op-1','payload',now=2)['status']=='replayed'
    assert s.record('op-1','other')['status']=='conflict'

def test_shape_and_no_payload(tmp_path):
    s=IdempotencyStore(tmp_path/'ops.json'); s.record('k',{'token':'secret'},status='blocked')
    raw=(tmp_path/'ops.json').read_text()
    assert 'secret' not in raw and 'token' not in raw
    assert set(s.inspect('k')) >= {'fingerprint','result_status','created_at'}

def test_invalid_key_status():
    with pytest.raises(ValueError): normalize_operation_key(' ')
    with pytest.raises(ValueError): normalize_operation_key('x\n')
    with pytest.raises(ValueError): IdempotencyStore('/tmp/x').record('k',{},status='wat')

def test_fingerprint_stable():
    assert fingerprint({'b':2,'a':1}) == fingerprint({'a':1,'b':2})
