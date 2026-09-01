from authorized_assessment.runtime.lease import LocalLeaseStore


def test_acquire_renew_release_and_hash(tmp_path):
    s=LocalLeaseStore(tmp_path/'lease.json')
    got=s.acquire('r','alice',10,token='secret',now=100)
    assert got['status']=='acquired' and got['token_hash'] != 'secret'
    assert s.inspect('r',now=105)['status']=='held'
    assert s.renew('r','alice',10,token='secret',now=105)['status']=='renewed'
    assert s.release('r','alice',token='secret',now=106)['status']=='released'
    assert s.inspect('r')['status']=='free'

def test_conflict_owner_expiry_and_ttl(tmp_path):
    s=LocalLeaseStore(tmp_path/'lease.json')
    assert s.acquire('r','a',0,token='x')['status']=='rejected'
    assert s.acquire('r','a',2,token='x',now=1)['ok']
    assert s.acquire('r','b',2,token='y',now=1)['status']=='conflict'
    assert s.renew('r','b',2,token='x',now=3)['status']=='expired'
    assert s.acquire('r','b',2,token='y',now=3)['status']=='acquired'

def test_bad_token_does_not_mutate(tmp_path):
    s=LocalLeaseStore(tmp_path/'lease.json'); s.acquire('r','a',10,token='x',now=1)
    assert s.release('r','a',token='wrong',now=2)['status']=='forbidden'
    assert s.inspect('r',now=2)['status']=='held'

def test_invalid_types_and_empty_resource_fail_closed(tmp_path):
    s=LocalLeaseStore(tmp_path/'lease.json')
    assert s.acquire('', 'a', 1, token='x')['reason'] == 'invalid_resource'
    assert s.acquire('r', 'a', 'not-a-number', token='x')['status'] == 'rejected'
    assert s.renew('r', 'a', None, token='x')['reason'] == 'invalid_ttl'
    assert s.acquire('r', 'a', 1, token='')['reason'] == 'invalid_token'
