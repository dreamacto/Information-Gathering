from authorized_assessment.runtime.task_lineage import create_task, next_retry, validate_lineage

def test_retry_is_monotonic_and_immutable():
    first=create_task(task_id='t1',assessment_id='a',workflow='w',correlation_id='c'); first['status']='failed'; first['error']='timeout'
    retry=next_retry(first,task_id='t2',error='timeout')
    assert retry['attempt_no']==2 and retry['retry_of']=='t1' and retry['parent_id']=='t1'
    assert first['task_id']=='t1' and validate_lineage([first,retry])['ok']

def test_cross_workflow_and_self_loop_fail_closed():
    a=create_task(task_id='a',assessment_id='assess',workflow='w'); b=create_task(task_id='b',assessment_id='assess',workflow='other'); b['parent_id']='a'
    assert not validate_lineage([a,b])['ok']
    c=create_task(task_id='c',assessment_id='assess',workflow='w'); c['parent_id']='c'
    assert 'self_loop' in validate_lineage([c])['errors']

def test_non_retryable_cancelled_and_blocked():
    for status in ('cancelled','blocked','complete'):
        node=create_task(task_id='t',assessment_id='a',workflow='w'); node['status']=status
        assert next_retry(node,task_id='t2',error='x')['status']=='blocked'

def test_attempt_gap_rejected():
    a=create_task(task_id='a',assessment_id='assess',workflow='w'); a['status']='failed'; a['error']='x'
    b=next_retry(a,task_id='b',error='x'); b['attempt_no']=3
    assert not validate_lineage([a,b])['ok']
