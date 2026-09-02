from datetime import datetime, timedelta, timezone
from authorized_assessment.orchestration.approval_interrupt import check_approval


def approval():
    now = datetime.now(timezone.utc).isoformat()
    return {"approval_id":"approval_demo","requested_action":"other_gated","assessment_id":"asmt","phase":"approval","target_ref":{"path":"target.json","sha256":"a"*64},"roe_ref":{"path":"roe.md","sha256":"b"*64},"script_gate":{"passed":True,"checked_at":now},"human_confirmation":{"confirmed":True,"confirmed_at":now},"decision":"approved","created_at":now}


def policy():
    return {"schema_version":"1.0","engagement_id":"asmt","workflow":"wz","phase":"approval","authorization_status":"confirmed","active_testing_authorized":False,"allowed_actions":["offline_analysis","other_gated"],"blocked_actions":["webshell"],"approval_required":["other_gated"],"rate_policy":{"same_host_delay_seconds":2,"same_host_concurrency":1,"cross_host_worker_limit":1},"stop_conditions":["operator_stop_request"],"source_hashes":{"roe":"b"*64},"generated_at":datetime.now(timezone.utc).isoformat(),"scope_confirmed":True,"stop_active":False}


def test_two_key_approval():
    result = check_approval(approval=approval(), policy_snapshot=policy(), required=True, assessment_id="asmt", phase="approval", target_ref={"path":"target.json","sha256":"a"*64})
    assert result.approved


def test_missing_and_stop_block():
    assert check_approval(approval=None, policy_snapshot=policy(), required=True).status == "approval_required"
    assert not check_approval(approval=approval(), policy_snapshot={**policy(), "stop_active":True}, required=True, assessment_id="asmt", phase="approval", target_ref={"path":"target.json","sha256":"a"*64}).approved
