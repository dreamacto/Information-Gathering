import pytest
from authorized_assessment.orchestration.worker_context import WorkerContext

def test_wz_xcx_cursor_isolation():
    assert WorkerContext("wz","scope","phase_status.json").cursor_file=="phase_status.json"
    assert WorkerContext("xcx","auth","phase_status.miniapp.json").cursor_file=="phase_status.miniapp.json"
    with pytest.raises(ValueError): WorkerContext("wz","scope","phase_status.miniapp.json")

def test_sensitive_context_rejected():
    with pytest.raises(ValueError): WorkerContext("wz","scope","phase_status.json",facts=("token=bad",))
    with pytest.raises(ValueError): WorkerContext("wz","scope","phase_status.json",coverage={"password":"x"})

def test_snapshot_and_readonly_copy():
    c=WorkerContext.from_snapshot({"workflow":"wz","phase":"scope","current_facts":["safe"],"coverage":{"done":1}})
    assert c.as_dict()["facts"]==["safe"]
    with pytest.raises(TypeError): c.coverage["x"]=1
