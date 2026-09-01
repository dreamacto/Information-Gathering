from authorized_assessment.orchestration.worker_manifest import WorkerPermissions, WorkerLimits, build_manifest, validate_manifest
from authorized_assessment.orchestration.worker_registry import WorkerRegistry

def test_register_duplicate_and_snapshot():
    reg=WorkerRegistry(); m=build_manifest(worker_id="worker_code", worker_type="code", name="fake")
    reg.register(m, lambda ctx: {})
    assert reg.manifest("worker_code")==m
    assert [x.worker_id for x in reg.snapshot()]==["worker_code"]
    try: reg.register(m, lambda ctx: {})
    except ValueError: pass
    else: raise AssertionError("duplicate accepted")

def test_manifest_rejects_write_permissions():
    m=build_manifest(worker_id="worker_code", worker_type="code", name="fake")
    d=m.as_dict(); d["permissions"]["write_cursor"]=True
    assert any("write_cursor" in x for x in validate_manifest(d))

def test_empty_unregister():
    reg=WorkerRegistry(); assert reg.unregister("worker_none") is False
