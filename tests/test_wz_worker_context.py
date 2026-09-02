import pytest
from authorized_assessment.orchestration.worker_context import WorkerContext
from authorized_assessment.orchestration.wz_routes import validate_artifact_ref


def test_wz_context_is_frozen_and_cursor_bound():
    context = WorkerContext("wz", "graphql_mapping", "phase_status.json", facts=("fact",), coverage={"x": 1})
    assert context.as_dict()["cursor_file"] == "phase_status.json"
    with pytest.raises(TypeError):
        context.coverage["x"] = 2
    with pytest.raises(ValueError):
        WorkerContext("wz", "graphql_mapping", "phase_status.miniapp.json")


def test_wz_context_rejects_sensitive_inputs():
    with pytest.raises(ValueError):
        WorkerContext("wz", "x", "phase_status.json", facts=("token=hidden",))


def test_artifact_scope_rejects_cross_workflow_and_raw_paths():
    assert validate_artifact_ref("artifacts/application-map/graphql-manifest.json") == []
    assert validate_artifact_ref("runs/old/result.json")
    assert validate_artifact_ref("evidence/raw/item.json")
    assert validate_artifact_ref("artifacts/input-testing/input.json", phase="product_triage")
