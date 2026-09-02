from __future__ import annotations

import pytest
from authorized_assessment.orchestration.worker_context import CURSOR_FILES, WorkerContext


def test_xcx_context_isolated_and_readonly():
    context = WorkerContext("xcx", "package_inventory", "phase_status.miniapp.json", facts=("package hash",), coverage={"done": 1})
    assert context.as_dict()["cursor_file"] == CURSOR_FILES["xcx"]
    with pytest.raises(TypeError):
        context.coverage["new"] = 2


@pytest.mark.parametrize("workflow,cursor", [("wz", "phase_status.miniapp.json"), ("xcx", "phase_status.json"), ("fh", "phase_status.miniapp.json")])
def test_context_rejects_cross_stream_cursor(workflow, cursor):
    with pytest.raises(ValueError):
        WorkerContext(workflow, "identity", cursor)


@pytest.mark.parametrize("payload", [
    {"token": "hidden"}, {"cookie": "hidden"}, {"authorization": "hidden"},
    {"nested": {"password": "hidden"}}, {"fact": "session=hidden"},
])
def test_context_rejects_sensitive_fields_and_values(payload):
    with pytest.raises(ValueError):
        WorkerContext("xcx", "identity", "phase_status.miniapp.json", coverage=payload)


def test_empty_and_invalid_context_inputs_fail_closed():
    with pytest.raises(ValueError):
        WorkerContext.from_snapshot({})
    with pytest.raises(ValueError):
        WorkerContext.from_snapshot({"workflow": "xcx", "phase": "", "current_facts": []})
    with pytest.raises(ValueError):
        WorkerContext("xcx", "", "phase_status.miniapp.json")
