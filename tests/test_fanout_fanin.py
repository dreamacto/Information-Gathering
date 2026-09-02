from authorized_assessment.orchestration.fanout import expand_branches
from authorized_assessment.orchestration.fanin import collect_branches


def test_fanout_is_stable_and_reference_only():
    rows = expand_branches("task_parent", ["b", "a", "a"], correlation_id="corr", workflow="wz", cursor_file="phase_status.json")
    assert [row.branch_id for row in rows] == ["task_parent__a", "task_parent__b"]
    assert all(row.parent_id == "task_parent" and row.idempotency_key for row in rows)


def test_fanin_statuses():
    assert collect_branches("all", ["a", "b"], {"a":"ok", "b":"ok"}).ready
    assert collect_branches("all", ["a", "b"], {"a":"ok", "b":"timeout"}).status == "timeout"
    assert collect_branches("any", ["a", "b"], {"a":"ok"}).ready
