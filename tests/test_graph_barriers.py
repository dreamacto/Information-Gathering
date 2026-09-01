from authorized_assessment.orchestration.graph_barriers import evaluate_barrier


def test_all_waits_for_every_success():
    assert not evaluate_barrier("all", ["a", "b"], {"a": "succeeded"}).ready
    assert evaluate_barrier("all", ["a", "b"], {"a": "succeeded", "b": "completed"}).ready


def test_any_accepts_one_success_but_not_empty_or_unknown():
    assert evaluate_barrier("any", ["a", "b"], {"a": "succeeded", "b": "blocked"}).ready
    assert not evaluate_barrier("any", ["a", "b"], {}).ready
    assert not evaluate_barrier("any", ["a"], {"a": "running"}).ready


def test_barrier_blocks_failure_timeout_cancel_and_permission():
    assert not evaluate_barrier("barrier", ["a", "b"], {"a": "succeeded", "b": "failed"}).ready
    assert evaluate_barrier("barrier", ["a", "b"], {"a": "succeeded", "b": "timeout"}).status == "timeout"
    assert evaluate_barrier("barrier", ["a", "b"], {"a": "cancelled", "b": "succeeded"}).status == "cancelled"
    assert not evaluate_barrier("barrier", ["a"], {"a": "permission_denied"}).ready


def test_missing_and_invalid_join_fail_closed():
    assert evaluate_barrier("all", ["a"], {}).reason == "missing branches"
    assert not evaluate_barrier("invalid", ["a"], {"a": "succeeded"}).ready
