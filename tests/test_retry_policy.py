from authorized_assessment.orchestration.retry_policy import decide_retry


def test_retry_timeout_then_exhaustion():
    assert decide_retry(error_class="timeout", attempt=1, retry_limit=1).retry
    assert decide_retry(error_class="timeout", attempt=2, retry_limit=1).status == "failed"


def test_non_retryable_is_blocked():
    assert decide_retry(error_class="permission_denied", attempt=1, retry_limit=3).status == "blocked"
    assert decide_retry(error_class="timeout", attempt=1, retry_limit=3, stop_active=True).status == "cancelled"


def test_invalid_values_fail_closed():
    assert decide_retry(error_class="timeout", attempt=0).status == "blocked"
    assert decide_retry(error_class="timeout", retry_limit=-1).status == "blocked"
