import pytest
from authorized_assessment.orchestration.worker_errors import make_error, is_retryable, from_exception

def test_retry_policy():
    assert is_retryable("timeout") is True
    assert is_retryable("permission_denied") is False
    assert is_retryable("blocked") is False
    assert is_retryable("scope_conflict") is False

def test_sensitive_error_text_rejected():
    with pytest.raises(ValueError): make_error(error_id="error_x",error_class="internal",safe_reason="traceback leaked",task_id="task_x",worker_id="worker_x")

def test_exception_is_redacted():
    e=from_exception(error_id="error_x",task_id="task_x",worker_id="worker_x",exc=RuntimeError("secret token"))
    assert e.redacted_detail=="RuntimeError"
    assert "token" not in str(e.as_dict()).lower()
