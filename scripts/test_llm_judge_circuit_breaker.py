"""Tests for LlmJudgeCircuitBreaker."""
import pytest
from scripts.llm_judge_circuit_breaker import JudgeCircuitOpenError, LlmJudgeCircuitBreaker


def test_judge_circuit_opens_after_failures():
    cb = LlmJudgeCircuitBreaker(failure_threshold=2, cooldown_s=10.0)
    with pytest.raises(TimeoutError):
        cb.call(lambda: (_ for _ in ()).throw(TimeoutError("timeout")))
    with pytest.raises(TimeoutError):
        cb.call(lambda: (_ for _ in ()).throw(TimeoutError("timeout")))
    with pytest.raises(JudgeCircuitOpenError):
        cb.call(lambda: "ok")
