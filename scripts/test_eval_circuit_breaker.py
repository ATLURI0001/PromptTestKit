"""Tests for eval_circuit_breaker."""
import sys
sys.path.insert(0, "scripts")
from eval_circuit_breaker import EvalCircuitBreaker


def test_eval_circuit_breaker():
    cb = EvalCircuitBreaker(threshold=2)
    assert cb.is_open() is False
    cb.record_failure(); cb.record_failure()
    assert cb.is_open() is True
