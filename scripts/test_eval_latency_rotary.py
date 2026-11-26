"""Tests for EvalLatencyRotary."""
from scripts.eval_latency_rotary import EvalLatencyRotary


def test_eval_latency_rotary():
    r = EvalLatencyRotary(capacity=2)
    r.record(5.0)
    r.record(15.0)
    r.record(25.0)
    assert r.avg_ms() == 20.0
