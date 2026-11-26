"""Tests for eval_batch_profiler."""
from scripts.eval_batch_profiler import benchmark_eval_batch


def test_eval_batch_profiler():
    ops = benchmark_eval_batch(["hello world", "test prompt"], iterations=50)
    assert ops > 0
