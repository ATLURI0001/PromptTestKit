"""Tests for token_throughput_profiler."""
import sys
sys.path.insert(0, "scripts")
from token_throughput_profiler import TokenThroughputProfiler


def test_token_throughput_profiler():
    p = TokenThroughputProfiler()
    p.record(42.0); p.record(18.5)
    assert p.min_rate() == 18.5
