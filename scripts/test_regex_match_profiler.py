"""Tests for regex_match_profiler."""
from scripts.regex_match_profiler import benchmark_regex_match


def test_regex_match_profiler():
    ops = benchmark_regex_match(r"\bpass\b", "status: pass", iterations=100)
    assert ops > 0
