from scripts.latency_benchmark_profiler import profile_latency


def test_latency_benchmark_profiler():
    result = profile_latency(lambda: None, rounds=50)
    assert result["rounds"] == 50
    assert result["avg_ms"] >= 0
