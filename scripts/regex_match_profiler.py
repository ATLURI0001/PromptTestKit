"""Regex assertion throughput profiler."""
import re
import time


def benchmark_regex_match(pattern: str, text: str, iterations: int = 500) -> float:
    compiled = re.compile(pattern)
    start = time.perf_counter()
    for _ in range(iterations):
        _ = compiled.search(text)
    elapsed = max(time.perf_counter() - start, 1e-9)
    return round(iterations / elapsed, 2)
