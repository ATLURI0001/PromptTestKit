"""Batch prompt evaluation throughput profiler."""
import time


def benchmark_eval_batch(prompts: list[str], iterations: int = 200) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        for p in prompts:
            _ = len(p.split())
    elapsed = max(time.perf_counter() - start, 1e-9)
    return round((iterations * len(prompts)) / elapsed, 2)
