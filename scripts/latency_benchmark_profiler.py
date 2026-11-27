"""PromptTestKit: latency benchmark profiler."""
import time


def profile_latency(fn, rounds: int = 100) -> dict:
    """Measure average call latency of fn over rounds calls."""
    start = time.monotonic()
    for _ in range(rounds):
        fn()
    elapsed = time.monotonic() - start
    return {"avg_ms": (elapsed / rounds) * 1000, "rounds": rounds}
