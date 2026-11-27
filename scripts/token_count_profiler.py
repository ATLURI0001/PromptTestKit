"""PromptTestKit: prompt token count profiler."""
import time


def profile_token_count(texts: list[str], rounds: int = 100) -> dict:
    """Rough token count profiler (whitespace split)."""
    start = time.monotonic()
    total = 0
    for _ in range(rounds):
        total += sum(len(t.split()) for t in texts)
    elapsed = time.monotonic() - start
    return {"elapsed_s": elapsed, "total_tokens": total}
