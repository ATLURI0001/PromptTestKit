"""Circuit breaker for LLM judge evaluation calls."""
import time


class JudgeCircuitOpenError(RuntimeError):
    """Raised when the LLM judge circuit breaker is open."""


class LlmJudgeCircuitBreaker:
    """Protects evaluation runs from failing LLM judge endpoints."""

    def __init__(self, failure_threshold: int = 3, cooldown_s: float = 15.0) -> None:
        self.failure_threshold = failure_threshold
        self.cooldown_s = cooldown_s
        self.failures = 0
        self.open_until = 0.0

    def call(self, fn):
        if time.monotonic() < self.open_until:
            raise JudgeCircuitOpenError("LLM judge circuit open")
        try:
            res = fn()
        except Exception:
            self.failures += 1
            if self.failures >= self.failure_threshold:
                self.open_until = time.monotonic() + self.cooldown_s
                self.failures = 0
            raise
        self.failures = 0
        return res
