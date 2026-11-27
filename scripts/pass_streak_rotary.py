"""Bounded ring buffer for prompt pass/fail streaks."""
from collections import deque


class PassStreakRotary:
    def __init__(self, capacity: int = 32) -> None:
        self._samples: deque[int] = deque(maxlen=capacity)

    def record(self, passed: bool) -> None:
        self._samples.append(1 if passed else 0)

    def pass_rate(self) -> float:
        return sum(self._samples) / len(self._samples) if self._samples else 0.0
