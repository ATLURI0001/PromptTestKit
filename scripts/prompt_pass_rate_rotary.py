"""Prompt Regression Pass-Rate & Assertion Latency Telemetry Rotary."""

from __future__ import annotations

from typing import List, Optional, Tuple


class PromptPassRateRotary:
    def __init__(self, capacity: int = 200) -> None:
        self.capacity = max(1, capacity)
        self.buffer: List[Optional[Tuple[bool, float]]] = [None] * self.capacity
        self.head = 0
        self.count = 0

    def record(self, passed: bool, latency_ms: float) -> None:
        self.buffer[self.head] = (passed, latency_ms)
        self.head = (self.head + 1) % self.capacity
        if self.count < self.capacity:
            self.count += 1

    def get_pass_rate_pct(self) -> float:
        if self.count == 0:
            return 0.0
        wins = sum(1 for i in range(self.count) if self.buffer[i] and self.buffer[i][0])
        return round((wins / self.count) * 100.0, 2)
