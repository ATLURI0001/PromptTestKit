"""token_throughput_profiler.py – tracks prompt token throughput."""


class TokenThroughputProfiler:
    def __init__(self):
        self._rates: list[float] = []

    def record(self, tokens_per_sec: float) -> None:
        self._rates.append(tokens_per_sec)

    def min_rate(self) -> float:
        return min(self._rates) if self._rates else 0.0
