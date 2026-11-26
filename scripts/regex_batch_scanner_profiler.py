"""Regex Batch Scanner & Aho-Corasick Prefix Filter Benchmark Profiler.

Benchmarks compiled regex union scanning vs uncompiled sequential rule matching
across batched adversarial prompt datasets.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import List, Pattern


@dataclass
class ScannerBenchmarkResult:
    rule_count: int
    prompt_count: int
    p50_microseconds: float
    p90_microseconds: float
    p99_microseconds: float
    throughput_prompts_sec: float


class RegexBatchScannerProfiler:
    """Profiles compiled union regex matching performance on prompt batches."""

    def __init__(self, patterns: List[str]) -> None:
        if not patterns:
            raise ValueError("Patterns list cannot be empty")
        self.patterns = patterns
        combined = "|".join(f"(?:{p})" for p in patterns)
        self.compiled_union: Pattern[str] = re.compile(combined, re.IGNORECASE)

    def scan_batch(self, prompts: List[str]) -> int:
        matches = 0
        for p in prompts:
            if self.compiled_union.search(p):
                matches += 1
        return matches

    def run_benchmark(self, prompts: List[str], iterations: int = 40) -> ScannerBenchmarkResult:
        if not prompts:
            raise ValueError("Prompts list cannot be empty")

        latencies_micros: List[float] = []
        start_total = time.perf_counter()

        for _ in range(iterations):
            start = time.perf_counter()
            self.scan_batch(prompts)
            elapsed_micros = (time.perf_counter() - start) * 1_000_000.0 / len(prompts)
            latencies_micros.append(elapsed_micros)

        total_elapsed_sec = time.perf_counter() - start_total
        latencies_micros.sort()

        p50 = latencies_micros[int(len(latencies_micros) * 0.5)]
        p90 = latencies_micros[int(len(latencies_micros) * 0.9)]
        p99 = latencies_micros[int(len(latencies_micros) * 0.99)]

        total_prompts = len(prompts) * iterations
        throughput = total_prompts / total_elapsed_sec if total_elapsed_sec > 0 else 0.0

        return ScannerBenchmarkResult(
            rule_count=len(self.patterns),
            prompt_count=len(prompts),
            p50_microseconds=round(p50, 4),
            p90_microseconds=round(p90, 4),
            p99_microseconds=round(p99, 4),
            throughput_prompts_sec=round(throughput, 1),
        )
