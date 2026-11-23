"""Prompt Evaluation Latency Profiler & Token Drift Degradation Diagnostic.

Tracks real-time prompt evaluation latencies, completion token velocities,
token expansion/compression drift, and degradation alarms across LLM test suites.
"""

from __future__ import annotations

import math
import threading
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional


class DriftDirection(str, Enum):
    EXPANSION = "EXPANSION"
    COMPRESSION = "COMPRESSION"
    STABLE = "STABLE"


class EvalHealthState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"


@dataclass
class EvalMetricRecord:
    eval_id: str
    suite_id: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    timestamp: float
    error: bool = False

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def tokens_per_sec(self) -> float:
        if self.latency_ms <= 0:
            return 0.0
        return (self.completion_tokens / (self.latency_ms / 1000.0))


@dataclass
class TelemetryReport:
    suite_id: str
    sample_count: int
    health_state: EvalHealthState
    p50_latency_ms: float
    p90_latency_ms: float
    p99_latency_ms: float
    mean_completion_tokens: float
    drift_direction: DriftDirection
    drift_percentage: float
    avg_tokens_per_sec: float
    error_rate: float


class PromptBenchmarkTelemetryProfiler:
    """Thread-safe latency profiler and token drift degradation tracker."""

    def __init__(
        self,
        suite_id: str,
        baseline_completion_tokens: float = 150.0,
        max_samples: int = 1000,
        drift_threshold_pct: float = 25.0,
        latency_p90_limit_ms: float = 1500.0,
    ) -> None:
        if not suite_id or not isinstance(suite_id, str):
            raise ValueError("suite_id must be a non-empty string")
        if baseline_completion_tokens <= 0:
            raise ValueError("baseline_completion_tokens must be positive")

        self.suite_id = suite_id.strip()
        self.baseline_tokens = float(baseline_completion_tokens)
        self.max_samples = max_samples
        self.drift_threshold_pct = drift_threshold_pct
        self.latency_p90_limit_ms = latency_p90_limit_ms

        self._lock = threading.Lock()
        self._history: Deque[EvalMetricRecord] = deque(maxlen=max_samples)
        self._total_recorded = 0

    def record_eval(
        self,
        eval_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
        timestamp: float,
        error: bool = False,
    ) -> EvalMetricRecord:
        """Records a single prompt evaluation observation."""
        if not eval_id or not isinstance(eval_id, str):
            raise ValueError("eval_id must be a non-empty string")
        if prompt_tokens < 0 or completion_tokens < 0:
            raise ValueError("Token counts cannot be negative")
        if latency_ms < 0:
            raise ValueError("latency_ms cannot be negative")

        rec = EvalMetricRecord(
            eval_id=eval_id.strip(),
            suite_id=self.suite_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            timestamp=timestamp,
            error=error,
        )

        with self._lock:
            self._history.append(rec)
            self._total_recorded += 1

        return rec

    def get_percentiles(self) -> Dict[str, float]:
        """Calculates P50, P90, P99 latencies across recorded samples."""
        with self._lock:
            if not self._history:
                return {"p50": 0.0, "p90": 0.0, "p99": 0.0, "mean": 0.0}
            latencies = sorted(r.latency_ms for r in self._history)

        n = len(latencies)
        p50 = latencies[int(n * 0.50)]
        p90 = latencies[min(int(n * 0.90), n - 1)]
        p99 = latencies[min(int(n * 0.99), n - 1)]
        mean = sum(latencies) / n

        return {
            "p50": round(p50, 2),
            "p90": round(p90, 2),
            "p99": round(p99, 2),
            "mean": round(mean, 2),
        }

    def generate_report(self) -> TelemetryReport:
        """Generates comprehensive telemetry health snapshot and drift diagnostic."""
        with self._lock:
            records = list(self._history)

        if not records:
            return TelemetryReport(
                suite_id=self.suite_id,
                sample_count=0,
                health_state=EvalHealthState.HEALTHY,
                p50_latency_ms=0.0,
                p90_latency_ms=0.0,
                p99_latency_ms=0.0,
                mean_completion_tokens=0.0,
                drift_direction=DriftDirection.STABLE,
                drift_percentage=0.0,
                avg_tokens_per_sec=0.0,
                error_rate=0.0,
            )

        pcts = self.get_percentiles()
        p50 = pcts["p50"]
        p90 = pcts["p90"]
        p99 = pcts["p99"]

        total_comp_tokens = sum(r.completion_tokens for r in records)
        mean_comp_tokens = total_comp_tokens / len(records)

        drift_diff = mean_comp_tokens - self.baseline_tokens
        drift_pct = (drift_diff / self.baseline_tokens) * 100.0

        if abs(drift_pct) < 10.0:
            direction = DriftDirection.STABLE
        elif drift_pct > 0:
            direction = DriftDirection.EXPANSION
        else:
            direction = DriftDirection.COMPRESSION

        valid_speeds = [r.tokens_per_sec for r in records if r.tokens_per_sec > 0]
        avg_speed = sum(valid_speeds) / len(valid_speeds) if valid_speeds else 0.0

        error_count = sum(1 for r in records if r.error)
        error_rate = error_count / len(records)

        # Health state determination
        if error_rate > 0.15 or p90 > (self.latency_p90_limit_ms * 1.5) or abs(drift_pct) > (self.drift_threshold_pct * 2.0):
            health = EvalHealthState.CRITICAL
        elif error_rate > 0.05 or p90 > self.latency_p90_limit_ms or abs(drift_pct) > self.drift_threshold_pct:
            health = EvalHealthState.DEGRADED
        else:
            health = EvalHealthState.HEALTHY

        return TelemetryReport(
            suite_id=self.suite_id,
            sample_count=len(records),
            health_state=health,
            p50_latency_ms=p50,
            p90_latency_ms=p90,
            p99_latency_ms=p99,
            mean_completion_tokens=round(mean_comp_tokens, 2),
            drift_direction=direction,
            drift_percentage=round(drift_pct, 2),
            avg_tokens_per_sec=round(avg_speed, 2),
            error_rate=round(error_rate, 4),
        )

    def format_markdown_report(self) -> str:
        """Formats the current diagnostic telemetry into a structured markdown report."""
        rep = self.generate_report()
        return (
            f"### Benchmark Telemetry Diagnostic Report ({rep.suite_id})\n\n"
            f"- **Health State**: `{rep.health_state.value}`\n"
            f"- **Evaluations Sampled**: {rep.sample_count}\n"
            f"- **Latency (ms)**: P50: {rep.p50_latency_ms}ms | P90: {rep.p90_latency_ms}ms | P99: {rep.p99_latency_ms}ms\n"
            f"- **Token Velocity**: {rep.avg_tokens_per_sec} tokens/sec\n"
            f"- **Token Drift**: {rep.drift_percentage:+.1f}% ({rep.drift_direction.value}) relative to baseline ({self.baseline_tokens} tokens)\n"
            f"- **Error Rate**: {rep.error_rate * 100:.2f}%\n"
        )
