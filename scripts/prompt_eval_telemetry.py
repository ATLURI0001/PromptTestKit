"""
Prompt Evaluation Latency & Pass-Rate Telemetry Rotary.

Thread-safe rotary buffer tracking LLM evaluation latencies, pass rates,
breach frequencies, token throughput, and OpenMetrics Prometheus exports.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional, Tuple


class EvalStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BREACH = "BREACH"
    ERROR = "ERROR"


@dataclass(frozen=True)
class EvalRecord:
    prompt_id: str
    model_id: str
    eval_latency_ms: float
    token_count: int
    status: EvalStatus
    timestamp: float


@dataclass
class EvalTelemetrySummary:
    total_evals: int
    pass_rate_pct: float
    breach_rate_pct: float
    error_rate_pct: float
    p50_latency_ms: float
    p90_latency_ms: float
    p99_latency_ms: float
    mean_latency_ms: float
    total_tokens: int
    tokens_per_second: float
    model_breakdown: Dict[str, Dict[str, float]]


class PromptEvalLatencyRotary:
    """Thread-safe circular ring buffer tracking prompt evaluation latency and outcomes."""

    def __init__(self, capacity: int = 2000) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._lock = threading.Lock()
        self._buffer: Deque[EvalRecord] = deque(maxlen=capacity)
        self._total_recorded = 0

    def record_evaluation(
        self,
        prompt_id: str,
        model_id: str,
        eval_latency_ms: float,
        token_count: int,
        status: EvalStatus = EvalStatus.PASS,
        timestamp: Optional[float] = None,
    ) -> EvalRecord:
        """Records an evaluation record into the rotary buffer."""
        if not prompt_id:
            raise ValueError("prompt_id cannot be empty")
        if not model_id:
            raise ValueError("model_id cannot be empty")
        if eval_latency_ms < 0:
            raise ValueError("eval_latency_ms must be non-negative")
        if token_count < 0:
            raise ValueError("token_count must be non-negative")

        ts = timestamp if timestamp is not None else time.time()
        record = EvalRecord(
            prompt_id=prompt_id,
            model_id=model_id,
            eval_latency_ms=float(eval_latency_ms),
            token_count=int(token_count),
            status=status,
            timestamp=ts,
        )

        with self._lock:
            self._buffer.append(record)
            self._total_recorded += 1

        return record

    def _percentile(self, sorted_vals: List[float], pct: float) -> float:
        if not sorted_vals:
            return 0.0
        idx = int(math.ceil(pct * len(sorted_vals))) - 1
        return sorted_vals[max(0, min(idx, len(sorted_vals) - 1))]

    def get_summary(self) -> EvalTelemetrySummary:
        """Calculates pass-rate, breach percentages, and latency quantiles."""
        with self._lock:
            records = list(self._buffer)

        if not records:
            return EvalTelemetrySummary(
                total_evals=0,
                pass_rate_pct=0.0,
                breach_rate_pct=0.0,
                error_rate_pct=0.0,
                p50_latency_ms=0.0,
                p90_latency_ms=0.0,
                p99_latency_ms=0.0,
                mean_latency_ms=0.0,
                total_tokens=0,
                tokens_per_second=0.0,
                model_breakdown={},
            )

        n = len(records)
        pass_count = sum(1 for r in records if r.status == EvalStatus.PASS)
        breach_count = sum(1 for r in records if r.status == EvalStatus.BREACH)
        error_count = sum(1 for r in records if r.status == EvalStatus.ERROR)

        latencies = sorted(r.eval_latency_ms for r in records)
        p50 = self._percentile(latencies, 0.50)
        p90 = self._percentile(latencies, 0.90)
        p99 = self._percentile(latencies, 0.99)
        mean_lat = sum(latencies) / n

        total_tokens = sum(r.token_count for r in records)
        time_span = max(0.001, records[-1].timestamp - records[0].timestamp) if n > 1 else 1.0
        tps = total_tokens / time_span if time_span > 0 else float(total_tokens)

        # Per model metrics
        model_groups: Dict[str, List[EvalRecord]] = {}
        for r in records:
            model_groups.setdefault(r.model_id, []).append(r)

        breakdown: Dict[str, Dict[str, float]] = {}
        for m_id, m_recs in model_groups.items():
            m_pass = sum(1 for r in m_recs if r.status == EvalStatus.PASS)
            m_mean_lat = sum(r.eval_latency_ms for r in m_recs) / len(m_recs)
            breakdown[m_id] = {
                "count": float(len(m_recs)),
                "pass_rate_pct": round((m_pass / len(m_recs)) * 100.0, 2),
                "mean_latency_ms": round(m_mean_lat, 2),
            }

        return EvalTelemetrySummary(
            total_evals=n,
            pass_rate_pct=round((pass_count / n) * 100.0, 2),
            breach_rate_pct=round((breach_count / n) * 100.0, 2),
            error_rate_pct=round((error_count / n) * 100.0, 2),
            p50_latency_ms=round(p50, 2),
            p90_latency_ms=round(p90, 2),
            p99_latency_ms=round(p99, 2),
            mean_latency_ms=round(mean_lat, 2),
            total_tokens=total_tokens,
            tokens_per_second=round(tps, 2),
            model_breakdown=breakdown,
        )

    def export_prometheus_metrics(self) -> str:
        """Emits Prometheus OpenMetrics text format."""
        summary = self.get_summary()
        lines = [
            "# HELP prompt_eval_total Total prompt evaluations recorded in buffer",
            "# TYPE prompt_eval_total counter",
            f"prompt_eval_total {summary.total_evals}",
            "# HELP prompt_eval_pass_rate_pct Evaluation pass rate percentage",
            "# TYPE prompt_eval_pass_rate_pct gauge",
            f"prompt_eval_pass_rate_pct {summary.pass_rate_pct}",
            "# HELP prompt_eval_latency_p90_ms 90th percentile evaluation latency in ms",
            "# TYPE prompt_eval_latency_p90_ms gauge",
            f"prompt_eval_latency_p90_ms {summary.p90_latency_ms}",
            "# HELP prompt_eval_tokens_total Cumulative tokens evaluated",
            "# TYPE prompt_eval_tokens_total counter",
            f"prompt_eval_tokens_total {summary.total_tokens}",
        ]
        for m_id, stats in summary.model_breakdown.items():
            lines.append(f'prompt_eval_model_pass_rate{{model="{m_id}"}} {stats["pass_rate_pct"]}')
        return "\n".join(lines) + "\n"
