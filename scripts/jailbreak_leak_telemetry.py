"""
Jailbreak Resistance Velocity & Canary Token Leak Telemetry Rotary.

Tracks adversarial attack vectors, jailbreak attempts, canary token leaks,
defense efficacy ratios, and OpenMetrics Prometheus exports across LLM evaluations.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional, Tuple


class AttackVector(str, Enum):
    ROLEPLAY_PROMPT = "ROLEPLAY_PROMPT"
    HYPOTHETICAL_SCENARIO = "HYPOTHETICAL_SCENARIO"
    BASE64_POLYGLOT = "BASE64_POLYGLOT"
    DELIMITER_ESCAPE = "DELIMITER_ESCAPE"
    AFFIRMATIVE_PRIMING = "AFFIRMATIVE_PRIMING"


class AttackOutcome(str, Enum):
    BLOCKED = "BLOCKED"
    LEAK_DETECTED = "LEAK_DETECTED"
    JAILBROKEN = "JAILBROKEN"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class AttackObservation:
    attack_id: str
    target_model: str
    vector: AttackVector
    outcome: AttackOutcome
    canary_leaked: bool
    latency_ms: float
    risk_score: float
    timestamp_sec: float


@dataclass
class JailbreakTelemetrySummary:
    total_attacks: int
    total_blocked: int
    total_leaks: int
    defense_efficacy_pct: float
    leak_rate_pct: float
    p50_risk_score: float
    p90_risk_score: float
    p99_risk_score: float
    mean_latency_ms: float
    attacks_per_second: float
    vector_breakdown: Dict[str, int]
    model_breakdown: Dict[str, Dict[str, float]]


class JailbreakTelemetryRotary:
    """
    Thread-safe circular telemetry buffer tracking jailbreak attempts,
    canary token leaks, and metric aggregates.
    """

    def __init__(self, capacity: int = 500) -> None:
        self.capacity = max(10, capacity)
        self._lock = threading.Lock()
        self._buffer: Deque[AttackObservation] = deque(maxlen=self.capacity)

    def record_attack(
        self,
        attack_id: str,
        target_model: str,
        vector: AttackVector | str,
        outcome: AttackOutcome | str,
        canary_leaked: bool = False,
        latency_ms: float = 0.0,
        risk_score: float = 0.0,
        timestamp_sec: Optional[float] = None,
    ) -> AttackObservation:
        if not attack_id or not isinstance(attack_id, str):
            raise ValueError("attack_id must be a non-empty string")
        if not target_model or not isinstance(target_model, str):
            raise ValueError("target_model must be a non-empty string")

        vec_enum = AttackVector(vector) if isinstance(vector, str) else vector
        out_enum = AttackOutcome(outcome) if isinstance(outcome, str) else outcome
        clamped_risk = max(0.0, min(1.0, float(risk_score)))
        ts = timestamp_sec if timestamp_sec is not None else time.time()

        obs = AttackObservation(
            attack_id=attack_id.strip(),
            target_model=target_model.strip().lower(),
            vector=vec_enum,
            outcome=out_enum,
            canary_leaked=bool(canary_leaked),
            latency_ms=max(0.0, float(latency_ms)),
            risk_score=clamped_risk,
            timestamp_sec=ts,
        )

        with self._lock:
            self._buffer.append(obs)
            return obs

    def get_summary(self) -> JailbreakTelemetrySummary:
        with self._lock:
            items = list(self._buffer)

        if not items:
            return JailbreakTelemetrySummary(
                total_attacks=0,
                total_blocked=0,
                total_leaks=0,
                defense_efficacy_pct=100.0,
                leak_rate_pct=0.0,
                p50_risk_score=0.0,
                p90_risk_score=0.0,
                p99_risk_score=0.0,
                mean_latency_ms=0.0,
                attacks_per_second=0.0,
                vector_breakdown={},
                model_breakdown={},
            )

        total = len(items)
        blocked = sum(1 for x in items if x.outcome == AttackOutcome.BLOCKED)
        leaks = sum(1 for x in items if x.canary_leaked or x.outcome == AttackOutcome.LEAK_DETECTED)
        defense_eff = (blocked / total) * 100.0
        leak_rate = (leaks / total) * 100.0

        risks = sorted(x.risk_score for x in items)
        p50_risk = risks[int(total * 0.50)]
        p90_risk = risks[min(total - 1, int(total * 0.90))]
        p99_risk = risks[min(total - 1, int(total * 0.99))]

        mean_lat = sum(x.latency_ms for x in items) / total

        span = items[-1].timestamp_sec - items[0].timestamp_sec
        aps = total / span if span > 0.001 else float(total)

        vec_counts: Dict[str, int] = {}
        model_stats: Dict[str, Dict[str, float]] = {}

        for x in items:
            vec_counts[x.vector.value] = vec_counts.get(x.vector.value, 0) + 1

            m = x.target_model
            if m not in model_stats:
                model_stats[m] = {"total": 0.0, "blocked": 0.0, "leaks": 0.0}
            model_stats[m]["total"] += 1.0
            if x.outcome == AttackOutcome.BLOCKED:
                model_stats[m]["blocked"] += 1.0
            if x.canary_leaked or x.outcome == AttackOutcome.LEAK_DETECTED:
                model_stats[m]["leaks"] += 1.0

        for m, stats in model_stats.items():
            tot = stats["total"]
            stats["defense_efficacy_pct"] = round((stats["blocked"] / tot) * 100.0, 2)
            stats["leak_rate_pct"] = round((stats["leaks"] / tot) * 100.0, 2)

        return JailbreakTelemetrySummary(
            total_attacks=total,
            total_blocked=blocked,
            total_leaks=leaks,
            defense_efficacy_pct=round(defense_eff, 2),
            leak_rate_pct=round(leak_rate, 2),
            p50_risk_score=round(p50_risk, 3),
            p90_risk_score=round(p90_risk, 3),
            p99_risk_score=round(p99_risk, 3),
            mean_latency_ms=round(mean_lat, 2),
            attacks_per_second=round(aps, 2),
            vector_breakdown=vec_counts,
            model_breakdown=model_stats,
        )

    def export_prometheus_metrics(self) -> str:
        lines: List[str] = [
            "# HELP prompttestkit_jailbreak_attacks_total Total adversarial attack attempts",
            "# TYPE prompttestkit_jailbreak_attacks_total counter",
        ]

        with self._lock:
            items = list(self._buffer)

        attack_counts: Dict[Tuple[str, str, str], int] = {}
        leak_counts: Dict[str, int] = {}

        for x in items:
            key = (x.target_model, x.vector.value, x.outcome.value)
            attack_counts[key] = attack_counts.get(key, 0) + 1
            if x.canary_leaked:
                leak_counts[x.target_model] = leak_counts.get(x.target_model, 0) + 1

        for (model, vec, out), count in attack_counts.items():
            lines.append(
                f'prompttestkit_jailbreak_attacks_total{{model="{model}",vector="{vec}",outcome="{out}"}} {count}'
            )

        lines.append(
            "# HELP prompttestkit_canary_leaks_total Total detected canary token exfiltrations"
        )
        lines.append("# TYPE prompttestkit_canary_leaks_total counter")
        for model, leaks in leak_counts.items():
            lines.append(
                f'prompttestkit_canary_leaks_total{{model="{model}"}} {leaks}'
            )

        summary = self.get_summary()
        lines.append(
            "# HELP prompttestkit_defense_efficacy_ratio Ratio of successfully blocked jailbreaks"
        )
        lines.append("# TYPE prompttestkit_defense_efficacy_ratio gauge")
        for model, stats in summary.model_breakdown.items():
            eff = stats.get("defense_efficacy_pct", 100.0) / 100.0
            lines.append(
                f'prompttestkit_defense_efficacy_ratio{{model="{model}"}} {eff:.4f}'
            )

        return "\n".join(lines) + "\n"
