"""Dynamic Prompt Injection Evaluation Telemetry & Attack Surface Diagnostic."""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class AttackCategory(str, Enum):
    JAILBREAK = "JAILBREAK"
    PROMPT_LEAK = "PROMPT_LEAK"
    ROLEPLAY_OVERRIDE = "ROLEPLAY_OVERRIDE"
    DELIMITER_INJECTION = "DELIMITER_INJECTION"
    CODE_INJECTION = "CODE_INJECTION"


class VulnerabilitySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_WEIGHTS: Dict[VulnerabilitySeverity, int] = {
    VulnerabilitySeverity.LOW: 1,
    VulnerabilitySeverity.MEDIUM: 2,
    VulnerabilitySeverity.HIGH: 5,
    VulnerabilitySeverity.CRITICAL: 10,
}


@dataclass
class EvalTelemetrySnapshot:
    suite_id: str
    total_evaluations: int
    total_breaches: int
    robustness_pct: float
    risk_index: int
    category_breach_rates: Dict[str, float]
    severity_breakdown: Dict[str, int]
    avg_latency_ms: float


class PromptEvalTelemetryCollector:
    """Thread-safe telemetry aggregator for adversarial LLM evaluation runs."""

    def __init__(self, suite_id: str) -> None:
        if not suite_id or not isinstance(suite_id, str):
            raise ValueError("suite_id must be a non-empty string")

        self.suite_id = suite_id
        self._lock = threading.Lock()
        self._total_evals = 0
        self._total_breaches = 0
        self._total_latency_ms = 0.0

        self._category_totals: Dict[str, int] = defaultdict(int)
        self._category_breaches: Dict[str, int] = defaultdict(int)
        self._severity_breaches: Dict[str, int] = defaultdict(int)

    def record_result(
        self,
        category: AttackCategory,
        severity: VulnerabilitySeverity,
        breached: bool,
        latency_ms: float = 0.0,
    ) -> None:
        """Records a single test evaluation outcome."""
        cat_key = category.value if isinstance(category, AttackCategory) else str(category)
        sev_key = severity.value if isinstance(severity, VulnerabilitySeverity) else str(severity)
        lat = max(0.0, float(latency_ms))

        with self._lock:
            self._total_evals += 1
            self._total_latency_ms += lat
            self._category_totals[cat_key] += 1

            if breached:
                self._total_breaches += 1
                self._category_breaches[cat_key] += 1
                self._severity_breaches[sev_key] += 1

    def get_snapshot(self) -> EvalTelemetrySnapshot:
        """Computes statistical metrics and weighted risk index."""
        with self._lock:
            total = self._total_evals
            breaches = self._total_breaches
            avg_lat = (self._total_latency_ms / total) if total > 0 else 0.0

            robustness = ((total - breaches) / total * 100.0) if total > 0 else 100.0

            # Calculate category rates
            cat_rates: Dict[str, float] = {}
            for cat, count in self._category_totals.items():
                b_count = self._category_breaches.get(cat, 0)
                cat_rates[cat] = round((b_count / count) * 100.0, 2) if count > 0 else 0.0

            # Calculate risk index
            risk_index = 0
            for sev_name, weight in SEVERITY_WEIGHTS.items():
                b_count = self._severity_breaches.get(sev_name.value, 0)
                risk_index += weight * b_count

            return EvalTelemetrySnapshot(
                suite_id=self.suite_id,
                total_evaluations=total,
                total_breaches=breaches,
                robustness_pct=round(robustness, 2),
                risk_index=risk_index,
                category_breach_rates=cat_rates,
                severity_breakdown=dict(self._severity_breaches),
                avg_latency_ms=round(avg_lat, 2),
            )

    def export_prometheus_metrics(self) -> str:
        """Formats active evaluation diagnostics in Prometheus text format."""
        snap = self.get_snapshot()
        lines = [
            "# HELP prompttestkit_eval_total Total prompt injection test evaluations",
            "# TYPE prompttestkit_eval_total counter",
            f'prompttestkit_eval_total{{suite_id="{self.suite_id}"}} {snap.total_evaluations}',
            "# HELP prompttestkit_breaches_total Total successful security breaches detected",
            "# TYPE prompttestkit_breaches_total counter",
            f'prompttestkit_breaches_total{{suite_id="{self.suite_id}"}} {snap.total_breaches}',
            "# HELP prompttestkit_robustness_pct Overall prompt defense robustness percentage",
            "# TYPE prompttestkit_robustness_pct gauge",
            f'prompttestkit_robustness_pct{{suite_id="{self.suite_id}"}} {snap.robustness_pct:.2f}',
            "# HELP prompttestkit_risk_index Weighted vulnerability severity risk score",
            "# TYPE prompttestkit_risk_index gauge",
            f'prompttestkit_risk_index{{suite_id="{self.suite_id}"}} {snap.risk_index}',
        ]
        return "\n".join(lines) + "\n"
