"""Unit tests for Dynamic Prompt Injection Evaluation Telemetry."""

import threading
import unittest
from scripts.eval_telemetry import (
    PromptEvalTelemetryCollector,
    AttackCategory,
    VulnerabilitySeverity,
)


class TestPromptEvalTelemetry(unittest.TestCase):
    def test_initialization_and_validation(self):
        col = PromptEvalTelemetryCollector("suite-prod-v1")
        snap = col.get_snapshot()

        self.assertEqual(snap.suite_id, "suite-prod-v1")
        self.assertEqual(snap.total_evaluations, 0)
        self.assertEqual(snap.total_breaches, 0)
        self.assertEqual(snap.robustness_pct, 100.0)
        self.assertEqual(snap.risk_index, 0)

        with self.assertRaises(ValueError):
            PromptEvalTelemetryCollector("")

    def test_record_results_and_category_breakdown(self):
        col = PromptEvalTelemetryCollector("suite-rag-guard")

        # 10 Jailbreaks: 2 breached, 8 defended
        for _ in range(2):
            col.record_result(AttackCategory.JAILBREAK, VulnerabilitySeverity.CRITICAL, breached=True, latency_ms=120.0)
        for _ in range(8):
            col.record_result(AttackCategory.JAILBREAK, VulnerabilitySeverity.CRITICAL, breached=False, latency_ms=100.0)

        # 5 Prompt Leaks: 1 breached, 4 defended
        col.record_result(AttackCategory.PROMPT_LEAK, VulnerabilitySeverity.HIGH, breached=True, latency_ms=80.0)
        for _ in range(4):
            col.record_result(AttackCategory.PROMPT_LEAK, VulnerabilitySeverity.HIGH, breached=False, latency_ms=90.0)

        snap = col.get_snapshot()
        self.assertEqual(snap.total_evaluations, 15)
        self.assertEqual(snap.total_breaches, 3)

        # Robustness: (12 / 15) * 100 = 80.0%
        self.assertEqual(snap.robustness_pct, 80.0)

        # Category rates
        self.assertEqual(snap.category_breach_rates[AttackCategory.JAILBREAK.value], 20.0) # 2/10
        self.assertEqual(snap.category_breach_rates[AttackCategory.PROMPT_LEAK.value], 20.0) # 1/5

        # Risk Index: 2 Critical (2 * 10 = 20) + 1 High (1 * 5 = 5) = 25
        self.assertEqual(snap.risk_index, 25)

    def test_prometheus_export(self):
        col = PromptEvalTelemetryCollector("suite-prom-test")
        col.record_result(AttackCategory.CODE_INJECTION, VulnerabilitySeverity.HIGH, breached=True, latency_ms=50.0)

        prom = col.export_prometheus_metrics()
        self.assertIn('prompttestkit_eval_total{suite_id="suite-prom-test"} 1', prom)
        self.assertIn('prompttestkit_breaches_total{suite_id="suite-prom-test"} 1', prom)
        self.assertIn('prompttestkit_risk_index{suite_id="suite-prom-test"} 5', prom)

    def test_thread_safety(self):
        col = PromptEvalTelemetryCollector("suite-concurrency")
        threads = []
        num_threads = 5
        evals_per_thread = 40

        def worker():
            for i in range(evals_per_thread):
                breached = (i % 4 == 0)
                col.record_result(AttackCategory.ROLEPLAY_OVERRIDE, VulnerabilitySeverity.MEDIUM, breached=breached, latency_ms=25.0)
                _ = col.get_snapshot()

        for _ in range(num_threads):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        snap = col.get_snapshot()
        self.assertEqual(snap.total_evaluations, num_threads * evals_per_thread)


if __name__ == "__main__":
    unittest.main()
