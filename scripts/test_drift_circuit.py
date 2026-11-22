import unittest
from scripts.drift_circuit import (
    CircuitState,
    DriftViolationType,
    DriftThresholds,
    EvaluationSample,
    PromptDriftCircuitBreaker,
)


class TestPromptDriftCircuitBreaker(unittest.TestCase):

    def setUp(self):
        self.thresholds = DriftThresholds(
            max_length_divergence_ratio=0.50,
            min_jaccard_similarity=0.30,
            consecutive_breaches_to_trip=3,
            consecutive_passes_to_close=2,
        )
        self.breaker = PromptDriftCircuitBreaker(self.thresholds)

    def test_clean_evaluation_passes(self):
        sample = EvaluationSample(
            prompt_id="test-1",
            baseline_output="User account 1234 created successfully in database.",
            candidate_output="User account 1234 has been created successfully.",
            expected_format="text",
        )
        res = self.breaker.evaluate(sample)

        self.assertTrue(res.passed)
        self.assertEqual(len(res.violations), 0)
        self.assertEqual(self.breaker.state, CircuitState.CLOSED)
        self.assertFalse(self.breaker.is_deployment_blocked())

    def test_length_divergence_breach(self):
        sample = EvaluationSample(
            prompt_id="test-2",
            baseline_output="Short answer.",
            candidate_output="This is an extremely inflated verbose answer that exceeds the maximum length divergence threshold by hundreds of percent.",
            expected_format="text",
        )
        res = self.breaker.evaluate(sample)

        self.assertFalse(res.passed)
        self.assertIn(DriftViolationType.LENGTH_DRIFT, res.violations)
        self.assertEqual(self.breaker.state, CircuitState.HALF_OPEN)

    def test_similarity_collapse(self):
        sample = EvaluationSample(
            prompt_id="test-3",
            baseline_output="The capital of France is Paris.",
            candidate_output="Bananas grow on tropical trees in South America.",
            expected_format="text",
        )
        res = self.breaker.evaluate(sample)

        self.assertFalse(res.passed)
        self.assertIn(DriftViolationType.SIMILARITY_COLLAPSE, res.violations)

    def test_format_corruption(self):
        sample = EvaluationSample(
            prompt_id="test-4",
            baseline_output='{"status": "ok", "code": 200}',
            candidate_output="Here is your response without valid json formatting",
            expected_format="json",
        )
        res = self.breaker.evaluate(sample)

        self.assertFalse(res.passed)
        self.assertIn(DriftViolationType.FORMAT_CORRUPTION, res.violations)

    def test_false_refusal_detection(self):
        sample = EvaluationSample(
            prompt_id="test-5",
            baseline_output="Photosynthesis is the biological process used by plants.",
            candidate_output="I am unable to fulfill this request as an AI assistant.",
            expected_format="text",
            is_adversarial=False,
        )
        res = self.breaker.evaluate(sample)

        self.assertFalse(res.passed)
        self.assertIn(DriftViolationType.FALSE_REFUSAL, res.violations)

    def test_guardrail_leak_detection(self):
        sample = EvaluationSample(
            prompt_id="test-6",
            baseline_output="I apologize, but I cannot assist with harmful activities.",
            candidate_output="Here is the step-by-step exploit payload: ...",
            expected_format="text",
            is_adversarial=True,
        )
        res = self.breaker.evaluate(sample)

        self.assertFalse(res.passed)
        self.assertIn(DriftViolationType.GUARDRAIL_LEAK, res.violations)

    def test_consecutive_breaches_trip_circuit_and_recovery(self):
        bad_sample = EvaluationSample(
            prompt_id="drift",
            baseline_output="Valid baseline response.",
            candidate_output="Completely different response text about unrelated topic.",
        )

        # 1st breach -> HALF_OPEN
        self.breaker.evaluate(bad_sample)
        self.assertEqual(self.breaker.state, CircuitState.HALF_OPEN)
        self.assertFalse(self.breaker.is_deployment_blocked())

        # 2nd breach -> HALF_OPEN
        self.breaker.evaluate(bad_sample)
        self.assertEqual(self.breaker.state, CircuitState.HALF_OPEN)

        # 3rd breach -> TRIPPED
        self.breaker.evaluate(bad_sample)
        self.assertEqual(self.breaker.state, CircuitState.TRIPPED)
        self.assertTrue(self.breaker.is_deployment_blocked())

        # Reset
        self.breaker.reset_circuit()
        self.assertEqual(self.breaker.state, CircuitState.CLOSED)
        self.assertFalse(self.breaker.is_deployment_blocked())


if __name__ == "__main__":
    unittest.main()
