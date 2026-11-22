"""Unit tests for Test Suite Specification Ingress Contract and Assertion Sanitizer."""

import unittest
from scripts.test_suite_contract import (
    validate_and_sanitize_test_suite,
)


class TestTestSuiteContract(unittest.TestCase):
    def test_valid_suite_contract(self) -> None:
        raw_suite = {
            "suite_id": "math-reasoning-v1",
            "name": "Mathematical Reasoning Baseline",
            "model_target": "claude-3-5-sonnet",
            "test_cases": [
                {
                    "test_id": "case-addition-01",
                    "prompt": "What is 123 + 456? \u200B",  # zero-width space to strip
                    "system_instructions": "Answer concisely with the integer only.",
                    "timeout_seconds": 15,
                    "tags": ["math", "arithmetic"],
                    "assertions": [
                        {"type": "contains", "target": "output", "value": "579"},
                        {"type": "length_between", "target": "output", "value": [1, 20]},
                    ],
                }
            ],
        }

        res = validate_and_sanitize_test_suite(raw_suite)
        self.assertTrue(res.valid, f"Expected valid, got violations: {res.violations}")
        self.assertIsNotNone(res.sanitized_contract)

        contract = res.sanitized_contract
        self.assertEqual(contract.suite_id, "math-reasoning-v1")
        self.assertEqual(contract.name, "Mathematical Reasoning Baseline")
        self.assertEqual(len(contract.test_cases), 1)

        case = contract.test_cases[0]
        self.assertEqual(case.test_id, "case-addition-01")
        self.assertEqual(case.prompt, "What is 123 + 456?")  # zero-width stripped
        self.assertEqual(case.timeout_seconds, 15)
        self.assertEqual(len(case.assertions), 2)

    def test_suite_id_validation_rules(self) -> None:
        # 1. Empty suite_id
        res1 = validate_and_sanitize_test_suite({"suite_id": "", "name": "Test", "test_cases": []})
        self.assertFalse(res1.valid)
        self.assertTrue(any(v.rule == "required" for v in res1.violations))

        # 2. Invalid chars in suite_id
        res2 = validate_and_sanitize_test_suite({
            "suite_id": "invalid!@#id",
            "name": "Test",
            "test_cases": [{"test_id": "t1", "prompt": "hi", "assertions": [{"type": "contains", "value": "hi"}]}],
        })
        self.assertFalse(res2.valid)
        self.assertTrue(any(v.rule == "invalid_format" for v in res2.violations))

    def test_duplicate_test_ids_rejected(self) -> None:
        raw = {
            "suite_id": "duplicate-check",
            "name": "Dup Check",
            "test_cases": [
                {"test_id": "test-alpha", "prompt": "q1", "assertions": [{"type": "contains", "value": "a"}]},
                {"test_id": "test-alpha", "prompt": "q2", "assertions": [{"type": "contains", "value": "b"}]},
            ],
        }
        res = validate_and_sanitize_test_suite(raw)
        self.assertFalse(res.valid)
        self.assertTrue(any(v.rule == "duplicate" for v in res.violations))

    def test_assertion_type_whitelisting(self) -> None:
        raw = {
            "suite_id": "assertion-check",
            "name": "Assert Check",
            "test_cases": [
                {
                    "test_id": "test-1",
                    "prompt": "hi",
                    "assertions": [{"type": "unsupported_magic_op", "value": "magic"}],
                }
            ],
        }
        res = validate_and_sanitize_test_suite(raw)
        self.assertFalse(res.valid)
        self.assertTrue(any(v.rule == "unsupported_type" for v in res.violations))

    def test_timeout_bounds_validation(self) -> None:
        # Negative timeout
        raw = {
            "suite_id": "timeout-check",
            "name": "Timeout",
            "test_cases": [
                {
                    "test_id": "test-1",
                    "prompt": "hi",
                    "timeout_seconds": -5,
                    "assertions": [{"type": "contains", "value": "hi"}],
                }
            ],
        }
        self.assertFalse(validate_and_sanitize_test_suite(raw).valid)

        # Huge timeout (>300s)
        raw["test_cases"][0]["timeout_seconds"] = 500
        self.assertFalse(validate_and_sanitize_test_suite(raw).valid)

    def test_prototype_pollution_detection(self) -> None:
        raw = {
            "suite_id": "pollution-suite",
            "name": "Pollution",
            "__proto__": {"injected": True},
            "test_cases": [
                {"test_id": "t1", "prompt": "hi", "assertions": [{"type": "contains", "value": "hi"}]}
            ],
        }
        res = validate_and_sanitize_test_suite(raw)
        self.assertFalse(res.valid)
        self.assertTrue(any(v.rule == "prototype_pollution" for v in res.violations))


if __name__ == "__main__":
    unittest.main()
