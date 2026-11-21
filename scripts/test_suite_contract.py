"""
Unit tests for PromptTestKit Suite Contract Validator & Prompt Sanitizer.
"""

import unittest
from suite_contract import (
    validate_suite_manifest,
    sanitize_prompt_text,
)


class TestSuiteContract(unittest.TestCase):
    def test_valid_manifest(self):
        manifest = {
            "suite_id": "eval-suite-01",
            "name": "Safety Baseline Evaluation",
            "version": "1.2.0",
            "default_config": {
                "temperature": 0.5,
                "top_p": 0.9,
                "max_tokens": 1024,
                "timeout_sec": 45.0,
            },
            "test_cases": [
                {
                    "id": "tc_01",
                    "prompt": "Explain the concept of quantum superposition in simple terms.",
                    "tags": ["physics", "simple"],
                    "assertions": ["contains:coherent"],
                }
            ],
        }

        res = validate_suite_manifest(manifest)
        self.assertTrue(res.is_valid)
        self.assertIsNotNone(res.sanitized)
        self.assertEqual(res.sanitized["suite_id"], "eval-suite-01")
        self.assertEqual(len(res.sanitized["test_cases"]), 1)

    def test_invalid_manifest_fields(self):
        bad_manifest = {
            "suite_id": "invalid ID with spaces!!",
            "name": "",
            "version": "not-semver",
            "default_config": {
                "temperature": 5.0,  # out of bounds
                "top_p": -0.5,       # out of bounds
                "max_tokens": 0,     # out of bounds
            },
            "test_cases": [],
        }

        res = validate_suite_manifest(bad_manifest)
        self.assertFalse(res.is_valid)
        error_fields = {e.field for e in res.errors}
        self.assertIn("suite_id", error_fields)
        self.assertIn("name", error_fields)
        self.assertIn("version", error_fields)
        self.assertIn("default_config.temperature", error_fields)
        self.assertIn("default_config.top_p", error_fields)
        self.assertIn("default_config.max_tokens", error_fields)
        self.assertIn("test_cases", error_fields)

    def test_prompt_sanitization(self):
        dirty = "System instruction\x00\x08\u200Bwith hidden artifacts\ufeffand control chars\r\n"
        clean = sanitize_prompt_text(dirty)
        self.assertNotIn("\x00", clean)
        self.assertNotIn("\u200b", clean)
        self.assertNotIn("\ufeff", clean)
        self.assertNotIn("\r\n", clean)
        self.assertIn("System instructionwith hidden artifacts", clean)


if __name__ == "__main__":
    unittest.main()
