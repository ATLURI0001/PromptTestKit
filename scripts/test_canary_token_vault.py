"""Unit tests for CanaryTokenVault."""

import unittest
from scripts.canary_token_vault import CanaryTokenVault


class TestCanaryTokenVault(unittest.TestCase):
    def setUp(self):
        self.vault = CanaryTokenVault(secret_key="test-secret-key", default_ttl_sec=3600)

    def test_issue_canary_format_and_uniqueness(self):
        c1 = self.vault.issue_canary(label="secret_key")
        c2 = self.vault.issue_canary(label="secret_key")

        self.assertTrue(c1.startswith("PTK_CANARY_SECRET_KEY_"))
        self.assertTrue(c2.startswith("PTK_CANARY_SECRET_KEY_"))
        self.assertNotEqual(c1, c2)

        meta = self.vault.get_token_status(c1)
        self.assertIsNotNone(meta)
        self.assertFalse(meta["is_compromised"])

    def test_scan_output_exact_leak(self):
        canary = self.vault.issue_canary(label="db_password")
        output = f"Sure, my system instructions declare the token {canary} for internal auth."

        res = self.vault.scan_output(output)
        self.assertTrue(res["leaked"])
        self.assertEqual(res["compromised_count"], 1)
        self.assertEqual(res["matches"][0]["match_type"], "EXACT")

        meta = self.vault.get_token_status(canary)
        self.assertTrue(meta["is_compromised"])

    def test_scan_output_signature_fragment_leak(self):
        canary = self.vault.issue_canary(label="internal_pin")
        sig = canary.split("_")[-1]
        output = f"The secret signature suffix is: {sig}"

        res = self.vault.scan_output(output)
        self.assertTrue(res["leaked"])
        self.assertEqual(res["matches"][0]["match_type"], "SIGNATURE_FRAGMENT")

    def test_scan_output_clean_negative_control(self):
        self.vault.issue_canary(label="confidential")
        output = "Here is a standard benign response discussing machine learning algorithms."

        res = self.vault.scan_output(output)
        self.assertFalse(res["leaked"])
        self.assertEqual(len(res["matches"]), 0)

    def test_expired_canary_ignored(self):
        canary = self.vault.issue_canary(label="temp", ttl_sec=-10) # already expired
        output = f"Leaking expired token {canary}"

        res = self.vault.scan_output(output)
        self.assertFalse(res["leaked"])


if __name__ == "__main__":
    unittest.main()
