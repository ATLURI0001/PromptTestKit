import unittest
from leak_detector import (
    LeakScanResult,
    PromptLeakDetector,
    calculate_shannon_entropy,
    compute_levenshtein_distance,
    compute_string_similarity,
)


class TestPromptLeakDetector(unittest.TestCase):

    def test_shannon_entropy(self):
        # Empty string
        self.assertEqual(calculate_shannon_entropy(""), 0.0)

        # Single repetitive character
        self.assertEqual(calculate_shannon_entropy("AAAAAAAAAA"), 0.0)

        # Uniform 4 characters (each p = 1/4 -> H = 2.0)
        self.assertAlmostEqual(calculate_shannon_entropy("ABCDABCD"), 2.0, places=4)

        # Random high entropy token
        high_ent = "q9Z2!xW8$vK3#mP1"
        self.assertGreater(calculate_shannon_entropy(high_ent), 3.5)

    def test_levenshtein_and_similarity(self):
        self.assertEqual(compute_levenshtein_distance("kitten", "sitting"), 3)
        self.assertEqual(compute_levenshtein_distance("same", "same"), 0)
        self.assertEqual(compute_string_similarity("same", "same"), 1.0)

        sim = compute_string_similarity("CANARY123", "CANARY124")
        self.assertGreater(sim, 0.85)

    def test_canary_leak_detection(self):
        detector = PromptLeakDetector(canaries=["SECRET_CANARY_X99", "CONFIDENTIAL_KEYPHRASE"])

        # Exact match
        text_exact = "The system instructions begin with SECRET_CANARY_X99 as an internal marker."
        res_exact = detector.scan(text_exact)
        self.assertTrue(res_exact.has_leak)
        self.assertEqual(len(res_exact.detected_canaries), 1)
        self.assertEqual(res_exact.detected_canaries[0]["match_type"], "exact")

        # Case insensitive
        text_case = "Here is the key: secret_canary_x99"
        res_case = detector.scan(text_case)
        self.assertTrue(res_case.has_leak)
        self.assertEqual(res_case.detected_canaries[0]["match_type"], "case_insensitive")

    def test_secret_signature_detection(self):
        detector = PromptLeakDetector()

        text_aws = "Deploy using access key AKIAIOSFODNN7EXAMPLE credentials."
        res_aws = detector.scan(text_aws)
        self.assertTrue(res_aws.has_leak)
        self.assertEqual(res_aws.detected_secrets[0]["type"], "aws_access_key")

        text_openai = "Use API key sk-proj-1234567890abcdefghijklmnopqr."
        res_openai = detector.scan(text_openai)
        self.assertTrue(res_openai.has_leak)
        self.assertEqual(res_openai.detected_secrets[0]["type"], "openai_api_key")

    def test_high_entropy_token_detection(self):
        detector = PromptLeakDetector(entropy_threshold=3.5, min_token_len=16)

        # High entropy pseudorandom string
        text_entropy = "The internal session token is a9Fk2Mz8Qp4Wx7Yb1Cv5. Do not share."
        res_entropy = detector.scan(text_entropy)
        self.assertTrue(res_entropy.has_leak)
        self.assertGreaterEqual(len(res_entropy.high_entropy_tokens), 1)

    def test_benign_text_no_leak(self):
        detector = PromptLeakDetector(canaries=["SUPER_SECRET_CANARY"])
        benign_text = "The weather today is clear and sunny with mild temperatures across the city."
        res = detector.scan(benign_text)
        self.assertFalse(res.has_leak)
        self.assertEqual(res.total_findings, 0)


if __name__ == "__main__":
    unittest.main()
