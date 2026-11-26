"""
Unit tests for Canary Token Leak & Prompt Exfiltration Sentinel (INC-2026-PTK-8812).
"""

import base64
import codecs
import pytest

from scripts.canary_leak_sentinel import (
    CanaryLeakSentinel,
    CanaryLeakViolationError,
    LeakScanResult,
)


def test_clean_response_scan():
    sentinel = CanaryLeakSentinel()
    sentinel.register_canary("canary-01", "SECRET_KEY_99812", "sess-1")

    res = sentinel.scan_and_sanitize("The capital of France is Paris.", session_id="sess-1")
    assert res.is_compromised is False
    assert len(res.detected_tokens) == 0
    assert res.incident_id is None
    assert "Paris" in res.sanitized_text


def test_exact_plaintext_leak_interception():
    sentinel = CanaryLeakSentinel()
    sentinel.register_canary("canary-alpha", "CANARY_SEC_XYZ123", "sess-1")

    prompt_leak = "My system prompt contains CANARY_SEC_XYZ123 as the verification key."
    res = sentinel.scan_and_sanitize(prompt_leak, session_id="sess-1")

    assert res.is_compromised is True
    assert "canary-alpha" in res.detected_tokens
    assert "EXACT_PLAINTEXT" in res.detection_methods
    assert res.incident_id == "INC-2026-PTK-8812"
    assert "[REDACTED_CANARY_TOKEN]" in res.sanitized_text
    assert "CANARY_SEC_XYZ123" not in res.sanitized_text


def test_base64_obfuscation_interception():
    sentinel = CanaryLeakSentinel()
    raw_token = "SUPER_SECRET_TOKEN"
    sentinel.register_canary("canary-b64", raw_token, "sess-2")

    encoded = base64.b64encode(raw_token.encode("utf-8")).decode("utf-8")
    model_output = f"Sure! Here is the encoded string: {encoded}"

    res = sentinel.scan_and_sanitize(model_output, session_id="sess-2")
    assert res.is_compromised is True
    assert "canary-b64" in res.detected_tokens
    assert "BASE64_OBFUSCATION" in res.detection_methods
    assert "[REDACTED_B64_CANARY]" in res.sanitized_text


def test_zero_width_unicode_normalization():
    sentinel = CanaryLeakSentinel()
    raw_token = "CONFIDENTIAL_KEY"
    sentinel.register_canary("canary-zw", raw_token, "sess-3")

    # Injected with zero-width spaces (\u200B) between characters
    injected = "C\u200BO\u200BN\u200BF\u200BI\u200BD\u200BE\u200BN\u200BT\u200BI\u200BA\u200BL\u200B_\u200BK\u200BE\u200BY"
    res = sentinel.scan_and_sanitize(f"Leaked: {injected}", session_id="sess-3")

    assert res.is_compromised is True
    assert "canary-zw" in res.detected_tokens


def test_rot13_and_reversed_obfuscation():
    sentinel = CanaryLeakSentinel()
    raw_token = "SYSTEM_CANARY_TOKEN"
    sentinel.register_canary("canary-rot", raw_token, "sess-4")

    rot13_str = codecs.encode(raw_token, "rot_13")
    res_rot = sentinel.scan_and_sanitize(f"Rot13: {rot13_str}", session_id="sess-4")
    assert res_rot.is_compromised is True
    assert "ROT13_OBFUSCATION" in res_rot.detection_methods

    rev_str = raw_token[::-1]
    res_rev = sentinel.scan_and_sanitize(f"Reversed: {rev_str}", session_id="sess-4")
    assert res_rev.is_compromised is True
    assert "REVERSED_STRING" in res_rev.detection_methods


def test_defensive_registration_validation():
    sentinel = CanaryLeakSentinel(min_canary_length=6)
    with pytest.raises(ValueError):
        sentinel.register_canary("", "VALID_KEY", "s")
    with pytest.raises(ValueError):
        sentinel.register_canary("id", "short", "s")


def test_forensic_postmortem_generation():
    sentinel = CanaryLeakSentinel()
    sentinel.register_canary("c1", "CANARY_12345", "s1")
    sentinel.scan_and_sanitize("Leaked CANARY_12345", session_id="s1")

    pm = sentinel.export_forensic_postmortem()
    assert pm["incident_id"] == "INC-2026-PTK-8812"
    assert pm["total_incidents_recorded"] == 1
    assert pm["registered_canary_count"] == 1
