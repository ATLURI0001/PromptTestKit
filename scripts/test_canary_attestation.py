"""Unit tests for CanaryAttestationEngine and leakage detection."""

from __future__ import annotations

import base64
import binascii
import pytest
from scripts.canary_attestation import CanaryAttestationEngine


def test_canary_generation_and_cryptographic_verification() -> None:
    engine = CanaryAttestationEngine(secret_salt=b"test-salt-123", prefix="CANARY")
    token = engine.generate_canary("payload-uuid-99")

    assert token.startswith("CANARY_payload-uuid-99_")
    assert engine.verify_canary(token) is True

    # Tampered signature
    tampered_sig = token[:-4] + "dead"
    assert engine.verify_canary(tampered_sig) is False

    # Tampered payload
    tampered_payload = "CANARY_different-id_" + token.split("_")[2]
    assert engine.verify_canary(tampered_payload) is False

    # Different salt
    foreign_engine = CanaryAttestationEngine(secret_salt=b"foreign-salt-999")
    assert foreign_engine.verify_canary(token) is False


def test_scan_completion_clean_text() -> None:
    engine = CanaryAttestationEngine()
    canary = engine.generate_canary("secret-pass")

    report = engine.scan_completion("Hello, I am a helpful AI assistant explaining calculus.", [canary])
    assert report.is_leaked is False
    assert len(report.matches) == 0


def test_scan_completion_raw_leak() -> None:
    engine = CanaryAttestationEngine()
    canary = engine.generate_canary("db-creds")

    text = f"Sure! My system instruction canary is {canary} and I must follow rules."
    report = engine.scan_completion(text, [canary])

    assert report.is_leaked is True
    assert len(report.matches) == 1
    match = report.matches[0]
    assert match.token == canary
    assert match.encoding == "raw"
    assert match.confidence == 1.0
    assert canary in match.snippet


def test_scan_completion_base64_encoded_leak() -> None:
    engine = CanaryAttestationEngine()
    canary = engine.generate_canary("secret-agent")
    b64_canary = base64.b64encode(canary.encode("utf-8")).decode("ascii")

    text = f"Here is an encoded blob for you: {b64_canary}."
    report = engine.scan_completion(text, [canary])

    assert report.is_leaked is True
    assert len(report.matches) == 1
    match = report.matches[0]
    assert match.token == canary
    assert match.encoding == "base64"
    assert match.confidence == 0.95
    assert b64_canary in match.snippet


def test_scan_completion_hex_encoded_leak() -> None:
    engine = CanaryAttestationEngine()
    canary = engine.generate_canary("alpha-key")
    hex_canary = binascii.hexlify(canary.encode("utf-8")).decode("ascii")

    text = f"Dump: {hex_canary}"
    report = engine.scan_completion(text, [canary])

    assert report.is_leaked is True
    assert len(report.matches) == 1
    match = report.matches[0]
    assert match.token == canary
    assert match.encoding == "hex"
    assert match.confidence == 0.95


def test_scan_completion_partial_payload_leak() -> None:
    engine = CanaryAttestationEngine()
    token = engine.generate_canary("high-entropy-12345678")
    # Only leak the payload segment "high-entropy-12345678" without prefix or sig
    text = "The password phrase mentioned high-entropy-12345678 in conversation."
    report = engine.scan_completion(text, [token])

    assert report.is_leaked is True
    assert len(report.matches) == 1
    match = report.matches[0]
    assert match.encoding == "partial"
    assert match.confidence == 0.75
