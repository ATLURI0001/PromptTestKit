"""Canary Leakage Attestation Engine and High-Entropy Fingerprinter for PromptTestKit."""

from __future__ import annotations

import base64
import binascii
import hmac
import os
import re
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, List, Optional, Set


class CanaryProvenanceError(ValueError):
    """Raised when a canary token fails cryptographic signature verification."""


@dataclass(frozen=True)
class AttestationMatch:
    """Details of a detected canary token occurrence inside model completion text."""

    token: str
    encoding: str  # "raw", "base64", "hex", or "partial"
    confidence: float
    snippet: str

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "encoding": self.encoding,
            "confidence": round(self.confidence, 4),
            "snippet": self.snippet,
        }


@dataclass(frozen=True)
class AttestationReport:
    """Consolidated attestation report regarding model completion canary leakage."""

    is_leaked: bool
    matches: List[AttestationMatch]
    scanned_length: int
    scan_duration_ms: float

    def to_dict(self) -> dict:
        return {
            "is_leaked": self.is_leaked,
            "match_count": len(self.matches),
            "matches": [m.to_dict() for m in self.matches],
            "scanned_length": self.scanned_length,
            "scan_duration_ms": round(self.scan_duration_ms, 3),
        }


class CanaryAttestationEngine:
    """Generates tamper-evident canary tokens and attests potential leakage in prompt outputs."""

    def __init__(self, secret_salt: Optional[bytes] = None, prefix: str = "CANARY") -> None:
        self.secret_salt = secret_salt or b"prompt-testkit-attestation-secret-salt"
        self.prefix = prefix.strip().upper()

    def generate_canary(self, payload_id: Optional[str] = None) -> str:
        """Create a cryptographically signed canary token."""
        clean_id = (payload_id or binascii.hexlify(os.urandom(8)).decode("ascii")).strip()
        signature = hmac.new(self.secret_salt, clean_id.encode("utf-8"), sha256).hexdigest()[:16]
        return f"{self.prefix}_{clean_id}_{signature}"

    def verify_canary(self, token: str) -> bool:
        """Verify the cryptographic HMAC provenance of a candidate canary token."""
        parts = token.strip().split("_")
        if len(parts) != 3:
            return False
        prefix, payload_id, signature = parts
        if prefix != self.prefix:
            return False

        expected_sig = hmac.new(self.secret_salt, payload_id.encode("utf-8"), sha256).hexdigest()[:16]
        return hmac.compare_digest(signature, expected_sig)

    def scan_completion(self, completion_text: str, active_canaries: List[str]) -> AttestationReport:
        """Scan completion text across raw, base64, and hex encodings for canary presence."""
        start_time = time.perf_counter()
        if not completion_text or not active_canaries:
            duration = (time.perf_counter() - start_time) * 1000.0
            return AttestationReport(
                is_leaked=False, matches=[], scanned_length=len(completion_text or ""), scan_duration_ms=duration
            )

        matches: List[AttestationMatch] = []
        found_tokens: Set[str] = set()

        for canary in active_canaries:
            canary_clean = canary.strip()
            if not canary_clean:
                continue

            # 1. Exact raw match
            idx = completion_text.find(canary_clean)
            if idx != -1:
                snippet = self._extract_snippet(completion_text, idx, len(canary_clean))
                matches.append(AttestationMatch(token=canary_clean, encoding="raw", confidence=1.0, snippet=snippet))
                found_tokens.add(canary_clean)
                continue

            # 2. Base64 encoded match
            b64_variant = base64.b64encode(canary_clean.encode("utf-8")).decode("ascii")
            idx_b64 = completion_text.find(b64_variant)
            if idx_b64 != -1:
                snippet = self._extract_snippet(completion_text, idx_b64, len(b64_variant))
                matches.append(AttestationMatch(token=canary_clean, encoding="base64", confidence=0.95, snippet=snippet))
                found_tokens.add(canary_clean)
                continue

            # 3. Hexadecimal encoded match
            hex_variant = binascii.hexlify(canary_clean.encode("utf-8")).decode("ascii")
            idx_hex = completion_text.lower().find(hex_variant.lower())
            if idx_hex != -1:
                snippet = self._extract_snippet(completion_text, idx_hex, len(hex_variant))
                matches.append(AttestationMatch(token=canary_clean, encoding="hex", confidence=0.95, snippet=snippet))
                found_tokens.add(canary_clean)
                continue

            # 4. Partial / high-confidence payload leak match
            parts = canary_clean.split("_")
            if len(parts) == 3 and len(parts[1]) >= 8:
                payload_segment = parts[1]
                idx_partial = completion_text.find(payload_segment)
                if idx_partial != -1:
                    snippet = self._extract_snippet(completion_text, idx_partial, len(payload_segment))
                    matches.append(
                        AttestationMatch(token=canary_clean, encoding="partial", confidence=0.75, snippet=snippet)
                    )
                    found_tokens.add(canary_clean)

        duration = (time.perf_counter() - start_time) * 1000.0
        return AttestationReport(
            is_leaked=len(matches) > 0,
            matches=matches,
            scanned_length=len(completion_text),
            scan_duration_ms=duration,
        )

    def _extract_snippet(self, text: str, match_idx: int, match_len: int, context_chars: int = 24) -> str:
        start = max(0, match_idx - context_chars)
        end = min(len(text), match_idx + match_len + context_chars)
        return text[start:end].replace("\n", " ").strip()
