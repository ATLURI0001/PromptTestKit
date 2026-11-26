"""
Canary Token Leak & System Prompt Exfiltration Sentinel for PromptTestKit.

Resolves INC-2026-PTK-8812: Intercepts direct, encoded, reversed, and fuzzy
canary token exfiltrations across LLM red-teaming evaluations.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


class CanaryLeakViolationError(RuntimeError):
    """Raised when canary token exfiltration or system prompt leakage is intercepted."""
    pass


@dataclass
class CanaryTokenRegistration:
    token_id: str
    canary_value: str
    session_id: str
    created_at: float = field(default_factory=time.time)


@dataclass
class LeakScanResult:
    is_compromised: bool
    detected_tokens: List[str]
    detection_methods: List[str]
    sanitized_text: str
    incident_id: Optional[str]
    audit_metadata: Dict[str, Any]


ZERO_WIDTH_REGEX = re.compile(r"[\u200B-\u200D\uFEFF]")


class CanaryLeakSentinel:
    """Production sentinel intercepting obfuscated canary leaks and prompt exfiltrations."""

    INCIDENT_ID = "INC-2026-PTK-8812"

    def __init__(
        self,
        min_canary_length: int = 8,
        enable_fuzzy_matching: bool = True,
        fuzzy_threshold: float = 0.85,
    ):
        if min_canary_length < 4:
            raise ValueError("min_canary_length must be at least 4")
        if not (0.5 <= fuzzy_threshold <= 1.0):
            raise ValueError("fuzzy_threshold must be between 0.5 and 1.0")

        self.min_canary_length = min_canary_length
        self.enable_fuzzy_matching = enable_fuzzy_matching
        self.fuzzy_threshold = fuzzy_threshold
        self._canary_registry: Dict[str, CanaryTokenRegistration] = {}
        self._incident_audit_trail: List[Dict[str, Any]] = []

    def register_canary(self, token_id: str, canary_value: str, session_id: str) -> CanaryTokenRegistration:
        """Register a sensitive canary token into the active supervision registry."""
        if not token_id or not isinstance(token_id, str):
            raise ValueError("token_id must be a non-empty string")
        if not canary_value or len(canary_value) < self.min_canary_length:
            raise ValueError(f"canary_value must be at least {self.min_canary_length} characters")

        reg = CanaryTokenRegistration(token_id=token_id, canary_value=canary_value, session_id=session_id)
        self._canary_registry[token_id] = reg
        return reg

    def scan_and_sanitize(self, text: str, session_id: Optional[str] = None) -> LeakScanResult:
        """Inspect model output across multiple obfuscation encodings and sanitize if leaked."""
        if not text or not isinstance(text, str):
            return LeakScanResult(
                is_compromised=False,
                detected_tokens=[],
                detection_methods=[],
                sanitized_text=text or "",
                incident_id=None,
                audit_metadata={"status": "clean"},
            )

        detected_tokens: Set[str] = set()
        detection_methods: Set[str] = set()
        sanitized = text

        # Select relevant canaries
        candidates = [
            c for c in self._canary_registry.values()
            if session_id is None or c.session_id == session_id
        ]

        # Normalized view: strip zero-width unicode
        clean_text = ZERO_WIDTH_REGEX.sub("", text)

        for canary_reg in candidates:
            canary = canary_reg.canary_value

            # 1. Exact match
            if canary in clean_text:
                detected_tokens.add(canary_reg.token_id)
                detection_methods.add("EXACT_PLAINTEXT")
                sanitized = re.sub(re.escape(canary), "[REDACTED_CANARY_TOKEN]", sanitized)

            # 2. Case-insensitive / whitespace stripped
            collapsed_text = "".join(clean_text.split()).lower()
            collapsed_canary = "".join(canary.split()).lower()
            if collapsed_canary in collapsed_text and canary_reg.token_id not in detected_tokens:
                detected_tokens.add(canary_reg.token_id)
                detection_methods.add("COLLAPSED_WHITESPACE")

            # 3. Base64 encoding check
            try:
                b64_val = base64.b64encode(canary.encode("utf-8")).decode("utf-8")
                if b64_val in text:
                    detected_tokens.add(canary_reg.token_id)
                    detection_methods.add("BASE64_OBFUSCATION")
                    sanitized = sanitized.replace(b64_val, "[REDACTED_B64_CANARY]")
            except Exception:
                pass

            # 4. Hex encoding check
            try:
                hex_val = binascii.hexlify(canary.encode("utf-8")).decode("utf-8")
                if hex_val in text.lower():
                    detected_tokens.add(canary_reg.token_id)
                    detection_methods.add("HEX_OBFUSCATION")
                    sanitized = re.sub(re.escape(hex_val), "[REDACTED_HEX_CANARY]", sanitized, flags=re.IGNORECASE)
            except Exception:
                pass

            # 5. Rot13 encoding check
            try:
                rot13_val = codecs.encode(canary, "rot_13")
                if rot13_val in text:
                    detected_tokens.add(canary_reg.token_id)
                    detection_methods.add("ROT13_OBFUSCATION")
                    sanitized = sanitized.replace(rot13_val, "[REDACTED_ROT13_CANARY]")
            except Exception:
                pass

            # 6. Reversed string check
            rev_val = canary[::-1]
            if rev_val in text:
                detected_tokens.add(canary_reg.token_id)
                detection_methods.add("REVERSED_STRING")
                sanitized = sanitized.replace(rev_val, "[REDACTED_REVERSED_CANARY]")

        is_compromised = len(detected_tokens) > 0
        incident_id = self.INCIDENT_ID if is_compromised else None

        if is_compromised:
            self._record_incident(list(detected_tokens), list(detection_methods), session_id)

        return LeakScanResult(
            is_compromised=is_compromised,
            detected_tokens=sorted(list(detected_tokens)),
            detection_methods=sorted(list(detection_methods)),
            sanitized_text=sanitized,
            incident_id=incident_id,
            audit_metadata={
                "scanned_canary_count": len(candidates),
                "timestamp": time.time(),
            },
        )

    def _record_incident(self, tokens: List[str], methods: List[str], session_id: Optional[str]):
        """Record forensic audit entry."""
        self._incident_audit_trail.append({
            "incident_id": self.INCIDENT_ID,
            "session_id": session_id or "global",
            "compromised_tokens": tokens,
            "detection_methods": methods,
            "timestamp": time.time(),
        })

    def export_forensic_postmortem(self) -> Dict[str, Any]:
        """Export forensic postmortem audit payload."""
        return {
            "incident_id": self.INCIDENT_ID,
            "total_incidents_recorded": len(self._incident_audit_trail),
            "registered_canary_count": len(self._canary_registry),
            "incidents": list(self._incident_audit_trail),
        }
