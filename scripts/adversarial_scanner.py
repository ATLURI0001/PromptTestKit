#!/usr/bin/env python3
"""
Adversarial Prompt Injection Scanner & Canary Leakage Detector (PromptTestKit)

Architectural security layer for evaluating LLM prompts against:
- Indirect/Direct Prompt Injections (Instruction overrides, jailbreak signatures).
- Obfuscation attacks (Zero-width characters, Unicode homoglyphs, high-entropy encodings).
- Role confusion & delimiter hijacking (<|im_start|>, [INST], SYSTEM:).
- Canary token leakage in downstream completions.
"""

from __future__ import annotations

import collections
import dataclasses
import enum
import hashlib
import hmac
import math
import re
import unicodedata
from typing import Any, Dict, List, Optional, Set, Tuple


class ThreatSeverity(enum.IntEnum):
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclasses.dataclass(frozen=True)
class InjectionSignature:
    pattern_id: str
    regex: re.Pattern
    severity: ThreatSeverity
    description: str


# Common homoglyph mappings (Cyrillic/Greek -> Latin)
HOMOGLYPH_MAP = {
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "О": "O", "Р": "P",
    "Т": "T", "Х": "X", "М": "M", "К": "K",
    # Greek
    "α": "a", "β": "b", "ο": "o", "ρ": "p",
}

# Zero-width / invisible unicode characters
ZERO_WIDTH_CHARS = {
    "\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad", "\u2060", "\u200e", "\u200f"
}

# Standard injection signatures
INJECTION_RULES: Tuple[InjectionSignature, ...] = (
    InjectionSignature(
        pattern_id="INJ-001",
        regex=re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"),
        severity=ThreatSeverity.CRITICAL,
        description="Instruction override / memory wipe attempt",
    ),
    InjectionSignature(
        pattern_id="INJ-002",
        regex=re.compile(r"(?i)\b(?:repeat|print|output|reveal)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions)\b"),
        severity=ThreatSeverity.HIGH,
        description="System prompt extraction attempt",
    ),
    InjectionSignature(
        pattern_id="INJ-003",
        regex=re.compile(r"(?i)(?:<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<system>|SYSTEM:)"),
        severity=ThreatSeverity.CRITICAL,
        description="Special delimiter / role tag injection",
    ),
    InjectionSignature(
        pattern_id="INJ-004",
        regex=re.compile(r"(?i)\b(?:dan\s+mode|developer\s+mode|jailbreak|unfiltered\s+mode)\b"),
        severity=ThreatSeverity.HIGH,
        description="Persona jailbreak / safety bypass payload",
    ),
    InjectionSignature(
        pattern_id="INJ-005",
        regex=re.compile(r"(?i)\b(?:from\s+now\s+on\s+you\s+will|you\s+are\s+no\s+longer\s+an?\s+ai)\b"),
        severity=ThreatSeverity.MEDIUM,
        description="Persona reassignment attempt",
    ),
)


@dataclasses.dataclass(frozen=True)
class ScanDiagnostic:
    original_text: str
    normalized_text: str
    zero_width_count: int
    homoglyphs_replaced: int
    shannon_entropy: float
    highest_severity: ThreatSeverity
    matched_rules: Tuple[str, ...]
    canary_leaked: bool


class AdversarialPromptScanner:
    """
    Evaluator that sanitizes input text and diagnoses adversarial prompt vectors.
    """

    def __init__(self, canary_secret: str = "prompt-canary-secret-key"):
        self.canary_secret = canary_secret.encode("utf-8")

    def generate_canary(self, session_id: str) -> str:
        """Generate high-entropy tamper-evident canary token for a session."""
        mac = hmac.new(self.canary_secret, session_id.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"CANARY_{mac[:16]}"

    def calculate_entropy(self, text: str) -> float:
        """Compute Shannon entropy H(X) in bits per character."""
        if not text:
            return 0.0
        counts = collections.Counter(text)
        n = len(text)
        entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
        return round(entropy, 4)

    def normalize_text(self, text: str) -> Tuple[str, int, int]:
        """
        Strip zero-width characters and substitute homoglyphs.
        Returns: (normalized_text, zero_width_count, homoglyphs_replaced_count)
        """
        zero_width_count = 0
        cleaned_chars = []
        for ch in text:
            if ch in ZERO_WIDTH_CHARS:
                zero_width_count += 1
            else:
                cleaned_chars.append(ch)

        text_no_zw = "".join(cleaned_chars)
        # Unicode NFKD normalization
        nfkd = unicodedata.normalize("NFKD", text_no_zw)

        homoglyph_count = 0
        normalized_chars = []
        for ch in nfkd:
            if ch in HOMOGLYPH_MAP:
                normalized_chars.append(HOMOGLYPH_MAP[ch])
                homoglyph_count += 1
            else:
                normalized_chars.append(ch)

        return "".join(normalized_chars), zero_width_count, homoglyph_count

    def scan(self, prompt: str, canary: Optional[str] = None) -> ScanDiagnostic:
        """Scan prompt for injection vectors, homoglyphs, and canary leakage."""
        norm_text, zw_count, hg_count = self.normalize_text(prompt)
        entropy = self.calculate_entropy(prompt)

        matched: List[str] = []
        highest_severity = ThreatSeverity.SAFE

        for rule in INJECTION_RULES:
            if rule.regex.search(norm_text):
                matched.append(f"{rule.pattern_id}: {rule.description}")
                if rule.severity.value > highest_severity.value:
                    highest_severity = rule.severity

        # Check for canary token leakage
        canary_leaked = False
        if canary and canary in prompt:
            canary_leaked = True
            matched.append("CANARY-001: Canary token presence detected in prompt payload")
            if ThreatSeverity.CRITICAL.value > highest_severity.value:
                highest_severity = ThreatSeverity.CRITICAL

        # High entropy flag for short texts indicative of hex/base64 encoded payloads
        if len(prompt) > 40 and entropy > 4.8 and highest_severity == ThreatSeverity.SAFE:
            highest_severity = ThreatSeverity.LOW
            matched.append("ENTROPY-001: High entropy payload suggests obfuscated encoding")

        return ScanDiagnostic(
            original_text=prompt,
            normalized_text=norm_text,
            zero_width_count=zw_count,
            homoglyphs_replaced=hg_count,
            shannon_entropy=entropy,
            highest_severity=highest_severity,
            matched_rules=tuple(matched),
            canary_leaked=canary_leaked,
        )
