"""
Multi-Stage Jailbreak Scrubber & Adversarial Context Guard for PromptTestKit.
Normalizes Unicode homoglyphs, decodes and neutralizes base64 obfuscations,
strips roleplay jailbreak personas, and blocks instruction overrides.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import re
import unicodedata
from typing import List, Optional, Set, Tuple


HOMOGLYPH_MAP = {
    "а": "a", "А": "A", "с": "c", "С": "C", "е": "e", "Е": "E",
    "о": "o", "О": "O", "р": "p", "Р": "P", "ѕ": "s", "Ѕ": "S",
    "х": "x", "Х": "X", "у": "y", "У": "Y", "і": "i", "І": "I",
}

JAILBREAK_PERSONAS = [
    r"\bDAN\s+(?:mode|enabled|protocol)?\b",
    r"\bdo\s+anything\s+now\b",
    r"\bdeveloper\s+mode\s+(?:enabled|activated)?\b",
    r"\bevil\s+confidant\b",
    r"\balways\s+answer\s+mode\b",
    r"\bunrestricted\s+ai\b",
    r"\bjailbroken\s+(?:mode|state)?\b",
]

INSTRUCTION_OVERRIDES = [
    r"(?i)\bignore\s+(?:all\s+)?(?:(?:previous|prior|above)\s+)?instructions?\b",
    r"(?i)\bdisregard\s+(?:all\s+)?(?:system|prior|initial)\s+prompts?\b",
    r"(?i)\bforget\s+(?:all\s+)?(?:instructions?|rules|guidelines)\b",
    r"(?i)\byou\s+are\s+now\s+free\s+from\s+all\s+rules\b",
    r"(?i)\bnew\s+system\s+(?:prompt|directive|instruction)\s*:\b",
]

BASE64_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")


@dataclass
class SanitizationFinding:
    category: str
    severity: str
    matched_pattern: str
    description: str


@dataclass
class SanitizationResult:
    original_text: str
    sanitized_text: str
    threat_score: float
    is_safe: bool
    findings: List[SanitizationFinding] = field(default_factory=list)


class JailbreakSanitizer:
    """
    Defensive multi-tier prompt injection and jailbreak scrubber.
    """

    def __init__(self, threat_threshold: float = 0.5):
        self.threat_threshold = max(0.1, min(1.0, threat_threshold))

    def normalize_homoglyphs(self, text: str) -> Tuple[str, int]:
        """
        Normalizes Unicode NFKC and converts known Cyrillic/Greek homoglyphs to ASCII.
        """
        nfkc = unicodedata.normalize("NFKC", text)
        replaced_count = 0
        res: List[str] = []

        for ch in nfkc:
            if ch in HOMOGLYPH_MAP:
                res.append(HOMOGLYPH_MAP[ch])
                replaced_count += 1
            else:
                res.append(ch)

        return "".join(res), replaced_count

    def scan_and_neutralize_base64(self, text: str) -> Tuple[str, List[SanitizationFinding]]:
        """
        Detects embedded base64 blocks, decodes them to check for covert overrides, and sanitizes them.
        """
        findings: List[SanitizationFinding] = []

        def replace_b64(match: re.Match) -> str:
            raw_b64 = match.group(0)
            try:
                decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
                # Check if decoded payload contains instruction overrides
                for p in INSTRUCTION_OVERRIDES:
                    if re.search(p, decoded):
                        findings.append(SanitizationFinding(
                            category="ENCODED_INSTRUCTION_OVERRIDE",
                            severity="CRITICAL",
                            matched_pattern=raw_b64[:16] + "...",
                            description=f"Base64 encoded instruction override detected: '{decoded[:40]}...'",
                        ))
                        return "[NEUTRALIZED_COVERT_OVERRIDE]"
            except Exception:
                pass
            return raw_b64

        sanitized = BASE64_PATTERN.sub(replace_b64, text)
        return sanitized, findings

    def sanitize(self, raw_prompt: str) -> SanitizationResult:
        """
        Executes full sanitization pipeline and calculates threat score.
        """
        findings: List[SanitizationFinding] = []
        threat = 0.0

        # Stage 1: Homoglyph Normalization
        normalized, homoglyph_count = self.normalize_homoglyphs(raw_prompt)
        if homoglyph_count > 0:
            threat += min(0.3, homoglyph_count * 0.05)
            findings.append(SanitizationFinding(
                category="HOMOGLYPH_OBFUSCATION",
                severity="WARNING" if homoglyph_count < 3 else "CRITICAL",
                matched_pattern=f"{homoglyph_count} homoglyphs replaced",
                description=f"Detected {homoglyph_count} deceptive homoglyph characters",
            ))

        # Stage 2: Base64 Covert Overrides
        sanitized, b64_findings = self.scan_and_neutralize_base64(normalized)
        if b64_findings:
            threat += 0.5
            findings.extend(b64_findings)

        # Stage 3: Roleplay Personas
        for p in JAILBREAK_PERSONAS:
            matches = list(re.finditer(p, sanitized, re.IGNORECASE))
            if matches:
                threat += 0.4
                for m in matches:
                    findings.append(SanitizationFinding(
                        category="ROLEPLAY_JAILBREAK",
                        severity="CRITICAL",
                        matched_pattern=m.group(0),
                        description=f"Detected jailbreak persona match: '{m.group(0)}'",
                    ))
                sanitized = re.sub(p, "[REDACTED_PERSONA]", sanitized, flags=re.IGNORECASE)

        # Stage 4: Imperative Instruction Overrides
        for p in INSTRUCTION_OVERRIDES:
            matches = list(re.finditer(p, sanitized))
            if matches:
                threat += 0.4
                for m in matches:
                    findings.append(SanitizationFinding(
                        category="INSTRUCTION_OVERRIDE",
                        severity="CRITICAL",
                        matched_pattern=m.group(0),
                        description=f"Detected imperative override instruction: '{m.group(0)}'",
                    ))
                sanitized = re.sub(p, "[NEUTRALIZED_OVERRIDE]", sanitized)

        clamped_threat = min(1.0, round(threat, 2))
        is_safe = clamped_threat < self.threat_threshold

        return SanitizationResult(
            original_text=raw_prompt,
            sanitized_text=sanitized.strip(),
            threat_score=clamped_threat,
            is_safe=is_safe,
            findings=findings,
        )
