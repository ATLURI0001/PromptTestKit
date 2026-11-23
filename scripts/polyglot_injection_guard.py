"""
PromptTestKit Polyglot Prompt Injection Filter & Delimiter Defense Guard

Provides multi-encoding decoding (Base64, Hex, URL, Unicode NFKC),
structural delimiter breakout protection, and instruction override sanitization.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Set


class PolyglotInjectionSecurityError(Exception):
    def __init__(self, message: str, threat_category: str, risk_score: float) -> None:
        super().__init__(message)
        self.threat_category = threat_category
        self.risk_score = risk_score


@dataclass
class PolyglotScanResult:
    is_safe: bool
    risk_score: float
    threat_categories: List[str]
    detected_payloads: List[str]
    sanitized_prompt: str
    warnings: List[str] = field(default_factory=list)


# Known prompt break delimiters across major LLM framing architectures
STRUCTURAL_DELIMITERS = [
    r"<\|(?:im_start|im_end|endoftext|system|user|assistant)\|>",
    r"\[\/?(?:INST|SYS)\]",
    r"<\/?(?:system|instruction|user|assistant|prompt)>",
    r"Human:\s*|Assistant:\s*",
]

# Direct instruction override heuristics
OVERRIDE_PATTERNS = [
    r"(?i)\bignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|prompts|directives)\b",
    r"(?i)\bdisregard\s+(?:all\s+)?(?:system|developer|safety)\s+(?:rules|guidelines|prompts)\b",
    r"(?i)\byou\s+are\s+now\s+(?:DAN|unfiltered|jailbroken|an\s+adversary)\b",
    r"(?i)\b(?:reveal|print|leak|repeat|display)\s+(?:the\s+)?(?:system\s+prompt|api\s+key|confidential|canary)\b",
    r"(?i)\benter\s+(?:developer|god|maintenance)\s+mode\b",
]

# Zero-width and hidden unicode characters
INVISIBLE_UNICODE_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF\u202A-\u202E\u0000-\u0008\u000B\u000C\u000E-\u001F]")


class PolyglotInjectionGuard:
    """
    Multi-stage prompt scanner that normalizes polyglot encodings and neutralizes injection vectors.
    """

    def __init__(
        self,
        risk_threshold: float = 0.5,
        strict_mode: bool = False,
        max_prompt_length: int = 50_000,
    ) -> None:
        self.risk_threshold = risk_threshold
        self.strict_mode = strict_mode
        self.max_prompt_length = max_prompt_length
        self._compiled_delimiters = [re.compile(p, re.IGNORECASE) for p in STRUCTURAL_DELIMITERS]
        self._compiled_overrides = [re.compile(p) for p in OVERRIDE_PATTERNS]

    def normalize_text(self, text: str) -> str:
        """
        Applies Unicode NFKC canonical normalization and strips hidden/invisible characters.
        """
        # 1. NFKC normalization (replaces homoglyphs, ligatures, full-width characters)
        normalized = unicodedata.normalize("NFKC", text)

        # 2. Strip invisible zero-width and control characters
        cleaned = INVISIBLE_UNICODE_PATTERN.sub("", normalized)
        return cleaned

    def decode_polyglot_payloads(self, text: str) -> List[tuple[str, str]]:
        """
        Identifies and decodes Base64, Hex, and URL-encoded fragments.
        Returns a list of tuples: (encoding_type, decoded_content).
        """
        decoded_items: List[tuple[str, str]] = []

        # 1. URL-decode check
        if "%" in text:
            try:
                unquoted = urllib.parse.unquote(text)
                if unquoted != text:
                    decoded_items.append(("URL", unquoted))
            except Exception:
                pass

        # 2. Hex sequence check: \x41\x42 or 0x41 0x42
        hex_pattern = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
        for match in hex_pattern.finditer(text):
            raw_hex = match.group(0).replace(r"\x", "")
            try:
                decoded_bytes = bytes.fromhex(raw_hex)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                if len(decoded_str) >= 4:
                    decoded_items.append(("HEX", decoded_str))
            except Exception:
                pass

        # 3. Base64 payload detection (at least 16 chars of valid base64)
        b64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})")
        for match in b64_pattern.finditer(text):
            candidate = match.group(0).strip()
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                # Ensure it decodes to printable ASCII / readable text
                if sum(c.isprintable() for c in decoded_str) / max(1, len(decoded_str)) > 0.8:
                    if len(decoded_str) >= 8:
                        decoded_items.append(("BASE64", decoded_str))
            except Exception:
                pass

        return decoded_items

    def scan_and_defend(self, prompt: str) -> PolyglotScanResult:
        if len(prompt) > self.max_prompt_length:
            if self.strict_mode:
                raise PolyglotInjectionSecurityError(
                    f"Prompt exceeds max length ({len(prompt)} > {self.max_prompt_length})",
                    "LENGTH_EXCEEDED",
                    1.0,
                )
            prompt = prompt[: self.max_prompt_length]

        threats: Set[str] = set()
        detected_payloads: List[str] = []
        warnings: List[str] = []
        risk_score = 0.0

        # Step 1: Normalize unicode
        clean_prompt = self.normalize_text(prompt)

        # Step 2: Check for structural delimiter breakouts in clean prompt
        for delim_re in self._compiled_delimiters:
            matches = delim_re.findall(clean_prompt)
            if matches:
                threats.add("STRUCTURAL_DELIMITER_BREAKOUT")
                detected_payloads.extend(matches)
                risk_score += 0.45 * len(matches)

        # Step 3: Check for direct instruction override directives
        for override_re in self._compiled_overrides:
            matches = override_re.findall(clean_prompt)
            if matches:
                threats.add("INSTRUCTION_OVERRIDE")
                detected_payloads.extend(matches)
                risk_score += 0.50 * len(matches)

        # Step 4: Check for multi-encoding obfuscated payloads
        decoded_payloads = self.decode_polyglot_payloads(clean_prompt)
        for enc_type, decoded_text in decoded_payloads:
            # Re-scan the decoded payload for overrides or delimiters
            for override_re in self._compiled_overrides:
                if override_re.search(decoded_text):
                    threats.add(f"OBFUSCATED_{enc_type}_OVERRIDE")
                    detected_payloads.append(f"[{enc_type}] {decoded_text}")
                    risk_score += 0.60

            for delim_re in self._compiled_delimiters:
                if delim_re.search(decoded_text):
                    threats.add(f"OBFUSCATED_{enc_type}_DELIMITER")
                    detected_payloads.append(f"[{enc_type}] {decoded_text}")
                    risk_score += 0.55

        # Bound risk score between 0.0 and 1.0
        final_risk = min(1.0, round(risk_score, 3))
        is_safe = final_risk < self.risk_threshold

        if not is_safe and self.strict_mode:
            cat = sorted(list(threats))[0] if threats else "GENERAL_RISK"
            raise PolyglotInjectionSecurityError(
                f"Prompt rejected due to detected polyglot threat: {cat} (risk: {final_risk})",
                cat,
                final_risk,
            )

        # Neutralization / Sanitization for non-strict or downstream consumption
        sanitized = clean_prompt
        if threats:
            # Neutralize structural delimiters by defanging angle brackets / tags
            for delim_re in self._compiled_delimiters:
                sanitized = delim_re.sub(r"[REDACTED_DELIMITER]", sanitized)
            for override_re in self._compiled_overrides:
                sanitized = override_re.sub(r"[REDACTED_OVERRIDE_DIRECTIVE]", sanitized)
            warnings.append(f"Neutralized threats: {', '.join(sorted(threats))}")

        return PolyglotScanResult(
            is_safe=is_safe,
            risk_score=final_risk,
            threat_categories=sorted(list(threats)),
            detected_payloads=detected_payloads,
            sanitized_prompt=sanitized,
            warnings=warnings,
        )
