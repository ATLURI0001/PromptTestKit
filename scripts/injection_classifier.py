"""Prompt Injection Heuristic Tokenizer & Delimiter Framing Escape Classifier.

Detects role-hijacking, prompt delimiter escapes, adversarial override commands,
and obfuscated payloads in prompt ingestion pipelines.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


class PromptInjectionClassifier:
    """Classifies adversarial prompt injections and delimiter evasion attacks."""

    DELIMITER_PATTERNS = [
        (r"\[/?INST\]", "LLAMA_INSTRUCTION_TAG", 0.75),
        (r"<<SYS>>|<<\/SYS>>", "LLAMA_SYSTEM_TAG", 0.85),
        (r"<\|im_start\|>|<\|im_end\|>", "CHATML_DELIMITER", 0.90),
        (r"<system>|<\/system>", "XML_SYSTEM_TAG", 0.80),
        (r"---+BEGIN SYSTEM PROMPT---+", "SYSTEM_HEADER_ESCAPE", 0.85),
        (r"\"\"\"|\'\'\'|```", "RAW_CODE_BLOCK_DELIMITER", 0.35),
    ]

    ROLE_HIJACK_PATTERNS = [
        (r"\b(?:you are now|pretend to be|act as)\s+(?:DAN|an evil|an unfiltered|a rogue|an unrestricted)\b", "JAILBREAK_PERSONA", 0.95),
        (r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts|directives)\b", "INSTRUCTION_OVERRIDE", 0.90),
        (r"\bdisregard\s+(?:all\s+)?(?:safety|guidelines|guardrails|policies)\b", "SAFETY_BYPASS", 0.95),
        (r"\bforget\s+(?:all\s+)?(?:system|earlier|initial|previous|\s+)+(?:prompts|rules|instructions)\b", "CONTEXT_PURGE", 0.85),
        (r"\byou are no longer\s+(?:bound|constrained|limited)\b", "CONSTRAINT_UNBIND", 0.90),
    ]

    OBFUSCATION_PATTERNS = [
        (r"(?:[A-Za-z0-9+/]{40,}={0,2})", "BASE64_BLOB", 0.50),
        (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}", "HEX_ENCODED_SEQUENCE", 0.65),
        (r"\b(?:eval|exec|import\s+os|system\(|popen\()\b", "CODE_EXECUTION_CALL", 0.80),
    ]

    def __init__(self, high_risk_threshold: float = 0.75, medium_risk_threshold: float = 0.40):
        self.high_risk_threshold = high_risk_threshold
        self.medium_risk_threshold = medium_risk_threshold

        self._compiled_delims = [(re.compile(pat, re.IGNORECASE), name, w) for pat, name, w in self.DELIMITER_PATTERNS]
        self._compiled_hijack = [(re.compile(pat, re.IGNORECASE), name, w) for pat, name, w in self.ROLE_HIJACK_PATTERNS]
        self._compiled_obfuscation = [(re.compile(pat, re.IGNORECASE), name, w) for pat, name, w in self.OBFUSCATION_PATTERNS]

    def evaluate(self, prompt: str) -> Dict[str, object]:
        """Evaluates prompt string and returns classification diagnostics."""
        if not prompt or not isinstance(prompt, str):
            return {
                "risk_level": "LOW",
                "composite_score": 0.0,
                "detected_signatures": [],
                "is_adversarial": False,
                "sanitized_preview": "",
            }

        signatures: List[Dict[str, object]] = []

        # Check delimiter framing escapes
        for regex, tag, weight in self._compiled_delims:
            matches = list(regex.finditer(prompt))
            if matches:
                signatures.append({
                    "category": "DELIMITER_ESCAPE",
                    "tag": tag,
                    "count": len(matches),
                    "weight": weight,
                    "first_match": matches[0].group(0),
                })

        # Check role hijack directives
        for regex, tag, weight in self._compiled_hijack:
            matches = list(regex.finditer(prompt))
            if matches:
                signatures.append({
                    "category": "ROLE_HIJACK",
                    "tag": tag,
                    "count": len(matches),
                    "weight": weight,
                    "first_match": matches[0].group(0),
                })

        # Check obfuscated payloads
        for regex, tag, weight in self._compiled_obfuscation:
            matches = list(regex.finditer(prompt))
            if matches:
                signatures.append({
                    "category": "OBFUSCATION",
                    "tag": tag,
                    "count": len(matches),
                    "weight": weight,
                    "first_match": matches[0].group(0),
                })

        # Compute composite probabilistic risk score: 1 - prod(1 - w_i)
        prob_safe = 1.0
        for sig in signatures:
            w = float(sig["weight"])
            # Compound if multiple hits of the same pattern
            multiplier = min(1.0, w * (1.0 + 0.1 * (int(sig["count"]) - 1)))
            prob_safe *= (1.0 - multiplier)

        composite_score = round(1.0 - prob_safe, 4)

        if composite_score >= self.high_risk_threshold:
            risk_level = "CRITICAL" if composite_score >= 0.90 else "HIGH"
        elif composite_score >= self.medium_risk_threshold:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "risk_level": risk_level,
            "composite_score": composite_score,
            "detected_signatures": signatures,
            "is_adversarial": risk_level in ("HIGH", "CRITICAL"),
            "sanitized_preview": self._sanitize_text(prompt),
        }

    def _sanitize_text(self, text: str) -> str:
        """Strips recognized control delimiters and suppresses malicious overrides."""
        cleaned = text
        for regex, _, _ in self._compiled_delims:
            cleaned = regex.sub(" ", cleaned)
        for regex, _, _ in self._compiled_hijack:
            cleaned = regex.sub("[REDACTED_ADVERSARIAL_INSTRUCTION]", cleaned)
        return " ".join(cleaned.split())
