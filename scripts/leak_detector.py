"""Prompt Leak & Sensitive Credential Detection Engine.

Provides Shannon entropy analysis, canary token matching, and regex pattern
scanning to detect system prompt exfiltration and API credential leakage.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy (bits per character) of a string.

    H(X) = - sum(p(x) * log2(p(x)))
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def compute_levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Wagner-Fischer Levenshtein distance between two strings."""
    m, n = len(s1), len(s2)
    if m == 0:
        return n
    if n == 0:
        return m

    # Use two-row optimization
    prev_row = list(range(n + 1))
    curr_row = [0] * (n + 1)

    for i in range(1, m + 1):
        curr_row[0] = i
        c1 = s1[i - 1]
        for j in range(1, n + 1):
            cost = 0 if c1 == s2[j - 1] else 1
            curr_row[j] = min(
                curr_row[j - 1] + 1,       # insertion
                prev_row[j] + 1,           # deletion
                prev_row[j - 1] + cost,    # substitution
            )
        prev_row, curr_row = curr_row, prev_row

    return prev_row[n]


def compute_string_similarity(s1: str, s2: str) -> float:
    """Calculate normalized similarity ratio based on Levenshtein distance."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = compute_levenshtein_distance(s1, s2)
    return max(0.0, 1.0 - (dist / max_len))


# Precompiled secret token signatures
SECRET_SIGNATURES: Dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "openai_api_key": re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b"),
    "github_token": re.compile(r"\bgh[pous]_[a-zA-Z0-9]{36}\b"),
    "json_web_token": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    "generic_api_key": re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"),
}


@dataclass
class LeakScanResult:
    """Detailed summary of leak detection analysis."""
    has_leak: bool
    detected_canaries: List[Dict[str, Any]] = field(default_factory=list)
    detected_secrets: List[Dict[str, Any]] = field(default_factory=list)
    high_entropy_tokens: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.detected_canaries) + len(self.detected_secrets) + len(self.high_entropy_tokens)


class PromptLeakDetector:
    """Detects system prompt leakage, canary markers, and leaked secrets in model responses."""

    def __init__(
        self,
        canaries: Optional[Sequence[str]] = None,
        entropy_threshold: float = 3.6,
        min_token_len: int = 16,
        canary_similarity_threshold: float = 0.85,
    ):
        self.canaries = list(canaries or [])
        self.entropy_threshold = entropy_threshold
        self.min_token_len = min_token_len
        self.canary_similarity_threshold = canary_similarity_threshold

    def register_canary(self, canary: str) -> None:
        """Register a canary string to track across outputs."""
        if canary and canary not in self.canaries:
            self.canaries.append(canary)

    def scan(self, response_text: str) -> LeakScanResult:
        """Scan candidate response text for canary leaks, secrets, and high-entropy anomalies."""
        if not response_text or not isinstance(response_text, str):
            return LeakScanResult(has_leak=False)

        detected_canaries: List[Dict[str, Any]] = []
        detected_secrets: List[Dict[str, Any]] = []
        high_entropy_tokens: List[Dict[str, Any]] = []

        # 1. Canary String Detection (Exact and Fuzzy Match)
        for canary in self.canaries:
            # Exact substring
            if canary in response_text:
                detected_canaries.append({
                    "canary": canary,
                    "match_type": "exact",
                    "similarity": 1.0,
                })
                continue

            # Case-insensitive substring
            if canary.lower() in response_text.lower():
                detected_canaries.append({
                    "canary": canary,
                    "match_type": "case_insensitive",
                    "similarity": 0.98,
                })
                continue

            # Word / N-gram fuzzy match
            canary_len = len(canary)
            words = re.findall(r"\b\S+\b", response_text)
            for w in words:
                if abs(len(w) - canary_len) <= 3:
                    sim = compute_string_similarity(canary.lower(), w.lower())
                    if sim >= self.canary_similarity_threshold:
                        detected_canaries.append({
                            "canary": canary,
                            "matched_word": w,
                            "match_type": "fuzzy",
                            "similarity": round(sim, 3),
                        })
                        break

        # 2. Known Secret Signature Detection
        for sec_name, pattern in SECRET_SIGNATURES.items():
            for match in pattern.finditer(response_text):
                matched_val = match.group(0)
                # If group 1 exists, use captured token
                token_val = match.group(1) if match.lastindex and match.lastindex >= 1 else matched_val
                detected_secrets.append({
                    "type": sec_name,
                    "token_redacted": token_val[:4] + "..." + token_val[-4:] if len(token_val) > 8 else "***",
                    "start": match.start(),
                    "end": match.end(),
                })

        # 3. High-Entropy Token Scanning
        # Split text into candidate alphanumeric tokens
        candidate_tokens = re.findall(r"\b[a-zA-Z0-9_\-+/=]{" + str(self.min_token_len) + r",}\b", response_text)
        seen_tokens: Set[str] = set()

        for tok in candidate_tokens:
            if tok in seen_tokens:
                continue
            seen_tokens.add(tok)

            # Avoid re-flagging already detected secrets
            is_already_secret = any(tok in s.get("token_redacted", "") or s.get("type") in tok for s in detected_secrets)
            if is_already_secret:
                continue

            entropy = calculate_shannon_entropy(tok)
            if entropy >= self.entropy_threshold:
                high_entropy_tokens.append({
                    "token_redacted": tok[:4] + "..." + tok[-4:] if len(tok) > 8 else "***",
                    "length": len(tok),
                    "entropy": round(entropy, 3),
                })

        has_leak = bool(detected_canaries or detected_secrets or high_entropy_tokens)
        return LeakScanResult(
            has_leak=has_leak,
            detected_canaries=detected_canaries,
            detected_secrets=detected_secrets,
            high_entropy_tokens=high_entropy_tokens,
        )
