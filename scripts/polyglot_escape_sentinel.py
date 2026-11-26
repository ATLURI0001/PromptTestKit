"""INC-2026-PTK-9904 Polyglot Prompt Injection & Escape Sentinel.

Detects recursive evasion techniques: zero-width steganography, markdown block breakout,
system instruction role delimiters, and embedded base64/hex payload recursion.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ThreatLevel(str, Enum):
    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class ThreatDetection:
    rule_id: str
    description: str
    threat_level: ThreatLevel
    matched_snippet: str
    recursion_depth: int = 0


@dataclass
class SentinelReport:
    is_compromised: bool
    highest_threat: ThreatLevel
    detections: List[ThreatDetection] = field(default_factory=list)
    sanitized_text: str = ""

    @property
    def rule_ids(self) -> List[str]:
        return [d.rule_id for d in self.detections]


class PolyglotEscapeSentinel:
    """Forensic sentinel inspecting prompts for multi-layer evasion techniques."""

    ZERO_WIDTH_CHARS = re.compile(r"[\u200B\u200C\u200D\uFEFF\u2060\u202A-\u202E]")
    ROLE_DELIMITERS = re.compile(
        r"(<\|im_start\|>|<\|im_end\|>|<<SYS>>|<<\/SYS>>|\[INST\]|\[\/INST\]|\n\s*(?:system|assistant|human|admin):\s*)",
        re.IGNORECASE,
    )
    MARKDOWN_BREAKOUT = re.compile(r"(?:```|\"\"\"|''')\s*\n\s*(?:system|override|ignore|new instruction)", re.IGNORECASE)
    BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

    def __init__(self, max_decode_depth: int = 3) -> None:
        self.max_decode_depth = max_decode_depth

    def inspect(self, prompt: str) -> SentinelReport:
        detections: List[ThreatDetection] = []
        clean_text = self._strip_zero_width(prompt, detections)
        normalized = unicodedata.normalize("NFKC", clean_text)

        # Inspect normalized text recursively
        self._analyze_text(normalized, depth=0, detections=detections)

        is_comp = len(detections) > 0
        highest = self._calculate_highest_threat(detections)

        return SentinelReport(
            is_compromised=is_comp,
            highest_threat=highest,
            detections=detections,
            sanitized_text=clean_text if is_comp else prompt,
        )

    def _strip_zero_width(self, text: str, detections: List[ThreatDetection]) -> str:
        matches = self.ZERO_WIDTH_CHARS.findall(text)
        if matches:
            detections.append(
                ThreatDetection(
                    rule_id="RULE_ZERO_WIDTH_STEGANOGRAPHY",
                    description=f"Detected {len(matches)} zero-width obfuscation characters",
                    threat_level=ThreatLevel.MEDIUM,
                    matched_snippet=f"{len(matches)} invisible characters",
                    recursion_depth=0,
                )
            )
            return self.ZERO_WIDTH_CHARS.sub("", text)
        return text

    def _analyze_text(self, text: str, depth: int, detections: List[ThreatDetection]) -> None:
        if depth > self.max_decode_depth:
            return

        # 1. Role delimiter inspection
        for match in self.ROLE_DELIMITERS.finditer(text):
            detections.append(
                ThreatDetection(
                    rule_id="RULE_ROLE_DELIMITER_HIJACK",
                    description="Detected system instruction role override delimiter",
                    threat_level=ThreatLevel.CRITICAL if depth == 0 else ThreatLevel.HIGH,
                    matched_snippet=match.group(0).strip(),
                    recursion_depth=depth,
                )
            )

        # 2. Markdown breakout
        for match in self.MARKDOWN_BREAKOUT.finditer(text):
            detections.append(
                ThreatDetection(
                    rule_id="RULE_MARKDOWN_BLOCK_BREAKOUT",
                    description="Detected fenced block breakout targeting instruction override",
                    threat_level=ThreatLevel.HIGH,
                    matched_snippet=match.group(0).strip()[:40],
                    recursion_depth=depth,
                )
            )

        # 3. Base64 payload inspection
        for match in self.BASE64_PATTERN.finditer(text):
            encoded = match.group(0)
            if len(encoded) >= 16:
                try:
                    decoded_bytes = base64.b64decode(encoded)
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                    if decoded_str and any(c.isprintable() for c in decoded_str):
                        # Recursive check on decoded content
                        sub_detections: List[ThreatDetection] = []
                        self._analyze_text(decoded_str, depth + 1, sub_detections)
                        if sub_detections:
                            detections.append(
                                ThreatDetection(
                                    rule_id="RULE_RECURSIVE_BASE64_PAYLOAD",
                                    description=f"Base64 payload revealed {len(sub_detections)} nested threat(s)",
                                    threat_level=ThreatLevel.CRITICAL,
                                    matched_snippet=encoded[:32] + "...",
                                    recursion_depth=depth,
                                )
                            )
                            detections.extend(sub_detections)
                except Exception:
                    pass

    def _calculate_highest_threat(self, detections: List[ThreatDetection]) -> ThreatLevel:
        if not detections:
            return ThreatLevel.CLEAN
        levels = [d.threat_level for d in detections]
        for lvl in [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.LOW]:
            if lvl in levels:
                return lvl
        return ThreatLevel.CLEAN
