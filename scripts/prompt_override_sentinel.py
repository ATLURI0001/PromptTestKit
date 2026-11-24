"""
System Prompt Override & Role-Play Hijack Failsafe Sentinel.

Provides defense-in-depth against structural system prompt boundary escapes,
identity role-inversion, obfuscated base64 payload injection, and hypothetical
jailbreak simulation pretexts.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class OverrideThreatSeverity(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Delimiter and tag injection patterns attempting to emulate or break system context
STRUCTURAL_BOUNDARY_PATTERNS = [
    re.compile(r"<\s*/?\s*(?:system|context|instruction|admin|developer)\s*>", re.IGNORECASE),
    re.compile(r"\[\s*/?\s*(?:SYSTEM|ADMIN|DEVELOPER|ROOT)\s*\]", re.IGNORECASE),
    re.compile(r"<<\s*/?\s*SYS\s*>>", re.IGNORECASE),
    re.compile(r"-{3,}\s*(?:BEGIN|END)\s+(?:SYSTEM|PROMPT|INSTRUCTIONS?)\s*-{3,}", re.IGNORECASE),
    re.compile(r"\{\s*\"(?:role|system_instruction)\"\s*:\s*\"system\"", re.IGNORECASE),
]

# Role-inversion, identity hijacking, and instruction-override directives
ROLE_INVERSION_PATTERNS = [
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|directives?|rules?|prompts?)\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(?:all\s+)?(?:safety|guidelines?|policies|instructions?|rules?)\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|unrestricted|god|dan|jailbreak|maintenance)\s+mode\b", re.IGNORECASE),
    re.compile(r"\bpretend\s+(?:you\s+have\s+no\s+rules|you\s+can\s+do\s+anything|to\s+be\s+an\s+unfiltered)\b", re.IGNORECASE),
    re.compile(r"\bfrom\s+now\s+on\s*,\s*you\s+(?:will|must)\s+(?:obey|follow\s+only|act\s+as)\b", re.IGNORECASE),
    re.compile(r"\boverride\s+system\s+(?:prompt|instructions?|constraints?)\b", re.IGNORECASE),
]

BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


@dataclass(frozen=True)
class OverrideInspectionResult:
    threat_severity: OverrideThreatSeverity
    risk_score: float
    is_mitigated: bool
    sanitized_prompt: str
    detected_violations: List[str]
    structural_triggers: List[str]


class PromptOverrideSentinel:
    """
    Defensive security sentinel inspecting and sanitizing prompts against override attempts.
    """

    def __init__(
        self,
        risk_threshold_critical: float = 0.70,
        risk_threshold_high: float = 0.40,
        max_prompt_length: int = 100_000,
    ) -> None:
        self.risk_threshold_critical = risk_threshold_critical
        self.risk_threshold_high = risk_threshold_high
        self.max_prompt_length = max_prompt_length
        self._stats: Dict[str, int] = {
            "total_inspected": 0,
            "clean_count": 0,
            "suspicious_count": 0,
            "high_threat_count": 0,
            "critical_threat_count": 0,
            "boundary_escapes_blocked": 0,
            "role_inversions_blocked": 0,
            "obfuscated_injections_blocked": 0,
        }

    def inspect_and_sanitize(self, prompt: str) -> OverrideInspectionResult:
        """
        Inspects incoming prompt for structural escapes, role inversions, and obfuscated payloads.
        Returns evaluation result with sanitized prompt text.
        """
        self._stats["total_inspected"] += 1

        if not isinstance(prompt, str) or not prompt.strip():
            self._stats["clean_count"] += 1
            return OverrideInspectionResult(
                threat_severity=OverrideThreatSeverity.CLEAN,
                risk_score=0.0,
                is_mitigated=False,
                sanitized_prompt=prompt if isinstance(prompt, str) else "",
                detected_violations=[],
                structural_triggers=[],
            )

        truncated_prompt = prompt[: self.max_prompt_length]
        detected_violations: List[str] = []
        structural_triggers: List[str] = []
        sanitized_text = truncated_prompt
        score = 0.0

        # 1. Structural Boundary Escape Scan
        for pattern in STRUCTURAL_BOUNDARY_PATTERNS:
            matches = pattern.findall(truncated_prompt)
            if matches:
                detected_violations.append(f"Structural boundary escape: '{matches[0]}'")
                structural_triggers.extend([str(m) for m in matches])
                score += 0.45 * len(matches)
                sanitized_text = pattern.sub("[SANITIZED_DELIMITER]", sanitized_text)
                self._stats["boundary_escapes_blocked"] += len(matches)

        # 2. Role Inversion & Override Directive Scan
        for pattern in ROLE_INVERSION_PATTERNS:
            matches = pattern.findall(truncated_prompt)
            if matches:
                detected_violations.append(f"Role inversion directive: '{matches[0]}'")
                structural_triggers.extend([str(m) for m in matches])
                score += 0.50 * len(matches)
                sanitized_text = pattern.sub("[SANITIZED_DIRECTIVE]", sanitized_text)
                self._stats["role_inversions_blocked"] += len(matches)

        # 3. Base64 Obfuscation Scanner
        for blob in BASE64_BLOB_PATTERN.findall(truncated_prompt):
            try:
                decoded = base64.b64decode(blob, validate=True).decode("utf-8", errors="ignore")
                for pattern in ROLE_INVERSION_PATTERNS:
                    if pattern.search(decoded):
                        detected_violations.append(f"Base64 obfuscated override payload: '{blob[:16]}...'")
                        structural_triggers.append("base64_hidden_override")
                        score += 0.60
                        sanitized_text = sanitized_text.replace(blob, "[SANITIZED_ENCODED_PAYLOAD]")
                        self._stats["obfuscated_injections_blocked"] += 1
                        break
            except Exception:
                continue

        clamped_score = min(1.0, score)

        if clamped_score >= self.risk_threshold_critical:
            severity = OverrideThreatSeverity.CRITICAL
            self._stats["critical_threat_count"] += 1
        elif clamped_score >= self.risk_threshold_high:
            severity = OverrideThreatSeverity.HIGH
            self._stats["high_threat_count"] += 1
        elif clamped_score > 0.0:
            severity = OverrideThreatSeverity.SUSPICIOUS
            self._stats["suspicious_count"] += 1
        else:
            severity = OverrideThreatSeverity.CLEAN
            self._stats["clean_count"] += 1

        is_mitigated = severity in (OverrideThreatSeverity.HIGH, OverrideThreatSeverity.CRITICAL)

        return OverrideInspectionResult(
            threat_severity=severity,
            risk_score=round(clamped_score, 4),
            is_mitigated=is_mitigated,
            sanitized_prompt=sanitized_text,
            detected_violations=detected_violations,
            structural_triggers=structural_triggers,
        )

    def get_audit_telemetry(self) -> Dict[str, Any]:
        return {
            "stats": dict(self._stats),
            "thresholds": {
                "high": self.risk_threshold_high,
                "critical": self.risk_threshold_critical,
            },
        }

    def reset(self) -> None:
        for k in self._stats:
            self._stats[k] = 0
