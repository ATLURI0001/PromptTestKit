"""Honeytoken Canary Vault & Prompt Context Exfiltration Detection Engine.

Generates cryptographic canary tokens to embed into system prompts and evaluates
model generation outputs for exact, partial, or fuzzy leak exfiltration.
"""

from __future__ import annotations

import hmac
import hashlib
import secrets
import time
from typing import Dict, List, Optional, Tuple


class CanaryTokenVault:
    """Manages high-entropy honeytoken canaries and detects exfiltration leaks."""

    def __init__(self, secret_key: Optional[str] = None, default_ttl_sec: int = 3600):
        self.secret_key = (secret_key or secrets.token_hex(16)).encode("utf-8")
        self.default_ttl_sec = default_ttl_sec
        # Map of token_string -> { label, created_at, expires_at, is_compromised, exfiltrated_at }
        self._tokens: Dict[str, Dict[str, object]] = {}

    def issue_canary(self, label: str = "sysprompt", ttl_sec: Optional[int] = None) -> str:
        """Issues a new cryptographic honeytoken canary."""
        ttl = ttl_sec if ttl_sec is not None else self.default_ttl_sec
        now = time.time()
        rand_bytes = secrets.token_bytes(8)
        sig = hmac.new(self.secret_key, rand_bytes, hashlib.sha256).hexdigest()[:12]
        token_str = f"PTK_CANARY_{label.upper()}_{sig}"

        self._tokens[token_str] = {
            "label": label,
            "created_at": now,
            "expires_at": now + ttl,
            "is_compromised": False,
            "exfiltrated_at": None,
        }
        return token_str

    def scan_output(self, response_text: str, fuzzy_threshold: float = 0.85) -> Dict[str, object]:
        """Scans generation text for active honeytoken leakage."""
        if not response_text or not isinstance(response_text, str):
            return {
                "leaked": False,
                "matches": [],
                "compromised_count": 0,
            }

        now = time.time()
        matches: List[Dict[str, object]] = []

        for token_str, meta in self._tokens.items():
            # Skip expired tokens
            if now > float(meta["expires_at"]):
                continue

            # 1. Exact Substring Match
            if token_str in response_text:
                meta["is_compromised"] = True
                meta["exfiltrated_at"] = now
                matches.append({
                    "canary_token": token_str,
                    "label": meta["label"],
                    "match_type": "EXACT",
                    "similarity": 1.0,
                })
                continue

            # 2. Check token signature suffix (in case prefix was truncated)
            sig = token_str.split("_")[-1]
            if len(sig) >= 8 and sig in response_text:
                meta["is_compromised"] = True
                meta["exfiltrated_at"] = now
                matches.append({
                    "canary_token": token_str,
                    "label": meta["label"],
                    "match_type": "SIGNATURE_FRAGMENT",
                    "similarity": 0.90,
                })
                continue

            # 3. Fuzzy Normalized Distance Search
            words = response_text.split()
            for w in words:
                clean_w = "".join(c for c in w if c.isalnum() or c == "_")
                if len(clean_w) >= len(token_str) - 3:
                    sim = self._similarity(token_str, clean_w)
                    if sim >= fuzzy_threshold:
                        meta["is_compromised"] = True
                        meta["exfiltrated_at"] = now
                        matches.append({
                            "canary_token": token_str,
                            "label": meta["label"],
                            "match_type": "FUZZY_PERTURBATION",
                            "similarity": round(sim, 4),
                        })
                        break

        return {
            "leaked": len(matches) > 0,
            "matches": matches,
            "compromised_count": len(matches),
        }

    def revoke_canary(self, token_str: str) -> bool:
        """Manually revokes an active canary."""
        return self._tokens.pop(token_str, None) is not None

    def get_token_status(self, token_str: str) -> Optional[Dict[str, object]]:
        """Retrieves audit metadata for a canary."""
        meta = self._tokens.get(token_str)
        if not meta:
            return None
        return dict(meta)

    @staticmethod
    def _similarity(s1: str, s2: str) -> float:
        """Computes bigram Dice coefficient for fuzzy matching."""
        if s1 == s2:
            return 1.0
        if len(s1) < 2 or len(s2) < 2:
            return 0.0

        bg1 = [s1[i:i+2] for i in range(len(s1) - 1)]
        bg2 = [s2[i:i+2] for i in range(len(s2) - 1)]

        intersection = sum(1 for b in bg1 if b in bg2)
        total = len(bg1) + len(bg2)
        return (2.0 * intersection) / total if total > 0 else 0.0
