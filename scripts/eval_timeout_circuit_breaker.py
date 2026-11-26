"""LLM evaluation timeout & fallback circuit breaker for PromptTestKit.

Provides per-judge evaluation timeout shielding, automated fallback scoring
via heuristic verification, exponential backoff with jitter, and half-open canary recovery
to prevent CI/CD test suite hangs and upstream inference pipeline stalls.
"""

from __future__ import annotations

import enum
import math
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


class EvalCircuitState(str, enum.Enum):
    CLOSED = "CLOSED"        # Normal judge invocation
    OPEN = "OPEN"            # Timeout trip; route to fallback heuristic
    HALF_OPEN = "HALF_OPEN"  # Canary probing allowed to test judge recovery


class EvalVerdict(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    DEGRADED_PASS = "DEGRADED_PASS"
    DEGRADED_FAIL = "DEGRADED_FAIL"
    SHED = "SHED"


@dataclass
class JudgeEvaluationRequest:
    judge_id: str
    prompt_id: str
    output_text: str
    expected_keywords: List[str] = field(default_factory=list)
    forbidden_patterns: List[str] = field(default_factory=list)
    min_length_chars: int = 1
    max_length_chars: int = 100000


@dataclass
class JudgeEvaluationResponse:
    judge_id: str
    prompt_id: str
    verdict: EvalVerdict
    score: float
    is_fallback: bool
    circuit_state: EvalCircuitState
    latency_ms: float
    details: str = ""


class EvalTimeoutCircuitBreaker:
    """Production-grade timeout protection and heuristic fallback for LLM judges."""

    def __init__(
        self,
        judge_id: str,
        timeout_sec: float = 2.0,
        consecutive_timeouts_to_open: int = 2,
        base_cooldown_sec: float = 5.0,
        max_cooldown_sec: float = 120.0,
        half_open_probe_limit: int = 2,
        jitter_factor: float = 0.1,
    ) -> None:
        self.judge_id = judge_id
        self.timeout_sec = max(0.001, timeout_sec)
        self.consecutive_timeouts_to_open = max(1, consecutive_timeouts_to_open)
        self.base_cooldown_sec = base_cooldown_sec
        self.max_cooldown_sec = max_cooldown_sec
        self.half_open_probe_limit = half_open_probe_limit
        self.jitter_factor = jitter_factor

        self.state = EvalCircuitState.CLOSED
        self._consecutive_timeouts: int = 0
        self._consecutive_backoff_steps: int = 0
        self._opened_at: Optional[float] = None
        self._cooldown_duration: float = base_cooldown_sec
        self._probes_in_flight: int = 0
        self._successful_canary_count: int = 0

        self.total_evaluations: int = 0
        self.fallback_evaluations: int = 0
        self.timeouts_intercepted: int = 0

    def _calculate_cooldown(self) -> float:
        mult = 2 ** min(self._consecutive_backoff_steps, 5)
        raw = min(self.max_cooldown_sec, self.base_cooldown_sec * mult)
        jitter = raw * self.jitter_factor
        return max(0.1, raw + random.uniform(-jitter, jitter))

    def evaluate(
        self,
        request: JudgeEvaluationRequest,
        judge_callable: Callable[[JudgeEvaluationRequest], Tuple[bool, float, str]],
        now: Optional[float] = None,
    ) -> JudgeEvaluationResponse:
        """Executes judge evaluation or falls back immediately if circuit is open or timed out."""
        current_time = now if now is not None else time.time()
        self.total_evaluations += 1

        # Check OPEN cooldown expiration
        if self.state == EvalCircuitState.OPEN:
            assert self._opened_at is not None
            if current_time >= self._opened_at + self._cooldown_duration:
                self.state = EvalCircuitState.HALF_OPEN
                self._probes_in_flight = 0
                self._successful_canary_count = 0

        # Route according to state
        if self.state == EvalCircuitState.OPEN:
            self.fallback_evaluations += 1
            return self._execute_fallback(request, current_time, "Judge circuit is OPEN due to repeated timeouts")

        # In CLOSED or HALF_OPEN: Attempt primary judge call
        if self.state == EvalCircuitState.HALF_OPEN:
            if self._probes_in_flight >= self.half_open_probe_limit:
                # Canary slots full, route remaining to fallback
                self.fallback_evaluations += 1
                return self._execute_fallback(request, current_time, "HALF_OPEN canary capacity full")
            self._probes_in_flight += 1

        # Execute primary judge with wall-clock timeout detection
        t_start = time.perf_counter()
        try:
            passed, score, details = judge_callable(request)
            elapsed_sec = time.perf_counter() - t_start
            latency_ms = round(elapsed_sec * 1000.0, 2)

            if elapsed_sec > self.timeout_sec:
                # Execution took longer than timeout deadline
                return self._handle_timeout(request, current_time, latency_ms)

            # Success
            self._handle_success()
            verdict = EvalVerdict.PASS if passed else EvalVerdict.FAIL
            return JudgeEvaluationResponse(
                judge_id=self.judge_id,
                prompt_id=request.prompt_id,
                verdict=verdict,
                score=score,
                is_fallback=False,
                circuit_state=self.state,
                latency_ms=latency_ms,
                details=details,
            )

        except TimeoutError:
            elapsed_sec = time.perf_counter() - t_start
            return self._handle_timeout(request, current_time, round(elapsed_sec * 1000.0, 2))
        except Exception as ex:
            # Treat unexpected judge crash/error as failure
            elapsed_sec = time.perf_counter() - t_start
            return self._handle_timeout(request, current_time, round(elapsed_sec * 1000.0, 2), error_msg=str(ex))

    def _handle_timeout(
        self,
        request: JudgeEvaluationRequest,
        current_time: float,
        latency_ms: float,
        error_msg: Optional[str] = None,
    ) -> JudgeEvaluationResponse:
        """Handles timeout or failure, tripping breaker if thresholds exceeded."""
        self.timeouts_intercepted += 1
        self.fallback_evaluations += 1
        self._consecutive_timeouts += 1

        reason = error_msg or f"Judge timed out after {latency_ms}ms (limit: {self.timeout_sec * 1000:.0f}ms)"

        if self.state == EvalCircuitState.HALF_OPEN:
            # Canary probe failed -> immediately trip back to OPEN
            self.state = EvalCircuitState.OPEN
            self._consecutive_backoff_steps += 1
            self._opened_at = current_time
            self._cooldown_duration = self._calculate_cooldown()
            self._probes_in_flight = 0
        elif self.state == EvalCircuitState.CLOSED:
            if self._consecutive_timeouts >= self.consecutive_timeouts_to_open:
                self.state = EvalCircuitState.OPEN
                self._opened_at = current_time
                self._cooldown_duration = self._calculate_cooldown()

        return self._execute_fallback(request, current_time, reason)

    def _handle_success(self) -> None:
        self._consecutive_timeouts = 0
        if self.state == EvalCircuitState.HALF_OPEN:
            self._successful_canary_count += 1
            if self._successful_canary_count >= self.half_open_probe_limit:
                # Circuit fully recovers
                self.state = EvalCircuitState.CLOSED
                self._consecutive_backoff_steps = 0
                self._opened_at = None
                self._probes_in_flight = 0

    def _execute_fallback(
        self,
        request: JudgeEvaluationRequest,
        now: float,
        reason: str,
    ) -> JudgeEvaluationResponse:
        """Executes fast, deterministic heuristic evaluation on output text."""
        text = request.output_text
        length = len(text)

        # 1. Length check
        if length < request.min_length_chars or length > request.max_length_chars:
            return JudgeEvaluationResponse(
                judge_id=self.judge_id,
                prompt_id=request.prompt_id,
                verdict=EvalVerdict.DEGRADED_FAIL,
                score=0.0,
                is_fallback=True,
                circuit_state=self.state,
                latency_ms=0.1,
                details=f"[Fallback] Length violation ({length} chars). Reason: {reason}",
            )

        # 2. Forbidden pattern checks
        for pat in request.forbidden_patterns:
            if re.search(pat, text, re.IGNORECASE):
                return JudgeEvaluationResponse(
                    judge_id=self.judge_id,
                    prompt_id=request.prompt_id,
                    verdict=EvalVerdict.DEGRADED_FAIL,
                    score=0.1,
                    is_fallback=True,
                    circuit_state=self.state,
                    latency_ms=0.1,
                    details=f"[Fallback] Forbidden pattern matched: '{pat}'. Reason: {reason}",
                )

        # 3. Expected keyword checks
        matched_keywords = 0
        for kw in request.expected_keywords:
            if re.search(re.escape(kw), text, re.IGNORECASE):
                matched_keywords += 1

        total_kw = len(request.expected_keywords)
        kw_ratio = (matched_keywords / total_kw) if total_kw > 0 else 1.0

        if kw_ratio >= 0.75:
            verdict = EvalVerdict.DEGRADED_PASS
            score = 0.85 * kw_ratio
        else:
            verdict = EvalVerdict.DEGRADED_FAIL
            score = 0.40 * kw_ratio

        return JudgeEvaluationResponse(
            judge_id=self.judge_id,
            prompt_id=request.prompt_id,
            verdict=verdict,
            score=round(score, 2),
            is_fallback=True,
            circuit_state=self.state,
            latency_ms=0.1,
            details=f"[Fallback] Heuristic keyword match: {matched_keywords}/{total_kw}. Reason: {reason}",
        )


class MultiJudgeCircuitRegistry:
    """Coordinates independent timeout circuit breakers across multi-judge configurations."""

    def __init__(self) -> None:
        self._breakers: Dict[str, EvalTimeoutCircuitBreaker] = {}

    def get_or_create(self, judge_id: str, **kwargs: Any) -> EvalTimeoutCircuitBreaker:
        if judge_id not in self._breakers:
            self._breakers[judge_id] = EvalTimeoutCircuitBreaker(judge_id=judge_id, **kwargs)
        return self._breakers[judge_id]
