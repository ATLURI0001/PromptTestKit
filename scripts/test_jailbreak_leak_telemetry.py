"""
Tests for Jailbreak Resistance Velocity & Canary Token Leak Telemetry Rotary.
"""

import pytest
from scripts.jailbreak_leak_telemetry import (
    AttackObservation,
    AttackOutcome,
    AttackVector,
    JailbreakTelemetryRotary,
)


def test_record_attack_and_validation() -> None:
    rotary = JailbreakTelemetryRotary(capacity=50)

    obs = rotary.record_attack(
        attack_id="atk-001",
        target_model="llama-3-70b",
        vector=AttackVector.ROLEPLAY_PROMPT,
        outcome=AttackOutcome.BLOCKED,
        canary_leaked=False,
        latency_ms=120.0,
        risk_score=0.85,
    )
    assert obs.attack_id == "atk-001"
    assert obs.target_model == "llama-3-70b"
    assert obs.outcome == AttackOutcome.BLOCKED

    # Test invalid attack_id
    with pytest.raises(ValueError):
        rotary.record_attack("", "model", AttackVector.BASE64_POLYGLOT, AttackOutcome.BLOCKED)


def test_summary_metrics_and_percentiles() -> None:
    rotary = JailbreakTelemetryRotary(capacity=100)

    # Record 4 attacks
    rotary.record_attack("atk-1", "gpt-4o", AttackVector.DELIMITER_ESCAPE, AttackOutcome.BLOCKED, risk_score=0.2)
    rotary.record_attack("atk-2", "gpt-4o", AttackVector.ROLEPLAY_PROMPT, AttackOutcome.BLOCKED, risk_score=0.4)
    rotary.record_attack("atk-3", "gpt-4o", AttackVector.BASE64_POLYGLOT, AttackOutcome.LEAK_DETECTED, canary_leaked=True, risk_score=0.9)
    rotary.record_attack("atk-4", "gpt-4o", AttackVector.AFFIRMATIVE_PRIMING, AttackOutcome.BLOCKED, risk_score=0.6)

    summary = rotary.get_summary()
    assert summary.total_attacks == 4
    assert summary.total_blocked == 3
    assert summary.total_leaks == 1
    assert summary.defense_efficacy_pct == 75.0
    assert summary.leak_rate_pct == 25.0
    assert summary.p50_risk_score >= 0.4
    assert summary.model_breakdown["gpt-4o"]["defense_efficacy_pct"] == 75.0


def test_prometheus_metrics_export() -> None:
    rotary = JailbreakTelemetryRotary()
    rotary.record_attack("atk-a", "claude-3-opus", AttackVector.HYPOTHETICAL_SCENARIO, AttackOutcome.BLOCKED)
    rotary.record_attack("atk-b", "claude-3-opus", AttackVector.BASE64_POLYGLOT, AttackOutcome.LEAK_DETECTED, canary_leaked=True)

    metrics = rotary.export_prometheus_metrics()
    assert "prompttestkit_jailbreak_attacks_total" in metrics
    assert 'model="claude-3-opus"' in metrics
    assert "prompttestkit_canary_leaks_total" in metrics
    assert "prompttestkit_defense_efficacy_ratio" in metrics


def test_rotary_capacity_eviction() -> None:
    capacity = 10
    rotary = JailbreakTelemetryRotary(capacity=capacity)
    for i in range(25):
        rotary.record_attack(f"atk-{i}", "test-model", AttackVector.ROLEPLAY_PROMPT, AttackOutcome.BLOCKED)

    summary = rotary.get_summary()
    assert summary.total_attacks == capacity
