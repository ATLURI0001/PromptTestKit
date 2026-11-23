"""Tests for Prompt Evaluation Latency Profiler & Token Drift Diagnostic."""

import pytest
from scripts.benchmark_telemetry import (
    DriftDirection,
    EvalHealthState,
    EvalMetricRecord,
    PromptBenchmarkTelemetryProfiler,
)


def test_profiler_initialization_and_validation():
    with pytest.raises(ValueError, match="suite_id must be a non-empty string"):
        PromptBenchmarkTelemetryProfiler("")

    with pytest.raises(ValueError, match="baseline_completion_tokens must be positive"):
        PromptBenchmarkTelemetryProfiler("test-suite", baseline_completion_tokens=0)

    profiler = PromptBenchmarkTelemetryProfiler("suite-alpha", baseline_completion_tokens=100.0)
    assert profiler.suite_id == "suite-alpha"
    assert profiler.baseline_tokens == 100.0

    # Empty report check
    rep = profiler.generate_report()
    assert rep.sample_count == 0
    assert rep.health_state == EvalHealthState.HEALTHY
    assert rep.drift_direction == DriftDirection.STABLE


def test_record_eval_and_percentiles():
    profiler = PromptBenchmarkTelemetryProfiler("suite-beta", baseline_completion_tokens=50.0)

    with pytest.raises(ValueError, match="eval_id must be a non-empty string"):
        profiler.record_eval("", 10, 20, 100.0, 1000.0)

    with pytest.raises(ValueError, match="Token counts cannot be negative"):
        profiler.record_eval("e-1", -1, 20, 100.0, 1000.0)

    # Record 100 samples with varying latencies
    for i in range(1, 101):
        profiler.record_eval(
            eval_id=f"eval-{i}",
            prompt_tokens=20,
            completion_tokens=50,
            latency_ms=float(i * 10),
            timestamp=1000.0 + i,
        )

    pcts = profiler.get_percentiles()
    assert pcts["p50"] == 510.0
    assert pcts["p90"] == 910.0
    assert pcts["p99"] == 1000.0


def test_token_drift_and_health_state_transitions():
    # Baseline 100 tokens, drift threshold 25%
    profiler = PromptBenchmarkTelemetryProfiler(
        "suite-gamma",
        baseline_completion_tokens=100.0,
        drift_threshold_pct=25.0,
        latency_p90_limit_ms=500.0,
    )

    # 1. Normal operations (HEALTHY)
    for i in range(10):
        profiler.record_eval(f"e-norm-{i}", 50, 105, 200.0, 1000.0 + i)

    rep1 = profiler.generate_report()
    assert rep1.health_state == EvalHealthState.HEALTHY
    assert rep1.drift_direction == DriftDirection.STABLE
    assert rep1.avg_tokens_per_sec > 0

    # 2. Token expansion drift > 25% (DEGRADED)
    profiler2 = PromptBenchmarkTelemetryProfiler(
        "suite-expansion",
        baseline_completion_tokens=100.0,
        drift_threshold_pct=25.0,
    )
    for i in range(10):
        profiler2.record_eval(f"e-exp-{i}", 50, 140, 200.0, 1000.0 + i)  # +40% expansion

    rep2 = profiler2.generate_report()
    assert rep2.health_state == EvalHealthState.DEGRADED
    assert rep2.drift_direction == DriftDirection.EXPANSION
    assert rep2.drift_percentage == 40.0

    # 3. High error rate > 15% (CRITICAL)
    profiler3 = PromptBenchmarkTelemetryProfiler("suite-crit", baseline_completion_tokens=100.0)
    for i in range(10):
        profiler3.record_eval(f"e-err-{i}", 50, 100, 200.0, 1000.0 + i, error=(i < 3))

    rep3 = profiler3.generate_report()
    assert rep3.health_state == EvalHealthState.CRITICAL
    assert rep3.error_rate == 0.3


def test_format_markdown_report():
    profiler = PromptBenchmarkTelemetryProfiler("suite-report", baseline_completion_tokens=100.0)
    profiler.record_eval("e-1", 30, 95, 250.0, 1000.0)
    md = profiler.format_markdown_report()
    assert "### Benchmark Telemetry Diagnostic Report (suite-report)" in md
    assert "**Health State**: `HEALTHY`" in md
    assert "**Token Velocity**:" in md
