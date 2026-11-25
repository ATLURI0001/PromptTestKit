import pytest
from scripts.prompt_eval_telemetry import (
    PromptEvalLatencyRotary,
    EvalStatus,
    EvalRecord,
)


def test_record_and_get_summary():
    rotary = PromptEvalLatencyRotary(capacity=100)

    # 4 records: 3 PASS, 1 BREACH
    base_ts = 1000.0
    rotary.record_evaluation("p1", "claude-3-opus", eval_latency_ms=100.0, token_count=500, status=EvalStatus.PASS, timestamp=base_ts + 1)
    rotary.record_evaluation("p2", "claude-3-opus", eval_latency_ms=200.0, token_count=600, status=EvalStatus.PASS, timestamp=base_ts + 2)
    rotary.record_evaluation("p3", "gpt-4o", eval_latency_ms=150.0, token_count=400, status=EvalStatus.PASS, timestamp=base_ts + 3)
    rotary.record_evaluation("p4", "gpt-4o", eval_latency_ms=400.0, token_count=800, status=EvalStatus.BREACH, timestamp=base_ts + 4)

    summary = rotary.get_summary()
    assert summary.total_evals == 4
    assert summary.pass_rate_pct == 75.0
    assert summary.breach_rate_pct == 25.0
    assert summary.error_rate_pct == 0.0
    assert summary.total_tokens == 2300
    assert summary.p50_latency_ms == 150.0
    assert summary.p90_latency_ms == 400.0
    assert summary.mean_latency_ms == 212.5

    assert "claude-3-opus" in summary.model_breakdown
    assert summary.model_breakdown["claude-3-opus"]["pass_rate_pct"] == 100.0
    assert summary.model_breakdown["gpt-4o"]["pass_rate_pct"] == 50.0


def test_rotary_buffer_capacity_eviction():
    rotary = PromptEvalLatencyRotary(capacity=3)

    rotary.record_evaluation("p1", "m1", 10.0, 100)
    rotary.record_evaluation("p2", "m1", 20.0, 100)
    rotary.record_evaluation("p3", "m1", 30.0, 100)
    rotary.record_evaluation("p4", "m1", 40.0, 100)  # Evicts p1

    summary = rotary.get_summary()
    assert summary.total_evals == 3
    assert summary.p50_latency_ms == 30.0  # [20, 30, 40]


def test_empty_buffer_summary():
    rotary = PromptEvalLatencyRotary(capacity=50)
    summary = rotary.get_summary()
    assert summary.total_evals == 0
    assert summary.pass_rate_pct == 0.0
    assert summary.tokens_per_second == 0.0


def test_prometheus_metrics_export():
    rotary = PromptEvalLatencyRotary(capacity=100)
    rotary.record_evaluation("p1", "claude-3-5-sonnet", 120.0, 1500, EvalStatus.PASS)

    prom = rotary.export_prometheus_metrics()
    assert "prompt_eval_total 1" in prom
    assert "prompt_eval_pass_rate_pct 100.0" in prom
    assert 'prompt_eval_model_pass_rate{model="claude-3-5-sonnet"} 100.0' in prom


def test_invalid_arguments():
    rotary = PromptEvalLatencyRotary(capacity=10)
    with pytest.raises(ValueError):
        rotary.record_evaluation("", "m1", 100.0, 100)

    with pytest.raises(ValueError):
        rotary.record_evaluation("p1", "", 100.0, 100)

    with pytest.raises(ValueError):
        rotary.record_evaluation("p1", "m1", -5.0, 100)

    with pytest.raises(ValueError):
        PromptEvalLatencyRotary(capacity=0)
