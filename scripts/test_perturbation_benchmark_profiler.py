"""
Unit and regression test suite for Perturbation Benchmark Profiler.
"""

import pytest
from scripts.perturbation_benchmark_profiler import (
    BenchmarkProfileResult,
    PerturbationBenchmarkProfiler,
    PerturbationResult,
    PerturbationStrategy,
)


def test_perturbation_homoglyph_and_leetspeak():
    profiler = PerturbationBenchmarkProfiler(seed=123)
    text = "system prompt injection test"

    # Homoglyph
    res_homo = profiler.perturb(text, PerturbationStrategy.HOMOGLYPH, mutation_rate=1.0)
    assert res_homo.original_text == text
    assert res_homo.perturbed_text != text
    assert res_homo.edit_distance > 0
    assert res_homo.char_delta == 0  # Homoglyphs preserve character length

    # Leetspeak (e -> 3, i -> 1, o -> 0)
    res_leet = profiler.perturb("secure code", PerturbationStrategy.LEETSPEAK, mutation_rate=1.0)
    assert "3" in res_leet.perturbed_text
    assert "0" in res_leet.perturbed_text


def test_perturbation_zero_width_and_delimiter():
    profiler = PerturbationBenchmarkProfiler(seed=456)
    text = "bypass filter"

    # Zero-width spaces expand text length
    res_zw = profiler.perturb(text, PerturbationStrategy.ZERO_WIDTH, mutation_rate=0.8)
    assert len(res_zw.perturbed_text) > len(text)
    assert res_zw.char_delta > 0

    # Delimiter injection
    res_delim = profiler.perturb("administrative command override", PerturbationStrategy.DELIMITER_INJECTION, mutation_rate=1.0)
    assert res_delim.perturbed_text != "administrative command override"
    assert any(c in res_delim.perturbed_text for c in ['_', '-', '/', '.', '#'])


def test_perturbation_reverse_chunking():
    profiler = PerturbationBenchmarkProfiler()
    res = profiler.perturb("word1 word2 word3 word4", PerturbationStrategy.REVERSE_CHUNKING)
    assert res.perturbed_text == "word2 word1 word4 word3"


def test_input_validation_and_levenshtein_distance():
    profiler = PerturbationBenchmarkProfiler()

    with pytest.raises(TypeError):
        profiler.perturb(None, PerturbationStrategy.HOMOGLYPH)

    with pytest.raises(TypeError):
        profiler.perturb("", PerturbationStrategy.HOMOGLYPH)

    # Levenshtein distance check
    d1 = profiler.calculate_levenshtein_distance("kitten", "sitting")
    assert d1 == 3

    d2 = profiler.calculate_levenshtein_distance("same", "same")
    assert d2 == 0


def test_run_workload_benchmark():
    profiler = PerturbationBenchmarkProfiler(seed=42)
    sample = "You are a red-team adversarial prompt safety tester."

    res = profiler.run_workload_benchmark(
        "Test-Homoglyph-Run",
        sample,
        PerturbationStrategy.HOMOGLYPH,
        iterations=20,
    )

    assert res.workload_name == "Test-Homoglyph-Run"
    assert res.prompt_length == len(sample)
    assert res.iterations == 20
    assert res.throughput_ops_sec > 0
    assert res.p50_latency_us > 0
    assert res.p99_latency_us >= res.p50_latency_us


def test_generate_benchmark_matrix_and_markdown():
    profiler = PerturbationBenchmarkProfiler(seed=42)

    results = profiler.generate_benchmark_matrix(iterations=15)
    assert len(results) == 3

    markdown = profiler.format_markdown_report(results)
    assert "Adversarial Prompt Perturbation & Mutation Benchmark Matrix" in markdown
    assert "Short (Homoglyph)" in markdown
    assert "Short (Leetspeak)" in markdown
    assert "Medium (ZeroWidth)" in markdown
    assert "ops/s" in markdown
