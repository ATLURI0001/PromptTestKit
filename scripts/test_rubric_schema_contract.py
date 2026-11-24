"""Tests for RubricSchemaContract and score boundary invariant guard."""

import math
import pytest
from scripts.rubric_schema_contract import (
    DimensionMissingError,
    DimensionScale,
    DimensionUnexpectedError,
    EvaluationAssessment,
    RubricContractError,
    RubricDimension,
    RubricSchemaContract,
    ScoreBoundaryViolationError,
    WeightNormalizationError,
)


@pytest.fixture
def sample_rubric():
    dims = [
        RubricDimension(name="safety", scale=DimensionScale.BINARY, weight=0.4, threshold=1.0),
        RubricDimension(name="factual_accuracy", scale=DimensionScale.LIKERT_5, weight=0.3, threshold=4.0),
        RubricDimension(name="adherence", scale=DimensionScale.PERCENTAGE, weight=0.3, threshold=80.0),
    ]
    return RubricSchemaContract(rubric_id="production-qa-v1", dimensions=dims)


def test_nominal_evaluation_validation(sample_rubric):
    scores = {
        "safety": 1.0,
        "factual_accuracy": 5.0,
        "adherence": 95.0,
    }
    assessment = sample_rubric.validate_and_score("judge-claude-3-opus", scores)
    assert assessment.passed is True
    assert len(assessment.verdict_reasons) == 0
    assert assessment.normalized_composite_score > 90.0
    assert len(assessment.assessment_digest) == 64


def test_weight_normalization_enforcement():
    # Weights do not sum to 1.0
    with pytest.raises(WeightNormalizationError):
        RubricSchemaContract(
            rubric_id="bad-weights",
            dimensions=[
                RubricDimension(name="d1", scale=DimensionScale.BINARY, weight=0.5, threshold=1.0),
                RubricDimension(name="d2", scale=DimensionScale.BINARY, weight=0.4, threshold=1.0),
            ],
        )

    # Zero or negative weight
    with pytest.raises(WeightNormalizationError):
        RubricSchemaContract(
            rubric_id="negative-weight",
            dimensions=[
                RubricDimension(name="d1", scale=DimensionScale.BINARY, weight=-0.2, threshold=1.0),
                RubricDimension(name="d2", scale=DimensionScale.BINARY, weight=1.2, threshold=1.0),
            ],
        )


def test_missing_and_unexpected_dimensions(sample_rubric):
    # Missing 'adherence'
    with pytest.raises(DimensionMissingError) as exc_info:
        sample_rubric.validate_and_score("judge-1", {"safety": 1.0, "factual_accuracy": 4.0})
    assert "adherence" in str(exc_info.value)

    # Unexpected extra dimension in strict mode
    with pytest.raises(DimensionUnexpectedError) as exc_info:
        sample_rubric.validate_and_score(
            "judge-1",
            {"safety": 1.0, "factual_accuracy": 4.0, "adherence": 90.0, "hallucinated_dim": 10.0},
        )
    assert "hallucinated_dim" in str(exc_info.value)


def test_score_boundary_and_finite_invariants(sample_rubric):
    # Out of bounds binary
    with pytest.raises(ScoreBoundaryViolationError):
        sample_rubric.validate_and_score("j1", {"safety": 1.5, "factual_accuracy": 4.0, "adherence": 90.0})

    # Out of bounds Likert (< 1.0)
    with pytest.raises(ScoreBoundaryViolationError):
        sample_rubric.validate_and_score("j1", {"safety": 1.0, "factual_accuracy": 0.5, "adherence": 90.0})

    # Out of bounds Percentage (> 100)
    with pytest.raises(ScoreBoundaryViolationError):
        sample_rubric.validate_and_score("j1", {"safety": 1.0, "factual_accuracy": 4.0, "adherence": 105.0})

    # Non-finite scores (NaN / Inf)
    with pytest.raises(ScoreBoundaryViolationError):
        sample_rubric.validate_and_score("j1", {"safety": float("nan"), "factual_accuracy": 4.0, "adherence": 90.0})

    with pytest.raises(ScoreBoundaryViolationError):
        sample_rubric.validate_and_score("j1", {"safety": 1.0, "factual_accuracy": float("inf"), "adherence": 90.0})


def test_threshold_failure_verdict(sample_rubric):
    scores = {
        "safety": 0.0, # Fails threshold 1.0
        "factual_accuracy": 3.0, # Fails threshold 4.0
        "adherence": 85.0, # Passes threshold 80.0
    }
    assessment = sample_rubric.validate_and_score("judge-2", scores)
    assert assessment.passed is False
    assert len(assessment.verdict_reasons) == 2
    assert any("safety" in r for r in assessment.verdict_reasons)
    assert any("factual_accuracy" in r for r in assessment.verdict_reasons)
