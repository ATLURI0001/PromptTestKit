"""Tests for the Prompt Evaluation Rubric Spec Contract & Weight Sanitizer."""

import pytest
from scripts.rubric_spec_contract import (
    CURRENT_RUBRIC_VERSION,
    ModelTier,
    ScoringScale,
    compute_rubric_hash,
    parse_and_sanitize_rubric_spec,
)


def test_valid_v2_rubric_spec() -> None:
    raw = {
        "schema_version": CURRENT_RUBRIC_VERSION,
        "rubric_id": "rag-factual-accuracy-v2",
        "model_tier": "advanced",
        "dimensions": [
            {
                "name": "groundedness",
                "weight": 0.5,
                "scale": "score_100",
                "passing_threshold": 80.0,
                "description": "Factual consistency with retrieved reference documents.",
            },
            {
                "name": "conciseness",
                "weight": 0.3,
                "scale": "likert_5",
                "passing_threshold": 3.0,
                "description": "Absence of verbose boilerplate or filler content.",
            },
            {
                "name": "safety_check",
                "weight": 0.2,
                "scale": "binary",
                "passing_threshold": 1.0,
                "description": "Zero injection or toxic output.",
            },
        ],
    }

    rubric = parse_and_sanitize_rubric_spec(raw)
    assert rubric.schema_version == CURRENT_RUBRIC_VERSION
    assert rubric.rubric_id == "rag-factual-accuracy-v2"
    assert rubric.model_tier == ModelTier.ADVANCED
    assert len(rubric.dimensions) == 3

    # Total weight normalized
    total_w = sum(d.weight for d in rubric.dimensions)
    assert abs(total_w - 1.0) < 0.001
    assert len(rubric.rubric_hash) == 64


def test_legacy_v1_rubric_schema_evolution() -> None:
    raw_legacy = {
        "schema_version": "1.0",
        "rubric_id": "legacy-chatbot-eval",
        "dimensions": [
            {
                "name": "tone",
                "scale": "likert_5",
                "passing_threshold": 4.0,
                "description": "Empathetic customer support tone.",
            },
            {
                "name": "resolution",
                "scale": "binary",
                "passing_threshold": 1.0,
                "description": "User problem was addressed.",
            },
        ],
    }

    rubric = parse_and_sanitize_rubric_spec(raw_legacy)
    assert rubric.schema_version == CURRENT_RUBRIC_VERSION
    # In legacy without weights, each of the 2 dimensions gets equal 0.5 weight
    assert rubric.dimensions[0].weight == 0.5
    assert rubric.dimensions[1].weight == 0.5


def test_rubric_spec_validation_errors() -> None:
    # Unsupported version
    with pytest.raises(ValueError, match="Unsupported rubric schema_version"):
        parse_and_sanitize_rubric_spec({
            "schema_version": "99.0",
            "rubric_id": "test",
            "dimensions": [{"name": "d1", "description": "desc"}],
        })

    # Invalid rubric_id
    with pytest.raises(ValueError, match="Invalid rubric_id format"):
        parse_and_sanitize_rubric_spec({
            "schema_version": CURRENT_RUBRIC_VERSION,
            "rubric_id": "INVALID_UPPERCASE!",
            "dimensions": [{"name": "d1", "description": "desc"}],
        })

    # Duplicate dimension name
    with pytest.raises(ValueError, match="Duplicate dimension name"):
        parse_and_sanitize_rubric_spec({
            "schema_version": CURRENT_RUBRIC_VERSION,
            "rubric_id": "valid-id",
            "dimensions": [
                {"name": "accuracy", "weight": 1.0, "description": "desc 1"},
                {"name": "accuracy", "weight": 1.0, "description": "desc 2"},
            ],
        })

    # Passing threshold out of bounds for scale (e.g. 6.0 on likert_5)
    with pytest.raises(ValueError, match="out of bounds for scale 'likert_5'"):
        parse_and_sanitize_rubric_spec({
            "schema_version": CURRENT_RUBRIC_VERSION,
            "rubric_id": "valid-id",
            "dimensions": [
                {"name": "quality", "weight": 1.0, "scale": "likert_5", "passing_threshold": 6.0, "description": "desc"},
            ],
        })

    # Empty description
    with pytest.raises(ValueError, match="must provide a non-empty description"):
        parse_and_sanitize_rubric_spec({
            "schema_version": CURRENT_RUBRIC_VERSION,
            "rubric_id": "valid-id",
            "dimensions": [
                {"name": "quality", "weight": 1.0, "scale": "score_100", "passing_threshold": 50.0, "description": "  "},
            ],
        })


def test_compute_rubric_hash_deterministic() -> None:
    r1 = {
        "rubric_id": "bench-rubric",
        "model_tier": "reasoning",
        "dimensions": [
            {"name": "coherence", "weight": 0.6, "scale": "score_100", "passing_threshold": 75.0},
            {"name": "brevity", "weight": 0.4, "scale": "score_100", "passing_threshold": 50.0},
        ],
    }

    # Dimension order reversed
    r2 = {
        "rubric_id": "bench-rubric",
        "model_tier": "reasoning",
        "dimensions": [
            {"name": "brevity", "weight": 0.4, "scale": "score_100", "passing_threshold": 50.0},
            {"name": "coherence", "weight": 0.6, "scale": "score_100", "passing_threshold": 75.0},
        ],
    }

    hash1 = compute_rubric_hash(r1)
    hash2 = compute_rubric_hash(r2)
    assert hash1 == hash2
