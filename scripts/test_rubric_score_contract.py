"""Tests for rubric_score_contract."""
import pytest
from scripts.rubric_score_contract import validate_rubric_score


def test_rubric_score_contract():
    validate_rubric_score(0.85, 1.0)
    with pytest.raises(ValueError):
        validate_rubric_score(1.5, 1.0)
