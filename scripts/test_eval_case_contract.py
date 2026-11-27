"""Tests for eval_case_contract."""
import pytest
from scripts.eval_case_contract import validate_eval_case


def test_eval_case_contract():
    validate_eval_case({"input": "2+2", "expected": "4"})
    with pytest.raises(ValueError):
        validate_eval_case({"input": ""})
