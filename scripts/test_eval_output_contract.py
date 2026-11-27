"""Tests for eval_output_contract."""
import sys
sys.path.insert(0, "scripts")
from eval_output_contract import EvalOutputContract


def test_eval_output_contract():
    c = EvalOutputContract(["score", "passed"])
    assert c.validate({"score": 0.9, "passed": True}) is True
    assert c.validate({"score": 0.9}) is False
