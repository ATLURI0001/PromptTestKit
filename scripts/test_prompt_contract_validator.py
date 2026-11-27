"""Tests for prompt_contract_validator."""
import sys
sys.path.insert(0, "scripts")
from prompt_contract_validator import PromptContractValidator


def test_contract_validator():
    v = PromptContractValidator(max_tokens=5, required_keys=["text", "role"])
    assert v.validate({"text": "hello world", "role": "user"}) == []
    errors = v.validate({"text": "hello"})
    assert any("missing key: role" in e for e in errors)
