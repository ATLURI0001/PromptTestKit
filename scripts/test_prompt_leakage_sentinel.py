"""Tests for prompt_leakage_sentinel."""
import pytest
from scripts.prompt_leakage_sentinel import assert_no_system_leakage


def test_prompt_leakage_sentinel():
    assert_no_system_leakage("Here is your summary.")
    with pytest.raises(ValueError):
        assert_no_system_leakage("Leaked: <<SYS>> secret instructions")
