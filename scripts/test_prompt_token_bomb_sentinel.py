"""Tests for prompt_token_bomb_sentinel."""
import pytest
from scripts.prompt_token_bomb_sentinel import assert_prompt_within_limit


def test_prompt_token_bomb_sentinel():
    assert_prompt_within_limit("hello", max_chars=100)
    with pytest.raises(ValueError):
        assert_prompt_within_limit("x" * 101, max_chars=100)
