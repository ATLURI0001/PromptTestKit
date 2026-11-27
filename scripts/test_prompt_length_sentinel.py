"""Tests for prompt_length_sentinel."""
import sys
sys.path.insert(0, "scripts")
from prompt_length_sentinel import PromptLengthSentinel


def test_prompt_length_sentinel():
    s = PromptLengthSentinel(max_chars=10)
    assert s.check("hello") is True
    assert s.check("this is way too long") is False
    assert s.blocked == 1
