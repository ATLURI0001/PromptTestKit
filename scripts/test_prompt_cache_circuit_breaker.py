"""Tests for PromptCacheCircuitBreaker."""
import pytest
from scripts.prompt_cache_circuit_breaker import (
    CacheCircuitOpenError,
    PromptCacheCircuitBreaker,
)


def test_prompt_cache_circuit_breaker():
    cb = PromptCacheCircuitBreaker(threshold=2, cooldown_s=5.0)
    with pytest.raises(ConnectionError):
        cb.call(lambda: (_ for _ in ()).throw(ConnectionError("redis down")))
    with pytest.raises(ConnectionError):
        cb.call(lambda: (_ for _ in ()).throw(ConnectionError("redis down")))
    with pytest.raises(CacheCircuitOpenError):
        cb.call(lambda: "ok")
