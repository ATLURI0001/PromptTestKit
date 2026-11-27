"""Tests for DatasetFetchCircuitBreaker."""
import pytest
from scripts.dataset_fetch_circuit_breaker import (
    DatasetCircuitOpenError,
    DatasetFetchCircuitBreaker,
)


def test_dataset_fetch_circuit_breaker():
    cb = DatasetFetchCircuitBreaker(threshold=2, cooldown_s=5.0)
    with pytest.raises(IOError):
        cb.call(lambda: (_ for _ in ()).throw(IOError("404")))
    with pytest.raises(IOError):
        cb.call(lambda: (_ for _ in ()).throw(IOError("404")))
    with pytest.raises(DatasetCircuitOpenError):
        cb.call(lambda: "ok")
