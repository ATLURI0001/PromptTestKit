import pytest
from scripts.response_schema_contract import validate_response_schema


def test_response_schema_contract():
    validate_response_schema({"text": "ok", "tokens": 10}, ["text", "tokens"])
    with pytest.raises(ValueError, match="missing keys"):
        validate_response_schema({"text": "ok"}, ["text", "tokens"])
