from scripts.json_output_contract import JsonOutputContract


def test_valid_json_output():
    contract = JsonOutputContract({"sentiment": str, "confidence": float})
    res = contract.validate('{"sentiment": "positive", "confidence": 0.94}')
    assert res.valid is True
    assert res.parsed["sentiment"] == "positive"


def test_rejects_fences_and_missing_keys():
    contract = JsonOutputContract({"answer": str, "score": int})
    res_fence = contract.validate('```json\n{"answer": "ok", "score": 1}\n```')
    assert res_fence.valid is False
    assert "ERR_UNSTRIPPED_MARKDOWN_FENCE" in res_fence.errors

    res_missing = contract.validate('{"answer": "ok", "extra": 123}')
    assert res_missing.valid is False
    assert "ERR_MISSING_KEY: score" in res_missing.errors
    assert "ERR_UNEXPECTED_KEY: extra" in res_missing.errors
