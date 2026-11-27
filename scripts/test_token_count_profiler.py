from scripts.token_count_profiler import profile_token_count


def test_token_count_profiler():
    result = profile_token_count(["hello world", "foo bar baz"], rounds=10)
    assert result["total_tokens"] == 50
    assert result["elapsed_s"] >= 0
