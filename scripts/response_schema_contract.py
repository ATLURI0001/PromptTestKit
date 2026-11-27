"""PromptTestKit: response schema contract – validates expected keys."""


def validate_response_schema(response: dict, required_keys: list[str]) -> None:
    missing = [k for k in required_keys if k not in response]
    if missing:
        raise ValueError(f"response missing keys: {missing}")
