"""Token bomb prompt length sentinel."""


def assert_prompt_within_limit(prompt: str, max_chars: int = 32768) -> None:
    if len(prompt) > max_chars:
        raise ValueError(f"sentinel violation: prompt length {len(prompt)} exceeds {max_chars}")
