"""prompt_length_sentinel.py – sentinel for oversized prompts."""


class PromptLengthSentinel:
    def __init__(self, max_chars: int = 4096):
        self.max_chars = max_chars
        self.blocked = 0

    def check(self, prompt: str) -> bool:
        if len(prompt) > self.max_chars:
            self.blocked += 1
            return False
        return True
