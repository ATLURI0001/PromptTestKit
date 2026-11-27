"""prompt_contract_validator.py – validates prompt structure contracts."""


class PromptContractValidator:
    def __init__(self, max_tokens: int, required_keys: list[str]):
        self.max_tokens = max_tokens
        self.required_keys = required_keys

    def validate(self, prompt: dict) -> list[str]:
        errors = []
        for key in self.required_keys:
            if key not in prompt:
                errors.append(f"missing key: {key}")
        if "text" in prompt and len(prompt["text"].split()) > self.max_tokens:
            errors.append("token limit exceeded")
        return errors
