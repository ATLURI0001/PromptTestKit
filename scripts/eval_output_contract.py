"""eval_output_contract.py – validates eval output schema contract."""


class EvalOutputContract:
    def __init__(self, required_keys: list[str]):
        self.required_keys = required_keys

    def validate(self, output: dict) -> bool:
        return all(k in output for k in self.required_keys)
