"""Evaluation test case schema contract validator."""


def validate_eval_case(case: dict) -> None:
    if not isinstance(case, dict):
        raise ValueError("eval case must be a dict")
    if not case.get("input") or not isinstance(case["input"], str):
        raise ValueError("eval case requires non-empty string 'input'")
    if "expected" not in case:
        raise ValueError("eval case requires 'expected' field")
