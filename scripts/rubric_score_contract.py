"""Rubric evaluation score contract validator."""


def validate_rubric_score(score: float, max_score: float = 1.0) -> None:
    if not isinstance(score, (int, float)) or score < 0 or score > max_score:
        raise ValueError(f"contract violation: score {score} out of range [0, {max_score}]")
