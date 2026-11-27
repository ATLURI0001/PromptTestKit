"""YAML injection sentinel for prompt templates."""


def has_yaml_injection(payload: str) -> bool:
    """Return True if payload contains unsafe YAML tags or directives."""
    lowered = payload.lower()
    return "!!python" in lowered or "!!js" in lowered or "%yaml" in lowered
