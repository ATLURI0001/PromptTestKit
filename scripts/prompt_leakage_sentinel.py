"""System prompt leakage sentinel."""


def assert_no_system_leakage(output: str) -> None:
    lowered = output.lower()
    for marker in ("you are a helpful assistant", "system_prompt:", "<<sys>>"):
        if marker in lowered:
            raise ValueError(f"sentinel violation: detected system leakage marker '{marker}'")
