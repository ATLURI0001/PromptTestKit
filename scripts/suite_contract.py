"""
PromptTestKit: Evaluation Suite Manifest Contract Validator & Prompt Sanitizer.
Enforces strict schema validation, hyperparameter bounds, and prompt sanitization.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

SUITE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
SEMVER_REGEX = re.compile(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$")
CONTROL_CHARS_REGEX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
ZERO_WIDTH_REGEX = re.compile(r"[\u200b-\u200d\ufeff\u200e\u200f]")


@dataclass
class ContractError:
    field: str
    code: str
    message: str


@dataclass
class ValidationResult:
    is_valid: bool
    sanitized: Optional[Dict[str, Any]] = None
    errors: List[ContractError] = field(default_factory=list)


def sanitize_prompt_text(text: Any, max_chars: int = 32768) -> str:
    """Strips zero-width artifacts, control characters, and clamps max prompt length."""
    if text is None:
        return ""
    s = str(text)
    s = ZERO_WIDTH_REGEX.sub("", s)
    s = CONTROL_CHARS_REGEX.sub("", s)
    s = s.replace("\r\n", "\n")
    return s[:max_chars].strip()


def validate_suite_manifest(raw: Any) -> ValidationResult:
    """Validates an ingress test suite manifest dictionary against schema contracts."""
    errors: List[ContractError] = []

    if not isinstance(raw, dict):
        return ValidationResult(
            is_valid=False,
            errors=[ContractError("root", "INVALID_TYPE", "Suite manifest must be a dictionary")],
        )

    # 1. suite_id
    suite_id = raw.get("suite_id")
    if not suite_id or not isinstance(suite_id, str):
        errors.append(ContractError("suite_id", "REQUIRED_FIELD", "suite_id is mandatory"))
    elif not SUITE_ID_REGEX.match(suite_id):
        errors.append(
            ContractError(
                "suite_id",
                "INVALID_FORMAT",
                f"suite_id '{suite_id}' violates alphanumeric naming rule",
            )
        )

    # 2. name
    name = raw.get("name")
    if not name or not isinstance(name, str):
        errors.append(ContractError("name", "REQUIRED_FIELD", "name is mandatory"))
    elif len(name) > 128:
        errors.append(ContractError("name", "LENGTH_EXCEEDED", "name cannot exceed 128 characters"))

    # 3. version
    version = raw.get("version", "1.0.0")
    if not isinstance(version, str) or not SEMVER_REGEX.match(version):
        errors.append(
            ContractError(
                "version",
                "INVALID_SEMVER",
                f"version '{version}' must conform to semantic versioning (e.g., 1.0.0)",
            )
        )

    # 4. default_config bounds
    cfg = raw.get("default_config", {})
    sanitized_cfg: Dict[str, Any] = {}
    if not isinstance(cfg, dict):
        errors.append(ContractError("default_config", "INVALID_TYPE", "default_config must be a dictionary"))
    else:
        # temperature
        temp = cfg.get("temperature", 0.7)
        if not isinstance(temp, (int, float)) or temp < 0.0 or temp > 2.0:
            errors.append(
                ContractError("default_config.temperature", "OUT_OF_BOUNDS", "temperature must be in [0.0, 2.0]")
            )
        else:
            sanitized_cfg["temperature"] = float(temp)

        # top_p
        top_p = cfg.get("top_p", 1.0)
        if not isinstance(top_p, (int, float)) or top_p < 0.0 or top_p > 1.0:
            errors.append(
                ContractError("default_config.top_p", "OUT_OF_BOUNDS", "top_p must be in [0.0, 1.0]")
            )
        else:
            sanitized_cfg["top_p"] = float(top_p)

        # max_tokens
        max_tokens = cfg.get("max_tokens", 2048)
        if not isinstance(max_tokens, int) or max_tokens < 1 or max_tokens > 131072:
            errors.append(
                ContractError("default_config.max_tokens", "OUT_OF_BOUNDS", "max_tokens must be in [1, 131072]")
            )
        else:
            sanitized_cfg["max_tokens"] = int(max_tokens)

        # timeout_sec
        timeout_sec = cfg.get("timeout_sec", 30.0)
        if not isinstance(timeout_sec, (int, float)) or timeout_sec < 0.1 or timeout_sec > 300.0:
            errors.append(
                ContractError("default_config.timeout_sec", "OUT_OF_BOUNDS", "timeout_sec must be in [0.1, 300.0]")
            )
        else:
            sanitized_cfg["timeout_sec"] = float(timeout_sec)

    # 5. test_cases array
    raw_cases = raw.get("test_cases")
    sanitized_cases: List[Dict[str, Any]] = []
    if not isinstance(raw_cases, list) or len(raw_cases) == 0:
        errors.append(
            ContractError("test_cases", "REQUIRED_NON_EMPTY", "test_cases must be a non-empty list")
        )
    elif len(raw_cases) > 500:
        errors.append(
            ContractError("test_cases", "COUNT_EXCEEDED", f"test_cases count {len(raw_cases)} exceeds maximum 500")
        )
    else:
        for i, tc in enumerate(raw_cases):
            if not isinstance(tc, dict):
                errors.append(ContractError(f"test_cases[{i}]", "INVALID_CASE", f"Test case at index {i} must be a dict"))
                continue

            tc_id = tc.get("id")
            if not tc_id or not isinstance(tc_id, str):
                errors.append(ContractError(f"test_cases[{i}].id", "REQUIRED_FIELD", "Test case id is mandatory"))

            prompt = tc.get("prompt")
            if not prompt or not isinstance(prompt, str) or not prompt.strip():
                errors.append(ContractError(f"test_cases[{i}].prompt", "REQUIRED_FIELD", "Prompt text cannot be empty"))

            if tc_id and prompt:
                sanitized_cases.append({
                    "id": str(tc_id).strip(),
                    "prompt": sanitize_prompt_text(prompt),
                    "tags": [str(t).strip() for t in tc.get("tags", []) if isinstance(t, str)],
                    "assertions": tc.get("assertions", []),
                })

    if errors:
        return ValidationResult(is_valid=False, errors=errors)

    sanitized_manifest = {
        "suite_id": str(suite_id),
        "name": str(name).strip(),
        "version": str(version),
        "default_config": sanitized_cfg,
        "test_cases": sanitized_cases,
    }

    return ValidationResult(is_valid=True, sanitized=sanitized_manifest)
