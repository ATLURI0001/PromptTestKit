"""Structured LLM JSON Output Schema & Key Boundary Contract.

Enforces strict JSON deserialization, required field presence, type matching,
and rejects unexpected keys or markdown code fence leaks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Type


@dataclass
class OutputContractResult:
    valid: bool
    parsed: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class JsonOutputContract:
    def __init__(self, required_schema: Dict[str, Type[Any]], strict_extra: bool = True) -> None:
        self.required_schema = required_schema
        self.strict_extra = strict_extra

    def validate(self, raw_text: str) -> OutputContractResult:
        errors: List[str] = []
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            errors.append("ERR_UNSTRIPPED_MARKDOWN_FENCE")
            return OutputContractResult(valid=False, errors=errors)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            return OutputContractResult(valid=False, errors=[f"ERR_INVALID_JSON: {exc}"])

        if not isinstance(data, dict):
            return OutputContractResult(valid=False, errors=["ERR_ROOT_NOT_OBJECT"])

        for key, expected_type in self.required_schema.items():
            if key not in data:
                errors.append(f"ERR_MISSING_KEY: {key}")
            elif not isinstance(data[key], expected_type):
                errors.append(f"ERR_TYPE_MISMATCH: {key} expected {expected_type.__name__}")

        if self.strict_extra:
            for key in data.keys():
                if key not in self.required_schema:
                    errors.append(f"ERR_UNEXPECTED_KEY: {key}")

        return OutputContractResult(valid=len(errors) == 0, parsed=data if not errors else {}, errors=errors)
