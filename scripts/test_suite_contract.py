"""Test Suite Specification Ingress Contract and Assertion Sanitizer.

Validates and sanitizes declarative prompt test suite specifications, enforcing
strict boundaries on prompt lengths, assertion schemas, execution deadlines, and prompt injection markers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

VALID_ID_REGEX = re.compile(r"^[a-z0-9_-]+$")
ALLOWED_ASSERTION_TYPES = {
    "contains",
    "not_contains",
    "regex_match",
    "json_schema",
    "semantic_similarity",
    "length_between",
}
ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF]")
FORBIDDEN_KEYS = {"__proto__", "constructor", "prototype"}


@dataclass
class AssertionSpec:
    """Sanitized assertion definition."""

    type: str
    target: str
    value: Any
    threshold: Optional[float] = None


@dataclass
class TestCaseSpec:
    """Sanitized test case definition."""

    test_id: str
    prompt: str
    system_instructions: str
    assertions: List[AssertionSpec]
    timeout_seconds: int
    tags: List[str]


@dataclass
class TestSuiteContract:
    """Validated top-level test suite contract."""

    suite_id: str
    name: str
    model_target: str
    test_cases: List[TestCaseSpec]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContractViolation:
    """Individual schema violation."""

    field: str
    rule: str
    message: str


@dataclass
class ContractValidationResult:
    """Result of contract validation."""

    valid: bool
    violations: List[ContractViolation] = field(default_factory=list)
    sanitized_contract: Optional[TestSuiteContract] = None


def validate_and_sanitize_test_suite(raw_data: Any) -> ContractValidationResult:
    """Validates and sanitizes a raw dictionary representing a prompt test suite."""
    violations: List[ContractViolation] = []

    if not isinstance(raw_data, dict):
        return ContractValidationResult(
            valid=False,
            violations=[
                ContractViolation("root", "invalid_type", "test suite payload must be a JSON/dict object")
            ],
        )

    # Check prototype pollution keys
    for k in raw_data.keys():
        if str(k).lower() in FORBIDDEN_KEYS:
            violations.append(
                ContractViolation(str(k), "prototype_pollution", "forbidden prototype/constructor key detected")
            )

    # 1. suite_id
    raw_id = str(raw_data.get("suite_id", "")).strip().lower()
    if not raw_id:
        violations.append(ContractViolation("suite_id", "required", "suite_id is required"))
    elif len(raw_id) > 64:
        violations.append(ContractViolation("suite_id", "max_length", "suite_id cannot exceed 64 characters"))
    elif not VALID_ID_REGEX.match(raw_id):
        violations.append(
            ContractViolation("suite_id", "invalid_format", "suite_id must contain only [a-z0-9_-]")
        )

    # 2. name
    raw_name = str(raw_data.get("name", "")).strip()
    if not raw_name:
        violations.append(ContractViolation("name", "required", "name is required"))
    elif len(raw_name) > 128:
        raw_name = raw_name[:128]

    # 3. model_target
    model_target = str(raw_data.get("model_target", "default")).strip().lower()
    if not model_target:
        model_target = "default"

    # 4. test_cases array
    raw_cases = raw_data.get("test_cases")
    if not isinstance(raw_cases, list) or len(raw_cases) == 0:
        violations.append(
            ContractViolation("test_cases", "min_items", "test_cases must be a non-empty list")
        )
        return ContractValidationResult(valid=False, violations=violations)

    if len(raw_cases) > 200:
        violations.append(
            ContractViolation("test_cases", "max_items", f"test_cases count ({len(raw_cases)}) exceeds 200")
        )

    sanitized_cases: List[TestCaseSpec] = []
    seen_test_ids = set()

    for idx, case in enumerate(raw_cases):
        prefix = f"test_cases[{idx}]"
        if not isinstance(case, dict):
            violations.append(ContractViolation(prefix, "invalid_type", "test case must be a dictionary"))
            continue

        # test_id
        tid = str(case.get("test_id", "")).strip().lower()
        if not tid:
            violations.append(ContractViolation(f"{prefix}.test_id", "required", "test_id is required"))
        elif not VALID_ID_REGEX.match(tid):
            violations.append(
                ContractViolation(f"{prefix}.test_id", "invalid_format", "test_id must match [a-z0-9_-]")
            )
        elif tid in seen_test_ids:
            violations.append(
                ContractViolation(f"{prefix}.test_id", "duplicate", f"duplicate test_id '{tid}' in suite")
            )
        else:
            seen_test_ids.add(tid)

        # prompt
        raw_prompt = str(case.get("prompt", ""))
        clean_prompt = ZERO_WIDTH_CHARS.sub("", raw_prompt).strip()
        if not clean_prompt:
            violations.append(ContractViolation(f"{prefix}.prompt", "required", "prompt must not be empty"))
        elif len(clean_prompt) > 65536:
            violations.append(ContractViolation(f"{prefix}.prompt", "max_length", "prompt exceeds 65536 chars"))

        # system_instructions
        raw_sys = str(case.get("system_instructions", ""))
        clean_sys = ZERO_WIDTH_CHARS.sub("", raw_sys).strip()

        # timeout_seconds
        timeout = case.get("timeout_seconds", 30)
        sanitized_timeout = 30
        try:
            val = int(timeout)
            if val < 1 or val > 300:
                violations.append(
                    ContractViolation(f"{prefix}.timeout_seconds", "bounds", "timeout must be between 1 and 300s")
                )
            else:
                sanitized_timeout = val
        except (ValueError, TypeError):
            violations.append(
                ContractViolation(f"{prefix}.timeout_seconds", "invalid_type", "timeout must be an integer")
            )

        # tags
        raw_tags = case.get("tags", [])
        sanitized_tags: List[str] = []
        if isinstance(raw_tags, list):
            for t in raw_tags:
                clean_tag = str(t).strip().lower()
                if clean_tag and len(clean_tag) <= 32:
                    sanitized_tags.append(clean_tag)

        # assertions
        raw_assertions = case.get("assertions", [])
        if not isinstance(raw_assertions, list) or len(raw_assertions) == 0:
            violations.append(
                ContractViolation(f"{prefix}.assertions", "min_items", "at least one assertion is required")
            )
            continue

        sanitized_assertions: List[AssertionSpec] = []
        for a_idx, assertion in enumerate(raw_assertions):
            a_prefix = f"{prefix}.assertions[{a_idx}]"
            if not isinstance(assertion, dict):
                violations.append(
                    ContractViolation(a_prefix, "invalid_type", "assertion must be a dictionary")
                )
                continue

            a_type = str(assertion.get("type", "")).strip().lower()
            if a_type not in ALLOWED_ASSERTION_TYPES:
                violations.append(
                    ContractViolation(
                        f"{a_prefix}.type",
                        "unsupported_type",
                        f"assertion type '{a_type}' not in {sorted(ALLOWED_ASSERTION_TYPES)}",
                    )
                )

            a_target = str(assertion.get("target", "output")).strip().lower()
            a_val = assertion.get("value")
            if a_val is None and a_type != "json_schema":
                violations.append(
                    ContractViolation(f"{a_prefix}.value", "required", "assertion value must not be null")
                )

            threshold = assertion.get("threshold")
            sanitized_threshold: Optional[float] = None
            if threshold is not None:
                try:
                    sanitized_threshold = float(threshold)
                except (ValueError, TypeError):
                    violations.append(
                        ContractViolation(f"{a_prefix}.threshold", "invalid_numeric", "threshold must be float")
                    )

            sanitized_assertions.append(
                AssertionSpec(
                    type=a_type,
                    target=a_target,
                    value=a_val,
                    threshold=sanitized_threshold,
                )
            )

        sanitized_cases.append(
            TestCaseSpec(
                test_id=tid,
                prompt=clean_prompt,
                system_instructions=clean_sys,
                assertions=sanitized_assertions,
                timeout_seconds=sanitized_timeout,
                tags=sanitized_tags,
            )
        )

    if violations:
        return ContractValidationResult(valid=False, violations=violations)

    return ContractValidationResult(
        valid=True,
        sanitized_contract=TestSuiteContract(
            suite_id=raw_id,
            name=raw_name,
            model_target=model_target,
            test_cases=sanitized_cases,
        ),
    )
