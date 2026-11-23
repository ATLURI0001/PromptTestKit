"""
Prompt Evaluation Benchmark Matrix Contract & Rubric Sanitizer.

Validates multi-dimensional prompt scoring rubrics, enforces normalized weights,
and migrates legacy unweighted rubric schemas to canonical v2 contract representations.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping


CURRENT_RUBRIC_VERSION = "2.0"
LEGACY_RUBRIC_VERSIONS = {"1.0", "1.1"}

RUBRIC_ID_REGEX = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
DIMENSION_NAME_REGEX = re.compile(r"^[a-z0-9_]{2,32}$")


class ScoringScale(str, Enum):
    BINARY = "binary"           # [0, 1]
    LIKERT_5 = "likert_5"       # [1, 5]
    SCORE_100 = "score_100"     # [0, 100]


class ModelTier(str, Enum):
    FAST = "fast"
    BALANCED = "balanced"
    ADVANCED = "advanced"
    REASONING = "reasoning"


@dataclass
class RubricDimensionSpec:
    name: str
    weight: float
    scale: ScoringScale
    passing_threshold: float
    description: str


@dataclass
class RubricSpecContract:
    schema_version: str
    rubric_id: str
    model_tier: ModelTier
    dimensions: list[RubricDimensionSpec]
    rubric_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["model_tier"] = self.model_tier.value
        for d in data["dimensions"]:
            d["scale"] = d["scale"].value
        return data


def compute_rubric_hash(rubric_dict: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 fingerprint over normalized rubric structure."""
    normalized = {
        "rubric_id": str(rubric_dict.get("rubric_id", "")).strip().lower(),
        "model_tier": str(rubric_dict.get("model_tier", "")).lower(),
        "dimensions": sorted(
            [
                {
                    "name": str(d.get("name", "")).strip().lower(),
                    "weight": round(float(d.get("weight", 0.0)), 4),
                    "scale": str(d.get("scale", "")).lower(),
                    "passing_threshold": round(float(d.get("passing_threshold", 0.0)), 2),
                }
                for d in rubric_dict.get("dimensions", [])
            ],
            key=lambda item: item["name"],
        ),
    }
    raw_json = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw_json.encode("utf-8")).hexdigest()


def parse_and_sanitize_rubric_spec(raw: Mapping[str, Any]) -> RubricSpecContract:
    """Validate inbound rubric payload, normalize weights, and evolve legacy schemas."""
    if not isinstance(raw, dict):
        raise TypeError("Rubric specification payload must be a JSON dictionary.")

    payload = dict(raw)

    # Schema evolution & version check
    version = str(payload.get("schema_version", "1.0")).strip()
    is_legacy = version in LEGACY_RUBRIC_VERSIONS
    if not is_legacy and version != CURRENT_RUBRIC_VERSION:
        raise ValueError(f"Unsupported rubric schema_version '{version}'. Expected '{CURRENT_RUBRIC_VERSION}' or legacy {LEGACY_RUBRIC_VERSIONS}.")

    # Validate rubric_id
    rubric_id = str(payload.get("rubric_id", "")).strip().lower()
    if not rubric_id or not RUBRIC_ID_REGEX.match(rubric_id):
        raise ValueError(f"Invalid rubric_id format: '{rubric_id}'. Must be lowercase alphanumeric with hyphens.")
    if len(rubric_id) > 64:
        raise ValueError("rubric_id exceeds maximum allowed length of 64 characters.")

    # Validate model_tier
    tier_str = str(payload.get("model_tier", ModelTier.BALANCED.value)).strip().lower()
    try:
        model_tier = ModelTier(tier_str)
    except ValueError:
        raise ValueError(f"Invalid model_tier '{tier_str}'. Must be one of {[t.value for t in ModelTier]}.")

    # Validate dimensions
    raw_dims = payload.get("dimensions", [])
    if not isinstance(raw_dims, list) or len(raw_dims) == 0:
        raise ValueError("Rubric must contain at least one evaluation dimension.")

    parsed_dims: list[RubricDimensionSpec] = []
    seen_names: set[str] = set()
    total_raw_weight = 0.0

    for idx, d in enumerate(raw_dims):
        if not isinstance(d, dict):
            raise TypeError(f"Dimension #{idx} must be a dictionary.")

        name = str(d.get("name", "")).strip().lower()
        if not name or not DIMENSION_NAME_REGEX.match(name):
            raise ValueError(f"Dimension #{idx} has invalid name '{name}'. Must match {DIMENSION_NAME_REGEX.pattern}.")
        if name in seen_names:
            raise ValueError(f"Duplicate dimension name '{name}' in rubric specification.")
        seen_names.add(name)

        # Scale
        scale_str = str(d.get("scale", ScoringScale.SCORE_100.value)).strip().lower()
        try:
            scale = ScoringScale(scale_str)
        except ValueError:
            raise ValueError(f"Dimension '{name}' has invalid scale '{scale_str}'. Must be one of {[s.value for s in ScoringScale]}.")

        # Threshold limits by scale
        min_score, max_score = {
            ScoringScale.BINARY: (0.0, 1.0),
            ScoringScale.LIKERT_5: (1.0, 5.0),
            ScoringScale.SCORE_100: (0.0, 100.0),
        }[scale]

        try:
            threshold = float(d.get("passing_threshold", min_score))
        except (ValueError, TypeError):
            raise ValueError(f"Dimension '{name}' passing_threshold must be a valid number.")

        if threshold < min_score or threshold > max_score:
            raise ValueError(f"Dimension '{name}' passing_threshold ({threshold}) out of bounds for scale '{scale.value}' [{min_score}, {max_score}].")

        # Weight
        try:
            raw_w = float(d.get("weight", 1.0 if is_legacy else 0.0))
        except (ValueError, TypeError):
            raise ValueError(f"Dimension '{name}' weight must be a valid number.")

        if raw_w <= 0:
            raise ValueError(f"Dimension '{name}' weight must be strictly positive.")

        total_raw_weight += raw_w
        desc = str(d.get("description", "")).strip()
        if not desc:
            raise ValueError(f"Dimension '{name}' must provide a non-empty description.")

        parsed_dims.append(RubricDimensionSpec(
            name=name,
            weight=raw_w,
            scale=scale,
            passing_threshold=round(threshold, 2),
            description=desc,
        ))

    # Normalize weights so they sum to 1.0
    for dim in parsed_dims:
        dim.weight = round(dim.weight / total_raw_weight, 4)

    contract = RubricSpecContract(
        schema_version=CURRENT_RUBRIC_VERSION,
        rubric_id=rubric_id,
        model_tier=model_tier,
        dimensions=parsed_dims,
    )
    contract.rubric_hash = compute_rubric_hash(contract.to_dict())
    return contract
