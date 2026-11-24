"""Evaluation Rubric Schema Ingress Contract and Score Boundary Invariant Guard.

Enforces strict structural boundaries, finite numeric ranges, dimension completeness,
and cryptographic nonces across automated and human LLM evaluation score submissions.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence


class DimensionScale(str, Enum):
    BINARY = "binary"           # Allowed range [0.0, 1.0]
    LIKERT_5 = "likert_5"       # Allowed range [1.0, 5.0]
    PERCENTAGE = "percentage"   # Allowed range [0.0, 100.0]


SCALE_BOUNDS: Mapping[DimensionScale, tuple[float, float]] = {
    DimensionScale.BINARY: (0.0, 1.0),
    DimensionScale.LIKERT_5: (1.0, 5.0),
    DimensionScale.PERCENTAGE: (0.0, 100.0),
}


class RubricContractError(Exception):
    """Base exception for rubric contract and boundary invariant violations."""


class DimensionMissingError(RubricContractError):
    """Raised when an evaluation score submission omits a mandatory rubric dimension."""


class DimensionUnexpectedError(RubricContractError):
    """Raised when an evaluation score submission includes undeclared dimensions."""


class ScoreBoundaryViolationError(RubricContractError):
    """Raised when a dimension score violates scale boundaries or is non-finite."""


class WeightNormalizationError(RubricContractError):
    """Raised when rubric dimension weights do not sum to 1.0 or are non-positive."""


@dataclass(frozen=True)
class RubricDimension:
    name: str
    scale: DimensionScale
    weight: float
    threshold: float
    description: str = ""

    def validate_score(self, score: float) -> None:
        if not isinstance(score, (int, float)) or isinstance(score, bool):
            raise ScoreBoundaryViolationError(
                f"Dimension '{self.name}' score must be numeric, got {type(score).__name__}"
            )
        if not math.isfinite(score):
            raise ScoreBoundaryViolationError(
                f"Dimension '{self.name}' score must be finite (got {score})"
            )
        min_val, max_val = SCALE_BOUNDS[self.scale]
        if score < min_val or score > max_val:
            raise ScoreBoundaryViolationError(
                f"Dimension '{self.name}' score {score} out of bounds for scale {self.scale.value} [{min_val}, {max_val}]"
            )


@dataclass(frozen=True)
class EvaluationAssessment:
    rubric_id: str
    evaluator_id: str
    dimension_scores: Mapping[str, float]
    normalized_composite_score: float
    passed: bool
    verdict_reasons: Sequence[str]
    assessment_digest: str


class RubricSchemaContract:
    """Ingress contract validator and score boundary invariant guard for prompt evaluation rubrics."""

    def __init__(self, rubric_id: str, dimensions: Sequence[RubricDimension]):
        if not rubric_id or not isinstance(rubric_id, str):
            raise RubricContractError("rubric_id must be a non-empty string")
        if not dimensions:
            raise RubricContractError("Rubric must contain at least one dimension")

        # Validate unique dimension names and weights
        names = set()
        total_weight = 0.0
        for dim in dimensions:
            if not isinstance(dim, RubricDimension):
                raise TypeError("Dimensions must be instances of RubricDimension")
            if dim.name in names:
                raise RubricContractError(f"Duplicate dimension name: '{dim.name}'")
            names.add(dim.name)
            if dim.weight <= 0.0 or not math.isfinite(dim.weight):
                raise WeightNormalizationError(
                    f"Dimension '{dim.name}' weight must be strictly positive and finite: {dim.weight}"
                )
            total_weight += dim.weight

        if abs(total_weight - 1.0) > 1e-5:
            raise WeightNormalizationError(
                f"Dimension weights must sum to 1.0, got {total_weight:.6f}"
            )

        self.rubric_id = rubric_id
        self._dimensions: Mapping[str, RubricDimension] = {d.name: d for d in dimensions}

    @property
    def dimensions(self) -> Mapping[str, RubricDimension]:
        return self._dimensions

    def validate_and_score(
        self,
        evaluator_id: str,
        raw_scores: Mapping[str, Any],
        strict: bool = True,
    ) -> EvaluationAssessment:
        """Validates incoming score payload against contract invariants and computes composite verdict."""
        if not evaluator_id or not isinstance(evaluator_id, str):
            raise RubricContractError("evaluator_id must be a non-empty string")
        if not isinstance(raw_scores, Mapping):
            raise RubricContractError("raw_scores must be a mapping of dimension names to numeric scores")

        # Check for missing dimensions
        missing = set(self._dimensions.keys()) - set(raw_scores.keys())
        if missing:
            raise DimensionMissingError(f"Missing required rubric dimensions: {sorted(missing)}")

        # Check for unexpected dimensions
        if strict:
            unexpected = set(raw_scores.keys()) - set(self._dimensions.keys())
            if unexpected:
                raise DimensionUnexpectedError(f"Unexpected dimensions not defined in rubric: {sorted(unexpected)}")

        clean_scores: Dict[str, float] = {}
        verdict_reasons: List[str] = []
        composite_sum = 0.0
        all_passed = True

        for dim_name, dim_def in self._dimensions.items():
            raw_val = raw_scores[dim_name]
            dim_def.validate_score(raw_val)
            score_float = float(raw_val)
            clean_scores[dim_name] = score_float

            # Normalize score to [0.0, 1.0] for composite calculation
            min_val, max_val = SCALE_BOUNDS[dim_def.scale]
            norm_val = (score_float - min_val) / (max_val - min_val) if max_val > min_val else score_float
            composite_sum += norm_val * dim_def.weight

            # Threshold check
            if score_float < dim_def.threshold:
                all_passed = False
                verdict_reasons.append(
                    f"Dimension '{dim_name}' score {score_float} below threshold {dim_def.threshold}"
                )

        normalized_composite = round(composite_sum * 100.0, 3)

        # Cryptographic assessment digest
        canonical_payload = {
            "rubric_id": self.rubric_id,
            "evaluator_id": evaluator_id,
            "scores": clean_scores,
            "composite": normalized_composite,
            "passed": all_passed,
        }
        digest = hashlib.sha256(
            json.dumps(canonical_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        return EvaluationAssessment(
            rubric_id=self.rubric_id,
            evaluator_id=evaluator_id,
            dimension_scores=clean_scores,
            normalized_composite_score=normalized_composite,
            passed=all_passed,
            verdict_reasons=verdict_reasons,
            assessment_digest=digest,
        )
