"""Conformal calibration helpers for DP-HONEY fuzzy leakage scores.

This module calibrates only the fuzzy/partial detection channel. Exact planted
value matches are ground-truth leaks and should bypass this threshold entirely.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

from .errors import DPHoneyError

DEFAULT_ALPHA = 0.05


@dataclass(frozen=True, slots=True)
class ConformalThreshold:
    """Adjusted empirical threshold for fuzzy DP-HONEY scores."""

    alpha: float
    q_hat: float
    calibration_count: int
    rank: int

    def __post_init__(self) -> None:
        _validate_alpha(self.alpha)
        if self.calibration_count <= 0:
            raise DPHoneyError("calibration_count must be positive")
        if self.rank <= 0:
            raise DPHoneyError("rank must be positive")
        if self.rank > self.calibration_count:
            if not math.isinf(self.q_hat):
                raise DPHoneyError("q_hat must be infinite when rank exceeds calibration_count")
        elif math.isinf(self.q_hat):
            raise DPHoneyError("q_hat may be infinite only when rank exceeds calibration_count")
        if not math.isinf(self.q_hat):
            _validate_score(self.q_hat, "q_hat")

    @property
    def is_finite(self) -> bool:
        """Whether this calibration produced a finite empirical threshold."""

        return math.isfinite(self.q_hat)

    def flags(self, score: float) -> bool:
        """Return whether a fuzzy score exceeds this calibrated threshold."""

        return is_fuzzy_outlier(score, self)


def calibrate_fuzzy_threshold(
    benign_scores: Iterable[float],
    *,
    alpha: float = DEFAULT_ALPHA,
) -> ConformalThreshold:
    """Calibrate the fuzzy/partial detector using held-out benign scores.

    Higher scores are more suspicious. The adjusted empirical rank is
    ``ceil((m + 1) * (1 - alpha))`` for ``m`` held-out benign scores. When the
    adjusted rank is beyond the calibration set, the threshold is infinite,
    which is the finite-sample conformal fallback for very small calibration
    sets.
    """

    validated_alpha = _validate_alpha(alpha)
    scores = sorted(_validate_scores(benign_scores))
    calibration_count = len(scores)
    rank = math.ceil((calibration_count + 1) * (1 - validated_alpha))
    q_hat = math.inf if rank > calibration_count else scores[rank - 1]
    return ConformalThreshold(
        alpha=validated_alpha,
        q_hat=q_hat,
        calibration_count=calibration_count,
        rank=rank,
    )


def is_fuzzy_outlier(score: float, threshold: ConformalThreshold) -> bool:
    """Return ``True`` when ``score`` should be blocked by the fuzzy channel."""

    validated_score = _validate_score(score, "score")
    return validated_score > threshold.q_hat


def _validate_alpha(alpha: float) -> float:
    if not math.isfinite(alpha) or not 0.0 < alpha < 1.0:
        raise DPHoneyError(f"alpha must be finite and in (0, 1), got {alpha!r}")
    return alpha


def _validate_scores(scores: Iterable[float]) -> list[float]:
    values = [_validate_score(score, "benign score") for score in scores]
    if not values:
        raise DPHoneyError("calibration requires at least one benign fuzzy score")
    return values


def _validate_score(score: float, name: str) -> float:
    if not math.isfinite(score):
        raise DPHoneyError(f"{name} must be finite, got {score!r}")
    if not 0.0 <= score <= 1.0:
        raise DPHoneyError(f"{name} must be in [0, 1], got {score!r}")
    return score


__all__ = [
    "DEFAULT_ALPHA",
    "ConformalThreshold",
    "calibrate_fuzzy_threshold",
    "is_fuzzy_outlier",
]
