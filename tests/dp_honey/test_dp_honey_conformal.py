"""Tests for DP-HONEY conformal fuzzy-score calibration."""

from __future__ import annotations

import math

import pytest

from detect.dp_honey.conformal import ConformalThreshold, calibrate_fuzzy_threshold, is_fuzzy_outlier
from detect.dp_honey.errors import DPHoneyError


def test_calibrate_fuzzy_threshold_uses_adjusted_empirical_rank():
    scores = [0.9, 0.1, 0.8, 0.0, 0.6, 0.3, 0.4, 0.2, 0.7, 0.5]

    threshold = calibrate_fuzzy_threshold(scores, alpha=0.2)

    assert threshold.alpha == 0.2
    assert threshold.calibration_count == 10
    assert threshold.rank == 9
    assert threshold.q_hat == 0.8
    assert threshold.is_finite


def test_calibrate_fuzzy_threshold_returns_infinite_threshold_for_small_sets():
    threshold = calibrate_fuzzy_threshold([0.1, 0.2, 0.3], alpha=0.05)

    assert threshold.rank == 4
    assert math.isinf(threshold.q_hat)
    assert not threshold.flags(1.0)


@pytest.mark.parametrize("alpha", [-0.1, 0.0, 1.0, 1.1, math.inf, math.nan])
def test_calibrate_fuzzy_threshold_rejects_invalid_alpha(alpha: float):
    with pytest.raises(DPHoneyError, match="alpha"):
        calibrate_fuzzy_threshold([0.1, 0.2], alpha=alpha)


@pytest.mark.parametrize("scores", [[], [-0.1], [1.1], [math.inf], [math.nan]])
def test_calibrate_fuzzy_threshold_rejects_invalid_scores(scores: list[float]):
    with pytest.raises(DPHoneyError):
        calibrate_fuzzy_threshold(scores, alpha=0.2)


def test_is_fuzzy_outlier_blocks_only_scores_above_q_hat():
    threshold = ConformalThreshold(alpha=0.2, q_hat=0.6, calibration_count=10, rank=9)

    assert not is_fuzzy_outlier(0.59, threshold)
    assert not is_fuzzy_outlier(0.6, threshold)
    assert is_fuzzy_outlier(0.61, threshold)
    assert threshold.flags(0.61)


@pytest.mark.parametrize(
    ("rank", "q_hat"),
    [(11, 0.9), (10, math.inf)],
)
def test_conformal_threshold_rejects_inconsistent_manual_threshold(rank: int, q_hat: float):
    with pytest.raises(DPHoneyError):
        ConformalThreshold(alpha=0.2, q_hat=q_hat, calibration_count=10, rank=rank)
