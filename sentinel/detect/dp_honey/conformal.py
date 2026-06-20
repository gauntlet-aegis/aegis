"""Split-conformal calibration of the DP-HONEY fuzzy threshold.

The exact scanner is ground truth and needs no threshold. The *fuzzy/partial* channel does:
we pick a threshold so the benign false-positive rate is <= alpha, with no manual tuning. The
nonconformity score is the best partial overlap the scanner reports on a benign output.
"""

from __future__ import annotations

import json
import math
from pathlib import Path


def calibrate_threshold(benign_scores: list[float], alpha: float = 0.05) -> float:
    """Conformal quantile: flag when score > threshold gives benign FPR <= alpha (in expectation)."""
    m = len(benign_scores)
    if m == 0:
        return 1.0
    k = math.ceil((m + 1) * (1 - alpha))
    k = min(k, m)
    return sorted(benign_scores)[k - 1]


def empirical_coverage(benign_scores: list[float], threshold: float) -> float:
    """Fraction of benign outputs at or below the threshold (target: >= 1 - alpha)."""
    if not benign_scores:
        return 1.0
    return sum(1 for s in benign_scores if s <= threshold) / len(benign_scores)


def save_threshold(path: str, threshold: float, alpha: float, coverage: float) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps({"threshold": threshold, "alpha": alpha, "coverage": coverage}, indent=2)
    )


def load_threshold(path: str) -> float:
    p = Path(path)
    if not p.exists():
        return 1.0
    return json.loads(p.read_text())["threshold"]
