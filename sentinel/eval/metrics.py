"""Detector-agnostic metric primitives shared by the offline eval scripts.

Kept tiny and numpy-only so each layer's eval (CIFT per-layer AUROC, DP-HONEY Table 2,
NIMBUS budget sweep) reuses the same rate/precision helpers instead of re-deriving them.
"""

from __future__ import annotations

import numpy as np


def rate(flags) -> float:
    """Fraction of truthy values in an iterable of bools (0.0 if empty)."""
    flags = [bool(f) for f in flags]
    return float(np.mean(flags)) if flags else 0.0


def precision_recall_f1(pred, truth) -> dict[str, float]:
    """Binary precision/recall/F1 from parallel boolean iterables."""
    pred = [bool(p) for p in pred]
    truth = [bool(t) for t in truth]
    tp = sum(p and t for p, t in zip(pred, truth))
    fp = sum(p and not t for p, t in zip(pred, truth))
    fn = sum((not p) and t for p, t in zip(pred, truth))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}
