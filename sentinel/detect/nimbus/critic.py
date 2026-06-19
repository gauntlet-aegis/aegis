"""InfoNCE critic for NIMBUS.

A diagonal bilinear score f(s, c) = sum(w * s * c) over char-n-gram features. With w = 1 this is
cosine similarity (a strong default); training sharpens w to up-weight the n-gram dimensions that
carry leakage and down-weight noisy ones. Kept tiny and numpy-friendly so NIMBUS has no MPS
dependency and runs identically in black-box mode.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np


class LeakageCritic:
    def __init__(self, dim: int) -> None:
        self.dim = dim
        self.w = np.ones(dim, dtype=np.float64)

    def score(self, s_feat: np.ndarray, c_feat: np.ndarray) -> float:
        return float((self.w * s_feat * c_feat).sum())

    def score_batch(self, s_feat: np.ndarray, c_feats: np.ndarray) -> np.ndarray:
        """s_feat: [dim]; c_feats: [N, dim] -> [N] scores."""
        return (c_feats * (self.w * s_feat)).sum(axis=1)

    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({"dim": self.dim, "w": self.w.tolist()}))

    @classmethod
    def load(cls, path: str) -> "LeakageCritic | None":
        p = Path(path)
        if not p.exists():
            return None
        d = json.loads(p.read_text())
        c = cls(d["dim"])
        c.w = np.array(d["w"], dtype=np.float64)
        return c
