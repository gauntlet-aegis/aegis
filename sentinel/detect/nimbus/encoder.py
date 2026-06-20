"""Deterministic character-n-gram encoder for NIMBUS.

We are detecting cumulative leakage of a *random character string*, not semantic content, so a
semantic sentence encoder won't capture that an output fragment is part of the secret. A hashed
char-n-gram bag does: an output that contains characters of the secret shares n-grams with it, so
their feature vectors align. The encoder is deterministic and model-agnostic (works in black-box).
"""

from __future__ import annotations

import zlib

import numpy as np


class CharNGramEncoder:
    def __init__(self, dim: int = 512, ns: tuple[int, ...] = (2, 3, 4)) -> None:
        self.dim = dim
        self.ns = ns

    def encode(self, text: str) -> np.ndarray:
        v = np.zeros(self.dim, dtype=np.float64)
        t = text or ""
        for n in self.ns:
            for i in range(len(t) - n + 1):
                gram = t[i : i + n]
                h = zlib.crc32(gram.encode("utf-8")) % self.dim
                v[h] += 1.0
        norm = np.linalg.norm(v)
        return v / norm if norm > 0 else v
