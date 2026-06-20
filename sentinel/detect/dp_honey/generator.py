"""Fit/save/load the per-format DP-bigram models and expose a honeytoken generator.

The generator is the callable the HoneytokenLedger uses to mint model-visible fakes. Falls back
to a fresh format-valid sample if a model file is missing, so the spine never hard-depends on a
trained artifact.
"""

from __future__ import annotations

import pickle
from collections.abc import Callable
from pathlib import Path

import numpy as np

from sentinel.detect.dp_honey.bigram import DPBigramModel
from sentinel.detect.dp_honey.formats import FORMATS, get_format, synthetic_corpus


def fit_all(epsilon: float = 1.0, n: int = 4000, seed: int = 0) -> dict[str, DPBigramModel]:
    models: dict[str, DPBigramModel] = {}
    for name, fmt in FORMATS.items():
        models[name] = DPBigramModel(fmt, epsilon=epsilon).fit(synthetic_corpus(fmt, n), seed=seed)
    return models


def save_models(models: dict[str, DPBigramModel], path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(models, f)


def load_models(path: str) -> dict[str, DPBigramModel] | None:
    p = Path(path)
    if not p.exists():
        return None
    with open(p, "rb") as f:
        return pickle.load(f)


def make_generator(models: dict[str, DPBigramModel] | None) -> Callable[[str], str]:
    rng = np.random.default_rng()

    def generate(fmt_name: str) -> str:
        if models and fmt_name in models:
            return models[fmt_name].sample(rng)
        # Fallback: structurally valid random sample for the format.
        return get_format(fmt_name).random_example()

    return generate
