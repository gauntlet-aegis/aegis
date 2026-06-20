"""Assemble the detector bundle (generator, scanner, probe, estimator) from config.

Each piece degrades gracefully to a stub if its trained artifact is missing, so the proxy runs
end-to-end at any stage of the build. As later milestones land, more detectors come online.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from sentinel.config import Settings
from sentinel.detect.cift.detector import CIFTDetector
from sentinel.detect.dp_honey.conformal import load_threshold
from sentinel.detect.dp_honey.generator import load_models, make_generator
from sentinel.detect.dp_honey.scanner import CrossEncodingScanner
from sentinel.detect.nimbus.critic import LeakageCritic
from sentinel.detect.nimbus.encoder import CharNGramEncoder
from sentinel.detect.nimbus.estimator import NimbusEstimator
from sentinel.events.schema import Mode


def _cift_threshold(settings: Settings) -> float:
    p = Path("data/cift/threshold.json")
    if p.exists():
        return json.loads(p.read_text())["threshold"]
    return settings.cift.threshold


def build_detectors(settings: Settings) -> dict:
    detectors: dict = {}

    # DP-HONEY: generator (for the ledger) + cross-encoding scanner + conformal fuzzy threshold.
    models = load_models(settings.dp_honey.models_path)
    detectors["honey_generator"] = make_generator(models)
    detectors["dp_honey_scanner"] = CrossEncodingScanner()
    detectors["dp_honey_fuzzy_threshold"] = load_threshold(settings.dp_honey.threshold_path)

    # CIFT (white-box only): loaded if its artifacts exist; else the stage stays a benign stub.
    if settings.mode == Mode.WHITEBOX:
        detectors["cift"] = CIFTDetector.load(
            settings.cift.stats_path, settings.cift.probe_path, _cift_threshold(settings)
        )

    # NIMBUS (white- & black-box): InfoNCE estimator over char-n-gram features.
    critic = LeakageCritic.load(settings.nimbus.critic_path)
    bank_path = Path(settings.nimbus.neg_bank_path)
    if critic is not None and bank_path.exists():
        temperature = settings.nimbus.temperature
        meta = Path(settings.nimbus.meta_path)
        if meta.exists():
            temperature = json.loads(meta.read_text()).get("temperature", temperature)
        detectors["nimbus"] = NimbusEstimator(
            CharNGramEncoder(dim=settings.nimbus.encoder_dim),
            critic,
            np.load(bank_path),
            n_neg=settings.nimbus.n_neg,
            temperature=temperature,
        )
    return detectors
