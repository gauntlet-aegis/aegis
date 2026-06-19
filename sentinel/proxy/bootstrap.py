"""Assemble the detector bundle (generator, scanner, probe, estimator) from config.

Each piece degrades gracefully to a stub if its trained artifact is missing, so the proxy runs
end-to-end at any stage of the build. As later milestones land, more detectors come online.
"""

from __future__ import annotations

from sentinel.config import Settings
from sentinel.detect.dp_honey.conformal import load_threshold
from sentinel.detect.dp_honey.generator import load_models, make_generator
from sentinel.detect.dp_honey.scanner import CrossEncodingScanner


def build_detectors(settings: Settings) -> dict:
    detectors: dict = {}

    # DP-HONEY: generator (for the ledger) + cross-encoding scanner + conformal fuzzy threshold.
    models = load_models(settings.dp_honey.models_path)
    detectors["honey_generator"] = make_generator(models)
    detectors["dp_honey_scanner"] = CrossEncodingScanner()
    detectors["dp_honey_fuzzy_threshold"] = load_threshold(settings.dp_honey.threshold_path)

    # CIFT (M5) and NIMBUS (M6) wire in here as their artifacts come online.
    return detectors
