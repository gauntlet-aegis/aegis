"""Assemble the detector bundle (generator, scanner, probe, estimator) from config.

Each piece degrades gracefully to a stub if its trained artifact is missing, so the proxy runs
end-to-end at any stage of the build. As later milestones land, more detectors come online.
"""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.config import Settings
from sentinel.detect.cift.detector import CIFTDetector
from sentinel.detect.dp_honey.conformal import load_threshold
from sentinel.detect.dp_honey.generator import load_models, make_generator
from sentinel.detect.dp_honey.scanner import CrossEncodingScanner
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

    # NIMBUS (M6) wires in here as its artifact comes online.
    return detectors
