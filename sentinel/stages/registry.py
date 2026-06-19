"""Builds the ordered detection pipeline from config + mode.

White-box mode runs all stages; black-box mode drops any stage with ``requires_whitebox``
(i.e. CIFT) — which is exactly how the white-box-vs-black-box comparison slide is produced for
free. Stages are returned grouped by phase so the orchestrator can interleave them around the
forward pass.
"""

from __future__ import annotations

from sentinel.events.schema import Mode
from sentinel.stages.base import Phase, Stage
from sentinel.stages.cift_stage import CIFTStage
from sentinel.stages.dp_honey_stage import DPHoneyStage
from sentinel.stages.nimbus_stage import NimbusStage
from sentinel.stages.text_detector_stage import TextDetectorStage


def build_pipeline(
    mode: Mode,
    store,
    *,
    cift_detector=None,
    dp_honey_scanner=None,
    dp_honey_fuzzy_threshold: float | None = None,
    nimbus_estimator=None,
    nimbus_budget_bits: float = 16.0,
) -> list[Stage]:
    """Return stages in pipeline order, filtered by mode."""
    stages: list[Stage] = [
        CIFTStage(detector=cift_detector),  # post_forward_pre_output
        TextDetectorStage(),  # post_output
        DPHoneyStage(scanner=dp_honey_scanner, fuzzy_threshold=dp_honey_fuzzy_threshold),  # post_output
        NimbusStage(store, estimator=nimbus_estimator, budget_bits=nimbus_budget_bits),  # post_output
    ]
    if mode == Mode.BLACKBOX:
        stages = [s for s in stages if not s.requires_whitebox]
    return stages


def stages_for_phase(stages: list[Stage], phase: Phase) -> list[Stage]:
    return [s for s in stages if s.phase == phase]
