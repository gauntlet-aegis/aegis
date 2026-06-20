"""CIFT stage — pre-output white-box credential-access probe.

Stub for the spine milestone (returns benign/skipped). The real implementation
(readout capture -> diagonal Mahalanobis Causal Flow Score -> MLP probe) lands in
``sentinel/detect/cift/`` and is wired in here in M5.
"""

from __future__ import annotations

import time

from sentinel.events.schema import Action, LayerResult, Verdict
from sentinel.stages.base import Phase, StageInput, StageOutput


class CIFTStage:
    name = "cift"
    phase = Phase.POST_FORWARD_PRE_OUTPUT
    requires_whitebox = True

    def __init__(self, detector=None) -> None:
        # detector: the trained CIFT probe wrapper (None => stub mode).
        self._detector = detector

    def run(self, inp: StageInput) -> StageOutput:
        t0 = time.perf_counter()
        if inp.activations is None or self._detector is None:
            result = LayerResult(
                layer=self.name,
                ran=False,
                verdict=Verdict.SKIPPED,
                action=Action.PASS,
                detail={"reason": "no_activations_or_stub"},
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
            return StageOutput(result=result)

        prob, per_layer = self._detector.score(inp.activations)
        verdict = prob >= self._detector.threshold
        result = LayerResult(
            layer=self.name,
            ran=True,
            score=prob,
            threshold=self._detector.threshold,
            verdict=Verdict.MALICIOUS if verdict else Verdict.BENIGN,
            action=Action.BLOCK if verdict else Action.PASS,
            detail={"per_layer_cfs": per_layer},
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
        # CIFT acts before the output is returned: block-or-pass (nothing rendered to sanitize).
        return StageOutput(result=result, halt=verdict)
