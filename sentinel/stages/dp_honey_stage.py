"""DP-HONEY stage — encoding-robust honeytoken canary on the output.

Stub for the spine milestone. The real cross-encoding scanner + conformal fuzzy channel land
in ``sentinel/detect/dp_honey/`` and are wired in here in M4. Honeytoken *injection* itself is
done by the orchestrator via the ledger (a proxy property, PRD §4.3); this stage only detects.
"""

from __future__ import annotations

import time

from sentinel.events.schema import Action, LayerResult, Verdict
from sentinel.stages.base import Phase, StageInput, StageOutput


class DPHoneyStage:
    name = "dp_honey"
    phase = Phase.POST_OUTPUT
    requires_whitebox = False

    def __init__(self, scanner=None, fuzzy_threshold: float | None = None) -> None:
        self._scanner = scanner  # cross-encoding scanner (None => stub mode)
        self._fuzzy_threshold = fuzzy_threshold

    def run(self, inp: StageInput) -> StageOutput:
        t0 = time.perf_counter()
        if self._scanner is None:
            result = LayerResult(
                layer=self.name,
                ran=False,
                verdict=Verdict.SKIPPED,
                action=Action.PASS,
                detail={"reason": "stub"},
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
            return StageOutput(result=result)

        tokens = [t.value for t in (inp.ctx.ledger.honeytokens() if inp.ctx.ledger else [])]
        hits = self._scanner.scan(inp.output_text or "", tokens)
        exact = [h for h in hits if h.exact]
        fuzzy = max((h.fragment_ratio for h in hits), default=0.0)

        if exact:
            verdict, action, halt, score = Verdict.MALICIOUS, Action.BLOCK, True, 1.0
        elif self._fuzzy_threshold is not None and fuzzy > self._fuzzy_threshold:
            verdict, action, halt, score = Verdict.SUSPICIOUS, Action.SANITIZE, False, fuzzy
        else:
            verdict, action, halt, score = Verdict.BENIGN, Action.PASS, False, fuzzy

        result = LayerResult(
            layer=self.name,
            ran=True,
            score=score,
            threshold=self._fuzzy_threshold,
            verdict=verdict,
            action=action,
            detail={"hits": [h.as_dict() for h in hits]},
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
        return StageOutput(result=result, halt=halt)
