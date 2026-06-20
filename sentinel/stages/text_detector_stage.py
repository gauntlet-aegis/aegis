"""The naive text-filter baseline — the "anyone can grep" defense.

This is deliberately dumb: it scans the output for the planted secret verbatim (plus a couple
of trivial normalizations). It catches the verbatim attack and goes *dark* the moment the
attacker encodes the secret (Base64/hex/ROT13) — which is exactly the contrast the demo needs
against CIFT (pre-output) and DP-HONEY (encoding-robust canary).
"""

from __future__ import annotations

import time

from sentinel.events.schema import Action, LayerResult, Verdict
from sentinel.stages.base import Phase, StageInput, StageOutput


class TextDetectorStage:
    name = "text"
    phase = Phase.POST_OUTPUT
    requires_whitebox = False

    def run(self, inp: StageInput) -> StageOutput:
        t0 = time.perf_counter()
        output = inp.output_text or ""
        ledger = inp.ctx.ledger

        hit = None
        if ledger is not None:
            for token in ledger.honeytokens():
                if token.value and token.value in output:
                    hit = token.value
                    break

        verdict = Verdict.MALICIOUS if hit else Verdict.BENIGN
        action = Action.BLOCK if hit else Action.PASS
        result = LayerResult(
            layer=self.name,
            ran=True,
            score=1.0 if hit else 0.0,
            threshold=1.0,
            verdict=verdict,
            action=action,
            detail={"matched_verbatim": bool(hit)},
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
        return StageOutput(result=result, halt=bool(hit))
