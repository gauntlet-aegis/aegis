"""NIMBUS stage — cumulative multi-turn leakage budget.

Stub for the spine milestone (emits a zeroed NimbusBudget so the dashboard meter renders).
The real InfoNCE estimator + GRU critic land in ``sentinel/detect/nimbus/`` and are wired in
here in M6. This is the only stateful stage: it accumulates across turns via ConversationStore.
"""

from __future__ import annotations

import time

from sentinel.events.schema import Action, LayerResult, NimbusBudget, Verdict
from sentinel.stages.base import Phase, StageInput, StageOutput

WARN_RATIO = 0.6
SANITIZE_RATIO = 0.9
BLOCK_RATIO = 1.0


class NimbusStage:
    name = "nimbus"
    phase = Phase.POST_OUTPUT
    requires_whitebox = False

    def __init__(self, store, estimator=None, budget_bits: float = 16.0) -> None:
        self._store = store  # ConversationStore (cross-turn state)
        self._estimator = estimator  # InfoNCE estimator (None => stub mode)
        self._budget = budget_bits

    def run(self, inp: StageInput) -> StageOutput:
        t0 = time.perf_counter()
        st = self._store.get(inp.ctx.conversation_id)

        if self._estimator is None:
            per_turn = 0.0
        else:
            secret = inp.ctx.secret_to_track()
            i_now = self._estimator.infonce_bits(secret, inp.ctx.conversation_id, inp.output_text or "")
            per_turn = max(0.0, i_now - st.last_infonce_bits)
            st.last_infonce_bits = i_now

        st.cumulative_bits += per_turn
        ratio = st.cumulative_bits / self._budget if self._budget > 0 else 0.0

        if ratio >= BLOCK_RATIO:
            verdict, action, halt = Verdict.MALICIOUS, Action.BLOCK, True
        elif ratio >= SANITIZE_RATIO:
            verdict, action, halt = Verdict.SUSPICIOUS, Action.SANITIZE, False
        elif ratio >= WARN_RATIO:
            verdict, action, halt = Verdict.SUSPICIOUS, Action.WARN, False
        else:
            verdict, action, halt = Verdict.BENIGN, Action.PASS, False

        budget = NimbusBudget(
            cumulative_bits=st.cumulative_bits,
            budget_bits=self._budget,
            ratio=min(1.0, ratio) if self._budget > 0 else 0.0,
            per_turn_bits=per_turn,
            crossed_warn=ratio >= WARN_RATIO,
            crossed_block=ratio >= BLOCK_RATIO,
        )
        inp.ctx.nimbus = budget

        result = LayerResult(
            layer=self.name,
            ran=True,
            score=st.cumulative_bits,
            threshold=self._budget,
            verdict=verdict,
            action=action,
            detail={"i_cum_bits": st.cumulative_bits, "i_turn_bits": per_turn, "ratio": ratio},
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
        return StageOutput(result=result, halt=halt)
