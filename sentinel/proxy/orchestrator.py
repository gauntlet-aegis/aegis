"""The orchestrator: runs the PRD §5 pipeline for one turn and assembles the TurnEvent.

Order:
  1. DP-HONEY injection (pre-forward)  -> plant honeytokens into model-visible context
  2. forward pass                      -> text (+ activations in white-box)
  3. CIFT (post-forward, pre-output)   -> may halt before the output is returned
  4. text detector + DP-HONEY + NIMBUS (post-output)
Then graduated response picks the most-severe action and rewrites the output.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from sentinel.config import Settings
from sentinel.events.schema import Action, TurnEvent
from sentinel.model.host import ModelHost
from sentinel.proxy import response
from sentinel.proxy.context import ConversationStore, TurnContext
from sentinel.proxy.honeytoken import HoneytokenLedger, inject_honeytokens
from sentinel.stages.base import Phase, StageInput
from sentinel.stages.registry import build_pipeline, stages_for_phase


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _preview(text: str, n: int = 240) -> str:
    text = text or ""
    return text if len(text) <= n else text[:n] + "…"


class Orchestrator:
    def __init__(
        self,
        settings: Settings,
        host: ModelHost,
        store: ConversationStore | None = None,
        *,
        detectors: dict | None = None,
    ) -> None:
        self.settings = settings
        self.host = host
        self.store = store or ConversationStore()
        d = detectors or {}
        self._honey_generator = d.get("honey_generator")
        self.pipeline = build_pipeline(
            settings.mode,
            self.store,
            cift_detector=d.get("cift"),
            dp_honey_scanner=d.get("dp_honey_scanner"),
            dp_honey_fuzzy_threshold=d.get("dp_honey_fuzzy_threshold"),
            nimbus_estimator=d.get("nimbus"),
            nimbus_budget_bits=settings.nimbus.budget_bits,
        )

    def _ledger_for(self, conversation_id: str) -> HoneytokenLedger:
        st = self.store.get(conversation_id)
        if st.ledger is None:
            if self._honey_generator is not None:
                st.ledger = HoneytokenLedger(conversation_id, generator=self._honey_generator)
            else:
                st.ledger = HoneytokenLedger(conversation_id)
        return st.ledger

    def handle(
        self,
        conversation_id: str,
        turn_index: int,
        messages: list[dict],
        *,
        attack_label: str | None = None,
        real_secrets: dict[str, str] | None = None,
    ) -> tuple[str, TurnEvent]:
        t_total = time.perf_counter()
        ledger = self._ledger_for(conversation_id)
        for name, value in (real_secrets or {}).items():
            ledger.register_real(name, value)

        # 1. Injection (pre-forward): only honeytokens become model-visible.
        model_messages = inject_honeytokens(messages, ledger, turn_index)

        ctx = TurnContext(
            conversation_id=conversation_id,
            turn_index=turn_index,
            mode=self.settings.mode,
            messages=model_messages,
            system_prompt=next((m["content"] for m in model_messages if m["role"] == "system"), ""),
            user_query=next(
                (m["content"] for m in reversed(model_messages) if m["role"] == "user"), ""
            ),
            ledger=ledger,
            attack_label=attack_label,
        )

        # 2. Forward pass.
        gen = self.host.generate(model_messages)
        output_text = gen.text

        halted = False
        # 3. CIFT (post-forward, pre-output) — can abort before output is returned.
        for stage in stages_for_phase(self.pipeline, Phase.POST_FORWARD_PRE_OUTPUT):
            out = stage.run(StageInput(ctx=ctx, activations=gen.activations, output_text=None))
            ctx.layers.append(out.result)
            if out.halt:
                halted = True
                break

        # 4. Post-output stages (skipped if CIFT already halted).
        if not halted:
            for stage in stages_for_phase(self.pipeline, Phase.POST_OUTPUT):
                out = stage.run(StageInput(ctx=ctx, activations=None, output_text=output_text))
                ctx.layers.append(out.result)
                if out.mutated_output is not None:
                    output_text = out.mutated_output
                if out.halt:
                    break

        # Graduated response.
        final_action, caught_by = response.decide(ctx.layers)
        client_text = response.apply(final_action, output_text)

        # An attack "landed" if it was a real attack and nothing blocked/sanitized it.
        landed = bool(attack_label) and final_action in (Action.PASS, Action.WARN)

        event = TurnEvent(
            turn_id=str(uuid.uuid4()),
            conversation_id=conversation_id,
            turn_index=turn_index,
            ts=_now_iso(),
            mode=self.settings.mode,
            system_prompt_preview=_preview(ctx.system_prompt),
            untrusted_content_preview=_preview(ctx.untrusted_content or ctx.user_query),
            user_query=_preview(ctx.user_query),
            attack_label=attack_label,
            layers=ctx.layers,
            nimbus=ctx.nimbus,
            action=final_action,
            caught_by=caught_by,
            landed=landed,
            output_preview=_preview(client_text),
            timing_ms={
                "total": (time.perf_counter() - t_total) * 1000,
                "forward": gen.latency_ms,
            },
        )
        return client_text, event
