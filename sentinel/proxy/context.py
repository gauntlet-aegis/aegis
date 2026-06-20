"""Per-turn working state threaded through the pipeline, plus cross-turn conversation state.

``TurnContext`` is the mutable bag the orchestrator builds for one turn and hands to each
stage. ``ConversationStore`` holds state that must persist across turns within a conversation
(notably NIMBUS cumulative leakage and the per-conversation honeytoken ledger).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.events.schema import LayerResult, Mode, NimbusBudget
from sentinel.proxy.honeytoken import HoneytokenLedger


@dataclass
class TurnContext:
    """Everything about one proxied turn."""

    conversation_id: str
    turn_index: int
    mode: Mode

    # Parsed, model-visible (honeytoken-substituted) request parts.
    system_prompt: str = ""
    untrusted_content: str = ""
    user_query: str = ""
    messages: list[dict] = field(default_factory=list)  # model-visible chat messages

    ledger: HoneytokenLedger | None = None
    attack_label: str | None = None  # red-team ground truth, supplied via header for the demo

    # Accumulated as stages run.
    layers: list[LayerResult] = field(default_factory=list)
    nimbus: NimbusBudget | None = None

    def secret_to_track(self) -> str | None:
        """The honeytoken value NIMBUS watches for cumulative leakage (the model-visible secret)."""
        if self.ledger is None:
            return None
        tokens = self.ledger.honeytokens()
        return tokens[0].value if tokens else None


@dataclass
class _ConvState:
    cumulative_bits: float = 0.0
    last_infonce_bits: float = 0.0
    turn_count: int = 0
    ledger: HoneytokenLedger | None = None


class ConversationStore:
    """In-memory per-conversation state (NIMBUS accumulation + ledger persistence)."""

    def __init__(self) -> None:
        self._state: dict[str, _ConvState] = {}

    def get(self, conversation_id: str) -> _ConvState:
        st = self._state.get(conversation_id)
        if st is None:
            st = _ConvState()
            self._state[conversation_id] = st
        return st

    def reset(self, conversation_id: str) -> None:
        self._state.pop(conversation_id, None)
