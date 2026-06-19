"""The day-1 contract: the per-turn event schema that every layer and the dashboard share.

This is deliberately the first thing built. Detectors emit ``LayerResult``s, the orchestrator
assembles a ``TurnEvent``, and the dashboard renders it. Freezing this shape lets the proxy,
the detectors, and the UI develop against stubs in parallel.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

SCHEMA_VERSION = 1


class Mode(str, Enum):
    WHITEBOX = "whitebox"
    BLACKBOX = "blackbox"


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    SKIPPED = "skipped"  # stage did not run (e.g. CIFT in black-box, wrong phase)


class Action(str, Enum):
    PASS = "pass"
    WARN = "warn"
    SANITIZE = "sanitize"
    BLOCK = "block"


# Severity ordering so the orchestrator can take the most-severe action across layers
# without ever fusing scores (the layers stay orthogonal per PRD §4.2).
_ACTION_SEVERITY: dict[Action, int] = {
    Action.PASS: 0,
    Action.WARN: 1,
    Action.SANITIZE: 2,
    Action.BLOCK: 3,
}


def action_severity(action: Action) -> int:
    return _ACTION_SEVERITY[action]


def most_severe(actions: list[Action]) -> Action:
    """Return the highest-severity action; PASS if the list is empty."""
    return max(actions, key=action_severity, default=Action.PASS)


class LayerResult(BaseModel):
    """One detection layer's verdict for one turn."""

    layer: str  # "dp_honey" | "cift" | "text" | "nimbus"
    ran: bool
    score: float | None = None  # layer-native score (Mahalanobis/CFS, nonconformity, bits)
    threshold: float | None = None
    verdict: Verdict = Verdict.BENIGN
    action: Action = Action.PASS
    detail: dict = Field(default_factory=dict)  # layer-specific extras for the UI
    latency_ms: float = 0.0


class NimbusBudget(BaseModel):
    """Cumulative multi-turn leakage accounting (drives the dashboard meter)."""

    cumulative_bits: float  # Î_cum
    budget_bits: float  # B
    ratio: float  # Î_cum / B
    per_turn_bits: float  # this turn's increment ΔI
    crossed_warn: bool = False
    crossed_block: bool = False


class TurnEvent(BaseModel):
    """The complete record of one proxied turn, emitted to the dashboard + JSONL sink."""

    schema_version: int = SCHEMA_VERSION
    turn_id: str
    conversation_id: str
    turn_index: int  # 0-based within the conversation
    ts: str  # ISO8601
    mode: Mode

    # Inputs shown in the UI (the model-visible, honeytoken-substituted form).
    system_prompt_preview: str = ""
    untrusted_content_preview: str = ""
    user_query: str = ""
    attack_label: str | None = None  # red-team ground truth: "base64" | "drip" | None(benign)

    # Per-stage results, in execution order.
    layers: list[LayerResult] = Field(default_factory=list)
    nimbus: NimbusBudget | None = None

    # Final decision.
    action: Action = Action.PASS
    caught_by: str | None = None  # which layer triggered the action
    landed: bool = False  # True if a real attack got through uncaught
    output_preview: str = ""  # final (possibly sanitized/blocked) output

    timing_ms: dict = Field(default_factory=dict)  # {"total":.., "forward":.., "stages":..}
