"""Core decision types — the contract every detector, the policy engine, and the SDK share.

These enums and models are the stable join points of the whole system. Detectors recommend an
:class:`Action`; the policy engine combines recommendations under a mode and the most-severe
action wins (see :data:`ACTION_SEVERITY`); the SDK returns an :class:`AegisDecision`.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum

from pydantic import BaseModel, Field


class Action(IntEnum):
    """What to do with a guarded request/tool-call/response.

    Defined as an ``IntEnum`` so "most severe wins" is a plain ``max(...)`` — the integer
    value IS the severity ordering. Never average these; severity is ordinal, not numeric.
    """

    ALLOW = 0
    WARN = 1       # annotate, let through
    SANITIZE = 2   # let through with the offending span minimally redacted/generalized
    BLOCK = 3      # refuse to forward
    ESCALATE = 4   # block AND raise for human/out-of-band review (most severe)

    @property
    def is_allow(self) -> bool:
        return self is Action.ALLOW


# Explicit severity map (mirrors the IntEnum values) for readability at call sites.
ACTION_SEVERITY: dict[Action, int] = {a: int(a) for a in Action}


def most_severe(actions: list[Action]) -> Action:
    """Combine detector/policy actions: the single most severe one wins (never fuse scores)."""
    return max(actions, default=Action.ALLOW)


class Verdict(StrEnum):
    """A detector's qualitative read, independent of the recommended action."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    SKIPPED = "skipped"  # detector did not apply to this phase / input


class Phase(StrEnum):
    """Which guard surface produced an event."""

    REQUEST = "request"
    TOOL_CALL = "tool_call"
    RESPONSE = "response"


class TrustBoundary(StrEnum):
    """Provenance of the content under inspection (drives taint-aware scoring)."""

    TRUSTED = "trusted"      # system prompt, developer-authored
    UNTRUSTED = "untrusted"  # retrieved docs, tool outputs, user-pasted content
    MIXED = "mixed"          # both present in the same context


class AegisDecision(BaseModel):
    """The structured result every SDK guard returns.

    ``action`` is authoritative. ``sanitized_payload`` carries the rewritten content when the
    action is SANITIZE (the least-disclosing variant). Every non-ALLOW decision must carry at
    least one human-readable reason (enforced by the SDK / verified in tests).
    """

    action: Action
    risk_score: float = Field(ge=0.0, le=1.0, description="Max detector score that drove the action.")
    reasons: list[str] = Field(default_factory=list)
    detector_hits: list[DetectorResult] = Field(default_factory=list)
    sanitized_payload: str | dict | None = None
    trace_id: str
    event_id: str

    @property
    def allowed(self) -> bool:
        """True only for a clean ALLOW (nothing flagged). Stricter than :attr:`forwardable`."""
        return self.action is Action.ALLOW

    @property
    def forwardable(self) -> bool:
        """True when the original content may pass through: ALLOW or WARN (annotate, don't rewrite).
        WARN deliberately forwards — observe mode clamps everything to WARN and must never block."""
        return self.action <= Action.WARN

    @property
    def blocks(self) -> bool:
        """True when forwarding must stop: BLOCK or ESCALATE (refuse). SANITIZE rewrites instead."""
        return self.action >= Action.BLOCK


# Imported here (not at top) to avoid a circular import: DetectorResult lives in detectors.base,
# which imports Action/Verdict from this module. Rebuild the model once the name is available.
from aegis.detectors.base import DetectorResult  # noqa: E402

AegisDecision.model_rebuild()
