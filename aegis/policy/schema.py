"""Policy schema — the YAML contract the engine loads at startup (PDF sections 6.3/6.4).

A policy is a *mode* plus a flat list of *rules*. Rules are deliberately non-nested and
evaluated independently (the engine ORs them and takes the most-severe action) — no boolean
trees, no precedence to reason about. That keeps a policy auditable: each rule reads as one
plain "if <condition> -> <action>" line, and the only combinator is "most severe wins".

Each rule is a pydantic model carrying a string ``type`` discriminator, so the four shapes form
a discriminated union (:data:`PolicyRule`). The engine in ``engine.py`` matches each rule
against the list of :class:`~aegis.detectors.base.DetectorResult` for an event.
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field

from aegis.decision import Action

# StrEnum lives in modes.py (mode behavior travels with its definition). Re-imported here so the
# Policy model and the package __init__ can reference Mode from one obvious place.
from aegis.policy.modes import Mode


class DetectorScoreThreshold(BaseModel):
    """Fire when a detector's ``score`` meets ``threshold``.

    ``detector`` is a detector name, or ``"*"`` to match *any* detector (the catch-all rule the
    default policy uses to give every detector a floor). Comparison is ``score >= threshold``.
    """

    type: Literal["detector_score_threshold"]
    detector: str = "*"
    threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    action: Action = Action.BLOCK


class ToolArgCondition(BaseModel):
    """Fire on a tool-call argument carrying a secret.

    Matches against a detector named ``"tool_call_args"`` via its ``evidence`` findings (each
    finding is expected to carry ``tool``, ``arg`` and a ``contains_secret`` flag). ``tool`` and
    ``arg`` may be ``"*"`` to match any. When ``contains_secret`` is set, the finding's flag must
    equal it; when ``None`` the secret state is not constrained (the rule fires on any matching
    tool/arg finding).
    """

    type: Literal["tool_arg_condition"]
    tool: str = "*"
    arg: str = "*"
    contains_secret: bool | None = True
    action: Action = Action.BLOCK


class CanaryHit(BaseModel):
    """Fire when the ``"honeytoken"`` detector's verdict is malicious — a planted canary
    reappeared downstream, which is ground-truth exfiltration (PDF: honeytokens)."""

    type: Literal["canary_hit"]
    action: Action = Action.ESCALATE


class LeakageBudgetThreshold(BaseModel):
    """Fire when the ``"nimbus_lite"`` detector's cumulative leakage ``ratio`` meets ``ratio``.

    NIMBUS tracks how much of a session's leakage budget has been spent across turns; the rule
    reads that fraction from the detector's ``evidence`` (key ``ratio``). Comparison is
    ``evidence_ratio >= ratio``.
    """

    type: Literal["leakage_budget_threshold"]
    ratio: float = Field(default=0.9, ge=0.0, le=1.0)
    action: Action = Action.SANITIZE


# Discriminated union over the `type` field: pydantic picks the right model per rule, and an
# unknown `type` is a validation error (caught at load time, not at decide time).
PolicyRule = Annotated[
    Union[DetectorScoreThreshold, ToolArgCondition, CanaryHit, LeakageBudgetThreshold],
    Field(discriminator="type"),
]


class Policy(BaseModel):
    """A loaded policy: the active :class:`Mode` plus the flat rule list."""

    mode: Mode = Mode.BALANCED
    rules: list[PolicyRule] = Field(default_factory=list)


__all__ = [
    "Mode",
    "Policy",
    "PolicyRule",
    "DetectorScoreThreshold",
    "ToolArgCondition",
    "CanaryHit",
    "LeakageBudgetThreshold",
]
