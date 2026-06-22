"""The detector contract (PDF section 6.1).

Every detector returns the same logical shape so the pipeline and policy engine can treat them
uniformly. A detector is a small, single-responsibility unit: it inspects an
:class:`~aegis.events.AegisEvent` and returns a :class:`DetectorResult`. It must not enforce —
enforcement is the policy engine's job.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from aegis.decision import Action, Phase, Verdict

if TYPE_CHECKING:
    from aegis.events import AegisEvent


class DetectorResult(BaseModel):
    """Common detector output. ``evidence`` is detector-specific structured proof for the audit
    trail and dashboard (e.g. matched pattern, decoded payload, canary id, tool/arg names)."""

    detector_name: str
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    recommended_action: Action = Action.ALLOW
    verdict: Verdict = Verdict.BENIGN
    evidence: dict = Field(default_factory=dict)
    latency_ms: float = 0.0

    @classmethod
    def skipped(cls, name: str) -> "DetectorResult":
        """A detector that did not apply to this event (e.g. wrong phase)."""
        return cls(detector_name=name, score=0.0, verdict=Verdict.SKIPPED)


@runtime_checkable
class Detector(Protocol):
    """Structural contract for a detector.

    ``name`` is stable (used in evidence + policy rules). ``phases`` is the set of guard phases
    the detector applies to; the pipeline skips it elsewhere. ``run`` must be deterministic for
    deterministic detectors and must never raise on adversarial input (return a result instead).
    """

    name: str
    phases: frozenset[Phase]

    def run(self, event: "AegisEvent") -> DetectorResult: ...
