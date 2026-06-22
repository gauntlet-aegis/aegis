"""Aegis — runtime credential-exfiltration defense for LLM agents.

Aegis is an SDK-first security layer. The :mod:`aegis.sdk` guards
(``guard_request`` / ``guard_tool_call`` / ``guard_response``) own all security decisions;
the FastAPI gateway in :mod:`aegis.gateway` and the eval harness are thin callers of the
same SDK so the security logic lives in exactly one place.

Pipeline shape (see :mod:`aegis.pipeline`): Inspect (detectors) -> Score (risk) ->
Enforce (policy). Deterministic detectors are authoritative; the most-severe action wins
and detector scores are never numerically fused.

This package is demo-grade, not production-grade. The cumulative leakage ledger is a learned
*signal*, not a formal information-flow bound.
"""

from aegis.decision import Action, AegisDecision, Phase, TrustBoundary, Verdict
from aegis.events import AegisEvent

__all__ = [
    "Action",
    "AegisDecision",
    "AegisEvent",
    "Phase",
    "TrustBoundary",
    "Verdict",
]
