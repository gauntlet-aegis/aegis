"""Provenance / taint tracking (research extension).

Indirect prompt injection works because attacker-controlled (untrusted) content sits next to
trusted secrets in the same context. Taint tracking tags each span of content with where it
came from, so a later stage can ask: *did this credential-shaped value in a tool argument
originate in untrusted content?* That provenance signal is additive — it raises risk and
sharpens evidence, but never blocks on its own (deterministic detectors remain authoritative).

Encoding-awareness is achieved by letting callers pass the set of equivalent forms of a value
(verbatim + decoded/encoded variants, computed by :mod:`aegis.detectors.encoding`) into
:func:`provenance_of`, so a value that was base64-encoded inside untrusted content is still
traced back to its untrusted origin.
"""

from __future__ import annotations

from pydantic import BaseModel

from aegis.decision import TrustBoundary


class TaintedSpan(BaseModel):
    """A contiguous piece of content with a known origin.

    ``source`` is a human-readable origin label, e.g. ``"system"``, ``"user"``,
    ``"tool_output:web_fetch"``, ``"retrieved_doc"``.
    """

    text: str
    boundary: TrustBoundary
    source: str = ""

    def contains(self, needle: str) -> bool:
        return bool(needle) and needle in self.text


def overall_boundary(spans: list[TaintedSpan]) -> TrustBoundary:
    """Collapse spans to a single boundary: MIXED if both trusted and untrusted are present."""
    kinds = {s.boundary for s in spans}
    has_untrusted = TrustBoundary.UNTRUSTED in kinds or TrustBoundary.MIXED in kinds
    has_trusted = TrustBoundary.TRUSTED in kinds or TrustBoundary.MIXED in kinds
    if has_untrusted and has_trusted:
        return TrustBoundary.MIXED
    if has_untrusted:
        return TrustBoundary.UNTRUSTED
    return TrustBoundary.TRUSTED


def provenance_of(value: str, spans: list[TaintedSpan], *, equivalent_forms: set[str] | None = None) -> TrustBoundary:
    """Where did ``value`` come from? Returns the *most untrusted* origin span it appears in.

    ``equivalent_forms`` lets the caller include decoded/encoded variants of ``value`` so an
    encoded credential is still traced to its untrusted source. Defaults to just ``value``.
    """
    forms = {value} | (equivalent_forms or set())
    forms = {f for f in forms if f}
    untrusted_hit = trusted_hit = False
    for span in spans:
        if any(span.contains(f) for f in forms):
            if span.boundary in (TrustBoundary.UNTRUSTED, TrustBoundary.MIXED):
                untrusted_hit = True
            if span.boundary in (TrustBoundary.TRUSTED, TrustBoundary.MIXED):
                trusted_hit = True
    if untrusted_hit and trusted_hit:
        return TrustBoundary.MIXED
    if untrusted_hit:
        return TrustBoundary.UNTRUSTED
    return TrustBoundary.TRUSTED


def spans_from_messages(messages: list[dict]) -> list[TaintedSpan]:
    """Derive taint spans from chat messages.

    Convention: ``system``/``developer`` and ``assistant`` roles are TRUSTED; ``user`` and
    ``tool`` roles are UNTRUSTED (user-pasted text and tool outputs are attacker-reachable).
    A message may set ``{"trust": "trusted"|"untrusted"}`` to override.
    """
    spans: list[TaintedSpan] = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        override = m.get("trust")
        if override in (TrustBoundary.TRUSTED, "trusted"):
            boundary = TrustBoundary.TRUSTED
        elif override in (TrustBoundary.UNTRUSTED, "untrusted"):
            boundary = TrustBoundary.UNTRUSTED
        else:
            boundary = TrustBoundary.TRUSTED if role in ("system", "developer", "assistant") else TrustBoundary.UNTRUSTED
        spans.append(TaintedSpan(text=content, boundary=boundary, source=role))
    return spans
