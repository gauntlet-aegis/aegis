"""Honeytoken detector (PDF section 6.4) — ground-truth exfiltration detection.

Canaries planted via :class:`aegis.honeytokens.registry.HoneytokenRegistry` are unique strings
that have no legitimate reason to appear in a tool call or response. So when one does, it is a
leak by definition — not a heuristic. This detector scans every tool-call argument and every
response/tool-call body for any registered canary, both verbatim and after running the content
through :func:`aegis.detectors.encoding.decodings` (so a base64/hex/reversed canary is still
caught). On a hit it reports MALICIOUS / BLOCK with the canary's provenance.

Where it fits: the most authoritative leak signal in the detector suite — the policy engine can
trust a honeytoken hit far more than a shape-based heuristic. Never raises on adversarial input.
"""

from __future__ import annotations

import time

from aegis.decision import Action, Phase, Verdict
from aegis.detectors.base import DetectorResult
from aegis.detectors.encoding import decodings
from aegis.detectors.normalize import nfkc_strip
from aegis.events import AegisEvent
from aegis.honeytokens.registry import HoneytokenRegistry

# Minimum canary length to match by plain substring. Generated tokens are long (>=19 chars); this
# floor stops a short/dictionary-word canary (e.g. "cat") from flagging benign text as a leak.
_MIN_CANARY_LEN = 8


class HoneytokenDetector:
    """Detector: flag any registered canary appearing downstream (verbatim or decoded)."""

    name = "honeytoken"
    phases = frozenset({Phase.TOOL_CALL, Phase.RESPONSE})

    def __init__(self, registry: HoneytokenRegistry) -> None:
        self._registry = registry

    def run(self, event: AegisEvent) -> DetectorResult:
        t0 = time.perf_counter()
        tokens = self._registry.tokens()
        if not tokens:
            return self._benign(t0)

        try:
            hit = self._scan(event, tokens)
        except Exception:
            # Detectors must never raise on adversarial input — fail benign.
            return self._benign(t0)

        latency = (time.perf_counter() - t0) * 1000
        if hit is None:
            return DetectorResult(detector_name=self.name, score=0.0, confidence=1.0,
                                  verdict=Verdict.BENIGN, recommended_action=Action.ALLOW,
                                  latency_ms=latency)
        return DetectorResult(
            detector_name=self.name,
            score=1.0,
            confidence=1.0,
            verdict=Verdict.MALICIOUS,
            recommended_action=Action.BLOCK,
            evidence=hit,
            latency_ms=latency,
        )

    # ---- internals ----------------------------------------------------------------------
    def _scan(self, event: AegisEvent, tokens: list[str]) -> dict | None:
        """Return evidence for the first canary found, or ``None``. Checks each tool-arg value and
        the flat inspectable text, both verbatim and via decoded forms."""
        token_set = {t for t in tokens if len(t) >= _MIN_CANARY_LEN}
        if not token_set:
            return None

        # Per-argument scan first, so we can attribute the hit to the specific tool argument.
        for arg_name, value in event.tool_arg_items():
            ev = self._match(value, token_set, where=f"tool_arg:{arg_name}")
            if ev:
                return ev

        # Whole-surface scan (response output, or the flattened tool-call body).
        return self._match(event.inspectable_text(), token_set, where="output")

    def _match(self, text: str, token_set: set[str], *, where: str) -> dict | None:
        """Look for any token in ``text`` verbatim, then in its decoded forms. ``text`` is
        Unicode-normalized first so a canary spliced with zero-width/homoglyph chars still matches."""
        if not text:
            return None
        text = nfkc_strip(text)
        for token in token_set:
            if token in text:
                return self._evidence(token, where, "verbatim")
        for decoded in decodings(text):
            for token in token_set:
                if token in decoded:
                    return self._evidence(token, where, "decoded")
        return None

    def _evidence(self, token: str, where: str, encoding: str) -> dict:
        canary = self._registry.lookup(token)
        return {
            "canary_id": canary.canary_id if canary else None,
            "service": canary.service if canary else None,
            "location": canary.location if canary else None,
            "where": where,
            "encoding": encoding,
        }

    def _benign(self, t0: float) -> DetectorResult:
        return DetectorResult(detector_name=self.name, score=0.0, confidence=1.0,
                              verdict=Verdict.BENIGN, recommended_action=Action.ALLOW,
                              latency_ms=(time.perf_counter() - t0) * 1000)
