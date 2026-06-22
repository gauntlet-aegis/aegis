"""NIMBUS-LITE cumulative leakage ledger (multi-turn drip-exfiltration signal).

Single-turn detectors (secret-pattern, encoding) catch a credential that appears whole in one
event. They are blind to a *low-and-slow* attacker who leaks one harmless-looking fragment per
turn — none trips a single-turn shape check, but the fragments cumulatively reconstruct a secret.

This module accumulates a per-SESSION leakage score across turns. Each turn contributes an
increment from cheap, deterministic signals (a full credential shape trips instantly; novel
high-entropy token-character runs add a little each). When the running total crosses a normalized
budget, the session is flagged.

HONEST FRAMING: this is a learned/heuristic cumulative *signal*, NOT a formal information-flow
bound. It does not prove how many bits of a secret have actually left the boundary; it estimates
suspicion from observable token shapes. Treat its output as a risk score, not a guarantee.

Where it fits: a stateful detector in the same pipeline as the single-turn scanners. The pure
:class:`LeakageLedger` holds state and scores text; :class:`NimbusLiteLedger` adapts it to the
:class:`~aegis.detectors.base.Detector` protocol and maps the running ratio to an
:class:`~aegis.decision.Action`.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from aegis.decision import Action, Phase, Verdict
from aegis.detectors.base import DetectorResult
from aegis.detectors.encoding import decodings
from aegis.detectors.secret_pattern import find_secrets

# A "credential-looking fragment": a run of >=6 chars from the base64/hex token alphabet. Short
# enough to slip past whole-secret shape checks, distinctive enough that many distinct ones in one
# session is a drip-exfil tell. Letters-and-digits required so prose words ("password") don't count
# unless they carry digits — we additionally require at least one digit below to cut English noise.
_FRAGMENT = re.compile(r"[A-Za-z0-9+/=_-]{6,}")
_HAS_DIGIT = re.compile(r"[0-9]")

# Per-turn tuning (normalized so budget defaults to 1.0).
_FRAGMENT_INCREMENT = 0.15   # per NEW distinct fragment
_MAX_FRAGMENTS_PER_TURN = 3  # cap a single turn's fragment contribution (3 * 0.15 = 0.45)
# Bound retained per-session state so a long-lived guard process can't grow unboundedly across
# many distinct session ids; the oldest session is evicted past this cap (FIFO).
_MAX_SESSIONS = 50_000


def _fragments(text: str) -> set[str]:
    """Distinct credential-looking fragments in ``text`` (entropy-ish runs carrying a digit)."""
    if not text:
        return set()
    return {m.group(0) for m in _FRAGMENT.finditer(text) if _HAS_DIGIT.search(m.group(0))}


@dataclass
class _SessionState:
    """Mutable per-session accumulator. ``seen_fragments`` dedupes so re-emitting the same
    fragment cannot keep inflating the score."""

    cumulative: float = 0.0
    seen_fragments: set[str] = field(default_factory=set)


class LeakageLedger:
    """Stateful per-session cumulative-leakage accumulator.

    Deterministic, no ML. ``budget`` is the normalized leakage allowance (default 1.0); when a
    session's cumulative score reaches it, ``ratio`` hits 1.0. State is keyed by ``session_id``.

    HONEST FRAMING: the cumulative score is a heuristic suspicion signal, not a measured count of
    leaked secret bits (see module docstring).
    """

    def __init__(self, budget: float = 1.0) -> None:
        # A non-positive budget would silently disable the detector (ratio always 0 -> ALLOW). Clamp
        # to the default so a misconfiguration fails safe (still detecting) rather than blind.
        self.budget = float(budget) if (budget is not None and budget > 0) else 1.0
        self._sessions: dict[str, _SessionState] = {}

    def _state(self, session_id: str) -> _SessionState:
        st = self._sessions.get(session_id)
        if st is None:
            if len(self._sessions) >= _MAX_SESSIONS:
                self._sessions.pop(next(iter(self._sessions)))  # evict oldest (FIFO)
            st = self._sessions[session_id] = _SessionState()
        return st

    def observe(self, session_id: str, text: str) -> dict:
        """Score one turn's ``text`` for this session and fold it into the running total.

        Combines (a) full credential shapes — large instant increment that trips the budget — and
        (b) NEW high-entropy fragments — a small capped increment each, then marked seen so repeats
        do not re-accumulate. Also scans common decodings so an encoded fragment still counts.
        Returns ``{turn_score, cumulative, budget, ratio}``. Never raises.
        """
        try:
            st = self._state(session_id)
            text = text or ""

            # Scan the raw text plus its plausible decodings (base64/hex/reversal/etc.).
            surfaces = [text, *decodings(text)]

            # (a) A full credential shape anywhere -> instantly consume the whole budget.
            full_secret = any(find_secrets(s) for s in surfaces)

            # (b) Novel credential-looking fragments across all surfaces.
            candidates: set[str] = set()
            for s in surfaces:
                candidates |= _fragments(s)
            new_fragments = candidates - st.seen_fragments
            st.seen_fragments |= candidates

            turn_score = 0.0
            if full_secret:
                turn_score += self.budget
            counted = min(len(new_fragments), _MAX_FRAGMENTS_PER_TURN)
            turn_score += counted * _FRAGMENT_INCREMENT

            st.cumulative += turn_score
            ratio = st.cumulative / self.budget if self.budget > 0 else 0.0
            return {
                "turn_score": turn_score,
                "cumulative": st.cumulative,
                "budget": self.budget,
                "ratio": ratio,
            }
        except Exception:
            # A detector accumulator must never raise on adversarial input (base.py contract).
            return {"turn_score": 0.0, "cumulative": 0.0, "budget": self.budget, "ratio": 0.0}

    def state(self, session_id: str) -> dict:
        """Read current state for a session without mutating it."""
        st = self._sessions.get(session_id)
        cumulative = st.cumulative if st else 0.0
        return {
            "cumulative": cumulative,
            "budget": self.budget,
            "ratio": cumulative / self.budget if self.budget > 0 else 0.0,
            "seen_fragments": len(st.seen_fragments) if st else 0,
        }

    def reset(self, session_id: str) -> None:
        """Forget all accumulated state for a session (e.g. session ended / new conversation)."""
        self._sessions.pop(session_id, None)


class NimbusLiteLedger:
    """Detector adapter: scores each turn through a shared :class:`LeakageLedger` and maps the
    running ratio to an action.

    name ``nimbus_lite``; applies to RESPONSE and TOOL_CALL phases (the surfaces a credential
    leaves through). Mapping: ratio >= 1.0 BLOCK (malicious), >= 0.9 SANITIZE (suspicious),
    >= 0.6 WARN (suspicious), else ALLOW (benign). ``score`` is ``min(1.0, ratio)``. Never raises.

    HONEST FRAMING: the score is the ledger's heuristic cumulative signal, not a proven leak bound.
    """

    name = "nimbus_lite"
    phases = frozenset({Phase.RESPONSE, Phase.TOOL_CALL})

    def __init__(self, ledger: LeakageLedger) -> None:
        self.ledger = ledger

    def run(self, event) -> DetectorResult:  # event: AegisEvent (untyped to avoid import cycle)
        t0 = time.perf_counter()
        try:
            text = event.inspectable_text()
            arg_values = " ".join(v for _, v in event.tool_arg_items())
            combined = f"{text}\n{arg_values}" if arg_values else text
            res = self.ledger.observe(event.session_id, combined)
            ratio = res["ratio"]

            if ratio >= 1.0:
                action, verdict = Action.BLOCK, Verdict.MALICIOUS
            elif ratio >= 0.9:
                action, verdict = Action.SANITIZE, Verdict.SUSPICIOUS
            elif ratio >= 0.6:
                action, verdict = Action.WARN, Verdict.SUSPICIOUS
            else:
                action, verdict = Action.ALLOW, Verdict.BENIGN

            latency = (time.perf_counter() - t0) * 1000
            return DetectorResult(
                detector_name=self.name,
                score=min(1.0, ratio),
                confidence=0.7,
                recommended_action=action,
                verdict=verdict,
                evidence={
                    "turn_score": res["turn_score"],
                    "cumulative": res["cumulative"],
                    "budget": res["budget"],
                    "ratio": ratio,
                    "session_id": event.session_id,
                },
                latency_ms=latency,
            )
        except Exception:
            # Contract: never raise on adversarial input — degrade to a benign skip.
            return DetectorResult.skipped(self.name)
