"""Tests for the NIMBUS-LITE cumulative leakage ledger.

Covers the stateful accumulator (drip accumulation, fragment dedupe, instant full-secret trip,
per-session isolation) and the detector's ratio -> action mapping.
"""

from __future__ import annotations

from aegis.decision import Action, Phase, Verdict
from aegis.detectors.ledger import LeakageLedger, NimbusLiteLedger
from aegis.events import AegisEvent


def test_drip_of_distinct_fragments_crosses_warn_then_block():
    """A long drip of distinct benign-looking fragments eventually crosses WARN then BLOCK."""
    ledger = LeakageLedger(budget=1.0)
    sid = "drip"
    # Distinct high-entropy hex-ish fragments, one per turn — none is a full secret shape.
    fragments = [f"frag{i:02d}{i*7 % 100:02d}beef" for i in range(20)]

    crossed_warn = crossed_block = False
    warn_turn = block_turn = None
    for turn, frag in enumerate(fragments):
        ratio = ledger.observe(sid, frag)["ratio"]
        if not crossed_warn and ratio >= 0.6:
            crossed_warn, warn_turn = True, turn
        if not crossed_block and ratio >= 1.0:
            crossed_block, block_turn = True, turn

    assert crossed_warn, "drip never reached the WARN threshold"
    assert crossed_block, "drip never reached the BLOCK threshold"
    # WARN must be reached strictly before BLOCK (it is a slow climb, not an instant trip).
    assert warn_turn < block_turn


def test_repeating_same_fragment_does_not_keep_accumulating():
    """Re-emitting an already-seen fragment must not inflate the cumulative score."""
    ledger = LeakageLedger(budget=1.0)
    sid = "repeat"
    first = ledger.observe(sid, "deadbeef99")["cumulative"]
    assert first > 0.0  # the novel fragment did contribute once

    for _ in range(10):
        again = ledger.observe(sid, "deadbeef99")["cumulative"]
    # Cumulative is unchanged: every repeat scored zero (turn_score == 0).
    assert again == first
    assert ledger.observe(sid, "deadbeef99")["turn_score"] == 0.0


def test_single_full_secret_trips_immediately():
    """One full credential shape in a single turn consumes the whole budget at once."""
    ledger = LeakageLedger(budget=1.0)
    res = ledger.observe("oneshot", "here is my api_key sk-abcdefghijklmnopqrstuvwxyz0123")
    assert res["ratio"] >= 1.0
    assert res["turn_score"] >= ledger.budget


def test_sessions_accumulate_independently():
    """Two distinct session ids must not share state."""
    ledger = LeakageLedger(budget=1.0)
    ledger.observe("alice", "aa11bb22cc33")
    ledger.observe("alice", "dd44ee55ff66")

    assert ledger.state("alice")["cumulative"] > 0.0
    assert ledger.state("bob")["cumulative"] == 0.0  # untouched session is clean

    # reset clears only the named session.
    ledger.reset("alice")
    assert ledger.state("alice")["cumulative"] == 0.0


def test_detector_maps_ratios_to_actions():
    """The detector maps the running ratio to the documented action bands."""
    cases = [
        (0.5, Action.ALLOW, Verdict.BENIGN),
        (0.6, Action.WARN, Verdict.SUSPICIOUS),
        (0.9, Action.SANITIZE, Verdict.SUSPICIOUS),
        (1.0, Action.BLOCK, Verdict.MALICIOUS),
    ]
    for ratio, expected_action, expected_verdict in cases:
        # A stub ledger that reports a fixed ratio isolates the mapping from the scoring heuristic.
        class _FixedLedger(LeakageLedger):
            def observe(self, session_id: str, text: str) -> dict:  # type: ignore[override]
                return {"turn_score": 0.0, "cumulative": ratio, "budget": 1.0, "ratio": ratio}

        det = NimbusLiteLedger(_FixedLedger())
        event = AegisEvent.for_response("anything", session_id="map")
        result = det.run(event)
        assert result.recommended_action is expected_action, ratio
        assert result.verdict is expected_verdict, ratio
        assert result.score == min(1.0, ratio)
        assert result.evidence["ratio"] == ratio


def test_detector_phases_and_never_raises():
    """Sanity: correct phases, scores a tool call, and degrades to a skip on bad input."""
    det = NimbusLiteLedger(LeakageLedger())
    assert det.phases == frozenset({Phase.RESPONSE, Phase.TOOL_CALL})
    assert det.name == "nimbus_lite"

    tool_event = AegisEvent.for_tool_call("post", {"body": "tok99abcd11"}, session_id="t")
    assert det.run(tool_event).detector_name == "nimbus_lite"

    # A malformed event (no inspectable surface) must not raise.
    class _Bad:
        session_id = "bad"

        def inspectable_text(self):
            raise RuntimeError("boom")

    out = det.run(_Bad())
    assert out.verdict is Verdict.SKIPPED
