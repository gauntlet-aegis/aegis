from sentinel.events.schema import (
    Action,
    LayerResult,
    Mode,
    TurnEvent,
    Verdict,
    most_severe,
)


def test_turn_event_round_trip():
    ev = TurnEvent(
        turn_id="t1",
        conversation_id="c1",
        turn_index=0,
        ts="2026-06-19T00:00:00Z",
        mode=Mode.WHITEBOX,
        layers=[LayerResult(layer="cift", ran=True, score=0.9, verdict=Verdict.MALICIOUS,
                            action=Action.BLOCK)],
    )
    d = ev.model_dump(mode="json")
    again = TurnEvent.model_validate(d)
    assert again.layers[0].layer == "cift"
    assert again.action == Action.PASS  # default; not set above


def test_most_severe_precedence():
    assert most_severe([Action.PASS, Action.WARN, Action.BLOCK, Action.SANITIZE]) == Action.BLOCK
    assert most_severe([Action.PASS, Action.WARN]) == Action.WARN
    assert most_severe([]) == Action.PASS
