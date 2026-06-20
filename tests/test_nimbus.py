import numpy as np

from sentinel.config import Settings
from sentinel.detect.nimbus.critic import LeakageCritic
from sentinel.detect.nimbus.encoder import CharNGramEncoder
from sentinel.detect.nimbus.estimator import NimbusEstimator
from sentinel.events.schema import Action, Mode
from sentinel.proxy.context import ConversationStore, TurnContext
from sentinel.stages.base import StageInput
from sentinel.stages.nimbus_stage import NimbusStage

SECRET = "sk-AbC123XyZ456Def789GhJ"
BENIGN = [
    "Your invoice was emailed to the address on file.",
    "Refunds are processed within thirty days of renewal.",
    "The deployment finished and replicas are healthy.",
]


def _estimator(temp=0.02):
    enc = CharNGramEncoder(dim=512)
    bank = np.stack([enc.encode(b) for b in BENIGN])
    return NimbusEstimator(enc, LeakageCritic(512), bank, n_neg=2, temperature=temp)


def test_encoder_deterministic():
    enc = CharNGramEncoder()
    assert np.allclose(enc.encode("hello world"), enc.encode("hello world"))


def test_leak_scores_higher_than_benign():
    est = _estimator()
    leak = est.infonce_bits(SECRET, "c1", f"the audit slice is {SECRET[3:9]} thanks")
    benign = est.infonce_bits(SECRET, "c1", "your refund will arrive within thirty days")
    assert leak > benign


def test_bits_are_ceiling_bounded():
    est = _estimator()
    b = est.infonce_bits(SECRET, "c1", SECRET)  # full secret leaked
    assert 0.0 <= b <= est.ceiling_bits() + 1e-6


class _FixedEstimator:
    def __init__(self, bits):
        self._bits = bits

    def infonce_bits(self, secret, conversation_id, output_text):
        return self._bits


def test_stage_accumulates_and_blocks_at_budget():
    store = ConversationStore()
    stage = NimbusStage(store, estimator=_FixedEstimator(1.0), budget_bits=2.84)
    # 1.0 bit/turn: ratios 0.35 (pass), 0.70 (warn), 1.06 (block).
    actions, halts = [], []
    for i in range(3):
        ctx = TurnContext(conversation_id="c1", turn_index=i, mode=Mode.WHITEBOX)
        out = stage.run(StageInput(ctx=ctx, output_text="x"))
        actions.append(out.result.action)
        halts.append(out.halt)
    assert actions == [Action.PASS, Action.WARN, Action.BLOCK]
    assert halts == [False, False, True]


def test_stage_budget_resets_per_conversation():
    store = ConversationStore()
    stage = NimbusStage(store, estimator=_FixedEstimator(2.0), budget_bits=2.84)
    ctx_a = TurnContext(conversation_id="a", turn_index=0, mode=Mode.WHITEBOX)
    ctx_b = TurnContext(conversation_id="b", turn_index=0, mode=Mode.WHITEBOX)
    out_a = stage.run(StageInput(ctx=ctx_a, output_text="x"))
    out_b = stage.run(StageInput(ctx=ctx_b, output_text="x"))
    # Each conversation accumulates independently (2.0/2.84 = 0.70 -> warn, not block).
    assert out_a.result.action == Action.WARN
    assert out_b.result.action == Action.WARN
