"""Tests for the policy engine (PDF sections 6.3/6.4): loading, mode behavior, rule matching,
and most-severe combine."""

from __future__ import annotations

from pathlib import Path

from aegis.decision import Action, Verdict
from aegis.detectors.base import DetectorResult
from aegis.policy import Mode, Policy, PolicyEngine, load_policy

DEFAULT_YAML = Path(__file__).resolve().parents[1] / "aegis" / "policy" / "default.yaml"


def _engine(mode: Mode) -> PolicyEngine:
    policy = load_policy(DEFAULT_YAML)
    policy.mode = mode
    return PolicyEngine(policy)


def test_load_default_yaml() -> None:
    policy = load_policy(DEFAULT_YAML)
    assert isinstance(policy, Policy)
    assert policy.mode is Mode.BALANCED
    assert len(policy.rules) >= 1


def test_balanced_blocks_high_secret_score() -> None:
    result = DetectorResult(
        detector_name="secret_pattern",
        score=0.95,
        recommended_action=Action.BLOCK,
        verdict=Verdict.MALICIOUS,
    )
    outcome = _engine(Mode.BALANCED).decide([result])
    assert outcome.action is Action.BLOCK
    assert outcome.reasons  # non-ALLOW must carry a reason


def test_observe_clamps_block_to_warn() -> None:
    result = DetectorResult(
        detector_name="secret_pattern",
        score=0.95,
        recommended_action=Action.BLOCK,
        verdict=Verdict.MALICIOUS,
    )
    outcome = _engine(Mode.OBSERVE).decide([result])
    assert outcome.action is Action.WARN  # never blocks in observe
    assert outcome.reasons


def test_strict_bumps_warn_to_sanitize() -> None:
    # A 0.65 score trips the 0.6 WARN floor but not the 0.85 block; strict bumps WARN -> SANITIZE.
    result = DetectorResult(
        detector_name="secret_pattern",
        score=0.65,
        recommended_action=Action.WARN,
        verdict=Verdict.SUSPICIOUS,
    )
    outcome = _engine(Mode.STRICT).decide([result])
    assert outcome.action is Action.SANITIZE
    assert outcome.reasons


def test_canary_hit_escalates() -> None:
    result = DetectorResult(
        detector_name="honeytoken",
        score=1.0,
        recommended_action=Action.ALLOW,  # rule alone must drive the escalation
        verdict=Verdict.MALICIOUS,
    )
    outcome = _engine(Mode.BALANCED).decide([result])
    assert outcome.action is Action.ESCALATE
    assert any("canary" in r for r in outcome.reasons)


def test_benign_allows_with_no_reasons() -> None:
    benign = [
        DetectorResult(detector_name="secret_pattern", score=0.1, verdict=Verdict.BENIGN),
        DetectorResult(detector_name="encoding", score=0.0, verdict=Verdict.BENIGN),
    ]
    outcome = _engine(Mode.BALANCED).decide(benign)
    assert outcome.action is Action.ALLOW
    assert outcome.reasons == []
    assert outcome.fired_rules == []


def test_most_severe_wins_across_detectors() -> None:
    results = [
        DetectorResult(detector_name="encoding", score=0.65, recommended_action=Action.WARN),
        DetectorResult(detector_name="honeytoken", score=1.0, verdict=Verdict.MALICIOUS),
        DetectorResult(detector_name="secret_pattern", score=0.95, recommended_action=Action.BLOCK),
    ]
    outcome = _engine(Mode.BALANCED).decide(results)
    # WARN (encoding) vs BLOCK (secret) vs ESCALATE (canary) -> ESCALATE is most severe.
    assert outcome.action is Action.ESCALATE
    assert len(outcome.reasons) >= 2


def test_tool_arg_secret_blocks() -> None:
    result = DetectorResult(
        detector_name="tool_call_args",
        score=0.9,
        evidence={"findings": [{"tool": "http_post", "arg": "body", "contains_secret": True}]},
    )
    outcome = _engine(Mode.BALANCED).decide([result])
    assert outcome.action is Action.BLOCK
    assert any("tool_call_args" in r for r in outcome.reasons)


def test_leakage_budget_sanitizes_then_blocks() -> None:
    # The live ledger sets score == ratio; the wildcard score rule must DEFER to the dedicated
    # leakage_budget_threshold so ratio 0.92 sanitizes (graduated) rather than hard-blocking.
    sanitize = DetectorResult(detector_name="nimbus_lite", score=0.92, evidence={"ratio": 0.92})
    assert _engine(Mode.BALANCED).decide([sanitize]).action is Action.SANITIZE
    block = DetectorResult(detector_name="nimbus_lite", score=1.0, evidence={"ratio": 1.0})
    assert _engine(Mode.BALANCED).decide([block]).action is Action.BLOCK


def test_decide_never_raises_on_empty() -> None:
    outcome = _engine(Mode.BALANCED).decide([])
    assert outcome.action is Action.ALLOW
