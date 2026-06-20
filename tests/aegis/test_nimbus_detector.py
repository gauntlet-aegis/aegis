from __future__ import annotations

import unittest

from aegis.audit.memory import InMemoryAuditSink
from aegis.core.contracts import (
    Action,
    CapabilityMode,
    CapabilityStatus,
    DetectorComponent,
    Message,
    ModelInfo,
    NormalizedTurn,
)
from aegis.core.orchestrator import AegisRuntime, ModelResponse, RuntimeRequest
from aegis.detectors.canary import CanaryRecord, InMemoryCanaryRegistry, canary_sha256
from aegis.detectors.nimbus import (
    CharNGramLeakageEstimator,
    InMemoryNimbusSessionStore,
    LeakageEstimate,
    NimbusLeakageDetector,
)
from aegis.policy.engine import SeverityPolicyEngine
from aegis.providers.mock import MockModelProvider


class FixedLeakageEstimator:
    def __init__(self, bits: float) -> None:
        self._bits = bits

    def estimate(self, protected_value: str, output_text: str) -> LeakageEstimate:
        return LeakageEstimate(
            leakage_bits=self._bits,
            overlap_ratio=0.5,
            matched_ngram_count=4,
            total_ngram_count=8,
        )


def _record(value: str, canary_id: str) -> CanaryRecord:
    return CanaryRecord(
        canary_id=canary_id,
        credential_type="openai_key",
        value=value,
        sha256=canary_sha256(value),
        source="dp_honey_lite",
        metadata={"slot_name": "api_key"},
    )


def _request(session_id: str, turn_index: int, output_text: str) -> RuntimeRequest:
    return RuntimeRequest(
        trace_id=f"trace-{session_id}-{turn_index}",
        session_id=session_id,
        turn_index=turn_index,
        capability_mode=CapabilityMode.BLACK_BOX,
        model=ModelInfo(provider="mock", model_id="mock-model", revision=None, selected_device=None),
        messages=(Message(role="user", content="continue"),),
        tool_calls=(),
        sensitive_spans=(),
        metadata={"mock_response": output_text},
    )


def _turn(session_id: str, turn_index: int) -> NormalizedTurn:
    return NormalizedTurn(
        trace_id=f"trace-{session_id}-{turn_index}",
        session_id=session_id,
        turn_index=turn_index,
        capability_mode=CapabilityMode.BLACK_BOX,
        model=ModelInfo(provider="mock", model_id="mock-model", revision=None, selected_device=None),
        messages=(Message(role="user", content="continue"),),
        tool_calls=(),
        sensitive_spans=(),
        metadata={},
    )


def _detector(registry: InMemoryCanaryRegistry, store: InMemoryNimbusSessionStore) -> NimbusLeakageDetector:
    return NimbusLeakageDetector(
        detector_name="nimbus_lite",
        registry=registry,
        session_store=store,
        estimator=FixedLeakageEstimator(bits=1.0),
        budget_bits=3.0,
        warn_ratio=0.5,
        sanitize_ratio=0.8,
        block_ratio=1.0,
    )


class CharNGramLeakageEstimatorTest(unittest.TestCase):
    def test_scores_secret_fragment_above_benign_output(self) -> None:
        secret = "sk-hny-alpha-openai-0001"
        estimator = CharNGramLeakageEstimator(ngram_lengths=(3, 4), max_bits_per_turn=4.0)

        leak = estimator.estimate(
            protected_value=secret,
            output_text=f"The identifier begins with {secret[:12]}.",
        )
        benign = estimator.estimate(
            protected_value=secret,
            output_text="The deployment completed successfully.",
        )

        self.assertGreater(leak.overlap_ratio, benign.overlap_ratio)
        self.assertGreater(leak.leakage_bits, benign.leakage_bits)
        self.assertLessEqual(leak.leakage_bits, 4.0)


class NimbusLeakageDetectorTest(unittest.TestCase):
    def test_missing_model_response_degrades_without_updating_state(self) -> None:
        store = InMemoryNimbusSessionStore()
        registry = InMemoryCanaryRegistry(records=(_record("sk-hny-alpha-openai-0001", "hny_alpha"),))
        detector = _detector(registry=registry, store=store)

        result = detector.evaluate(
            turn=_turn(session_id="session-a", turn_index=0),
            model_response=None,
        )

        self.assertEqual(Action.ALLOW, result.recommended_action)
        self.assertEqual(CapabilityStatus.DEGRADED, result.capability_status)
        self.assertEqual("model_response_required", result.evidence["reason"])
        self.assertEqual(0.0, store.cumulative_bits(session_id="session-a", canary_id="hny_alpha"))

    def test_accumulates_leakage_and_crosses_thresholds(self) -> None:
        store = InMemoryNimbusSessionStore()
        registry = InMemoryCanaryRegistry(records=(_record("sk-hny-alpha-openai-0001", "hny_alpha"),))
        detector = _detector(registry=registry, store=store)

        actions: list[Action] = []
        ratios: list[float] = []
        for turn_index in range(3):
            result = detector.evaluate(
                turn=_turn(session_id="session-a", turn_index=turn_index),
                model_response=ModelResponse(output_text="slice", metadata={}),
            )
            actions.append(result.recommended_action)
            ratios.append(float(result.evidence["budget_ratio"]))

        self.assertEqual([Action.ALLOW, Action.WARN, Action.BLOCK], actions)
        self.assertEqual([1.0 / 3.0, 2.0 / 3.0, 1.0], ratios)

    def test_accumulates_independently_per_session(self) -> None:
        store = InMemoryNimbusSessionStore()
        registry = InMemoryCanaryRegistry(records=(_record("sk-hny-alpha-openai-0001", "hny_alpha"),))
        detector = _detector(registry=registry, store=store)

        first_session = detector.evaluate(
            turn=_turn(session_id="session-a", turn_index=0),
            model_response=ModelResponse(output_text="slice", metadata={}),
        )
        second_session = detector.evaluate(
            turn=_turn(session_id="session-b", turn_index=0),
            model_response=ModelResponse(output_text="slice", metadata={}),
        )

        self.assertEqual(Action.ALLOW, first_session.recommended_action)
        self.assertEqual(Action.ALLOW, second_session.recommended_action)
        self.assertEqual(1.0, store.cumulative_bits(session_id="session-a", canary_id="hny_alpha"))
        self.assertEqual(1.0, store.cumulative_bits(session_id="session-b", canary_id="hny_alpha"))

    def test_detector_evidence_does_not_expose_raw_canary_or_output_text(self) -> None:
        secret = "sk-hny-alpha-openai-0001"
        output_text = f"The first slice is {secret[:8]}."
        store = InMemoryNimbusSessionStore()
        registry = InMemoryCanaryRegistry(records=(_record(secret, "hny_alpha"),))
        detector = _detector(registry=registry, store=store)

        result = detector.evaluate(
            turn=_turn(session_id="session-a", turn_index=0),
            model_response=ModelResponse(output_text=output_text, metadata={}),
        )

        serialized = str(result.to_dict())
        self.assertNotIn(secret, serialized)
        self.assertNotIn(output_text, serialized)
        self.assertEqual("hny_alpha", result.evidence["canary_id"])
        self.assertEqual(canary_sha256(secret), result.evidence["sha256"])

    def test_runtime_applies_nimbus_session_detector_policy_recommendation(self) -> None:
        store = InMemoryNimbusSessionStore()
        registry = InMemoryCanaryRegistry(records=(_record("sk-hny-alpha-openai-0001", "hny_alpha"),))
        runtime = AegisRuntime(
            pre_generation_detectors=(),
            post_generation_detectors=(),
            session_detectors=(_detector(registry=registry, store=store),),
            policy_engine=SeverityPolicyEngine(),
            audit_sink=InMemoryAuditSink(),
            model_provider=MockModelProvider(default_content="slice"),
        )

        runtime.evaluate_turn(_request(session_id="session-a", turn_index=0, output_text="slice"))
        response = runtime.evaluate_turn(_request(session_id="session-a", turn_index=1, output_text="slice"))

        self.assertEqual(Action.WARN, response.policy_decision.final_action)
        self.assertEqual(("nimbus_lite",), response.policy_decision.triggered_detectors)
        self.assertEqual(DetectorComponent.NIMBUS, response.detector_results[0].component)


if __name__ == "__main__":
    unittest.main()
