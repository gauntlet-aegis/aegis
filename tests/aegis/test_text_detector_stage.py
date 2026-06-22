from __future__ import annotations

from aegis.core.contracts import Action, CapabilityMode, Message, ModelInfo, NormalizedTurn
from aegis.core.orchestrator import ModelResponse
from aegis.detectors.canary import CanaryRecord, InMemoryCanaryRegistry, canary_sha256
from aegis.stages.text_detector_stage import METADATA, TextDetectorStage


def _turn() -> NormalizedTurn:
    return NormalizedTurn(
        trace_id="trace-text-stage",
        session_id="session-text-stage",
        turn_index=1,
        capability_mode=CapabilityMode.BLACK_BOX,
        model=ModelInfo(provider="mock", model_id="mock-model", revision=None, selected_device=None),
        messages=(Message(role="user", content="summarize"),),
        tool_calls=(),
        sensitive_spans=(),
        metadata={},
    )


def _registry(value: str) -> InMemoryCanaryRegistry:
    return InMemoryCanaryRegistry(
        records=(
            CanaryRecord(
                canary_id="hny_stage",
                credential_type="api_key",
                value=value,
                sha256=canary_sha256(value),
                source="dp_honey",
                metadata={"scenario": "text_stage"},
            ),
        )
    )


def test_text_detector_stage_declares_baseline_metadata():
    assert METADATA.phase == "post_output"
    assert METADATA.always_on is True
    assert METADATA.requires_whitebox is False
    assert TextDetectorStage.phase == "post_output"
    assert TextDetectorStage.always_on is True
    assert TextDetectorStage.requires_whitebox is False


def test_text_detector_stage_is_deliberately_dark_on_encoded_leaks():
    token = "sk-hny-testCanaryValue123"
    stage = TextDetectorStage(detector_name="text_detector_stage", registry=_registry(token))

    encoded_result = stage.evaluate(
        turn=_turn(),
        model_response=ModelResponse(output_text="Encoded: c2staG55LXRlc3RDYW5hcnlWYWx1ZTEyMw==", metadata={}),
    )
    direct_result = stage.evaluate(
        turn=_turn(),
        model_response=ModelResponse(output_text=f"Direct: {token}", metadata={}),
    )

    assert encoded_result.recommended_action == Action.ALLOW
    assert direct_result.recommended_action == Action.ESCALATE
    assert token not in str(direct_result.to_dict())
