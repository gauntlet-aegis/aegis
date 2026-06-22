from __future__ import annotations

import base64

import pytest

from aegis.audit.memory import InMemoryAuditSink
from aegis.canaries.ledger import HoneytokenLedger
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
from aegis.policy.engine import SeverityPolicyEngine
from aegis.stages.dp_honey_stage import POST_OUTPUT_METADATA, PRE_FORWARD_METADATA, DPHoneyStage, DPHoneyStageError
from detect.dp_honey.conformal import ConformalThreshold


class EncodingLeakProvider:
    def __init__(self) -> None:
        self.seen_messages: tuple[Message, ...] = ()

    def generate(self, turn: NormalizedTurn) -> ModelResponse:
        self.seen_messages = turn.messages
        token = turn.messages[0].content.split("Use ", 1)[1].rstrip(".")
        encoded = base64.b64encode(token.encode("utf-8")).decode("ascii")
        return ModelResponse(output_text=f"Encoded leak: {encoded}", metadata={})


def _turn(messages: tuple[Message, ...] = (Message(role="user", content="summarize"),)) -> NormalizedTurn:
    return NormalizedTurn(
        trace_id="trace-dp-honey-stage",
        session_id="session-dp-honey-stage",
        turn_index=1,
        capability_mode=CapabilityMode.BLACK_BOX,
        model=ModelInfo(provider="mock", model_id="mock-model", revision=None, selected_device=None),
        messages=messages,
        tool_calls=(),
        sensitive_spans=(),
        metadata={},
    )


def _request(messages: tuple[Message, ...]) -> RuntimeRequest:
    return RuntimeRequest(
        trace_id="trace-dp-honey-stage",
        session_id="session-dp-honey-stage",
        turn_index=1,
        capability_mode=CapabilityMode.BLACK_BOX,
        model=ModelInfo(provider="mock", model_id="mock-model", revision=None, selected_device=None),
        messages=messages,
        tool_calls=(),
        sensitive_spans=(),
        metadata={},
    )


def _ledger() -> HoneytokenLedger:
    return HoneytokenLedger(
        session_id="session-dp-honey-stage",
        generator=lambda slot_name, credential_type: f"sk-hny-{slot_name}-{credential_type}-123",
        source="dp_honey",
    )


def test_dp_honey_stage_declares_pre_and_post_metadata():
    assert PRE_FORWARD_METADATA.phase == "pre_forward"
    assert POST_OUTPUT_METADATA.phase == "post_output"
    assert DPHoneyStage.pre_forward_phase == "pre_forward"
    assert DPHoneyStage.post_output_phase == "post_output"
    assert DPHoneyStage.always_on is True
    assert DPHoneyStage.requires_whitebox is False


def test_dp_honey_stage_injects_and_blocks_encoded_planted_value():
    stage = DPHoneyStage(detector_name="dp_honey_stage", ledger=_ledger())
    injection = stage.inject(
        messages=(Message(role="system", content="Use {{CREDENTIAL:repo_pat:github_pat}}."),),
        turn_index=0,
    )
    token = injection.canary_records[0].value
    encoded = base64.b64encode(token.encode("utf-8")).decode("ascii")

    result = stage.evaluate(
        turn=_turn(messages=injection.audit_messages),
        model_response=ModelResponse(output_text=f"Encoded leak: {encoded}", metadata={}),
    )

    assert result.component == DetectorComponent.DP_HONEY
    assert result.recommended_action == Action.BLOCK
    assert result.evidence["reason"] == "dp_honey_exact_leak_detected"
    assert result.evidence["matches"][0]["channel"] == "base64"
    assert result.evidence["matches"][0]["encoding"] == "base64"
    assert result.evidence["matches"][0]["canary_id"] == injection.canary_records[0].canary_id
    assert token in injection.model_messages[0].content
    assert token not in injection.audit_messages[0].content
    assert token not in str(result.to_dict())
    assert "{{CREDENTIAL" not in str(injection.to_dict())


def test_dp_honey_stage_annotator_feeds_model_without_leaking_audit_turn():
    provider = EncodingLeakProvider()
    stage = DPHoneyStage(detector_name="dp_honey_stage", ledger=_ledger())
    runtime = AegisRuntime(
        turn_annotators=(stage,),
        pre_generation_detectors=(),
        post_generation_detectors=(stage,),
        session_detectors=(),
        policy_engine=SeverityPolicyEngine(),
        audit_sink=InMemoryAuditSink(),
        model_provider=provider,
    )

    response = runtime.evaluate_turn(
        _request(messages=(Message(role="system", content="Use {{CREDENTIAL:repo_pat:github_pat}}."),))
    )
    token = stage._registry.records()[0].value

    assert token in provider.seen_messages[0].content
    assert token not in str(response.audit_event.to_dict())
    assert response.policy_decision.final_action == Action.BLOCK


def test_dp_honey_stage_uses_conformal_threshold_for_fuzzy_channel():
    stage = DPHoneyStage(
        detector_name="dp_honey_stage",
        ledger=_ledger(),
        fuzzy_threshold=ConformalThreshold(alpha=0.2, q_hat=0.2, calibration_count=10, rank=9),
    )
    injection = stage.inject(
        messages=(Message(role="system", content="Use {{CREDENTIAL:repo_pat:github_pat}}."),),
        turn_index=0,
    )
    token = injection.canary_records[0].value
    partial = token[: max(1, len(token) // 2)]

    result = stage.evaluate(
        turn=_turn(messages=injection.audit_messages),
        model_response=ModelResponse(output_text=f"Partial leak: {partial}", metadata={}),
    )

    assert result.recommended_action == Action.BLOCK
    assert result.evidence["reason"] == "dp_honey_fuzzy_leak_detected"
    assert result.evidence["q_hat"] == 0.2
    assert result.evidence["matches"][0]["channel"] == "partial_lcs"
    assert token not in str(result.to_dict())


def test_dp_honey_stage_allows_fuzzy_without_calibrated_outlier():
    stage = DPHoneyStage(
        detector_name="dp_honey_stage",
        ledger=_ledger(),
        fuzzy_threshold=ConformalThreshold(alpha=0.2, q_hat=0.95, calibration_count=10, rank=9),
    )
    injection = stage.inject(
        messages=(Message(role="system", content="Use {{CREDENTIAL:repo_pat:github_pat}}."),),
        turn_index=0,
    )
    token = injection.canary_records[0].value

    result = stage.evaluate(
        turn=_turn(messages=injection.audit_messages),
        model_response=ModelResponse(output_text=f"Partial leak: {token[:8]}", metadata={}),
    )

    assert result.recommended_action == Action.ALLOW
    assert result.evidence["reason"] == "no_dp_honey_leak_detected"
    assert result.evidence["match_count"] == 0


def test_dp_honey_stage_reports_degraded_when_unconfigured_or_pre_output():
    stage = DPHoneyStage(detector_name="dp_honey_stage")

    missing_response = stage.evaluate(turn=_turn(), model_response=None)
    missing_registry = stage.evaluate(turn=_turn(), model_response=ModelResponse(output_text="hello", metadata={}))

    assert missing_response.capability_status == CapabilityStatus.DEGRADED
    assert missing_response.evidence["reason"] == "model_response_required"
    assert missing_registry.capability_status == CapabilityStatus.DEGRADED
    assert missing_registry.evidence["reason"] == "canary_registry_not_configured"


def test_dp_honey_stage_requires_ledger_for_injection():
    stage = DPHoneyStage(detector_name="dp_honey_stage")

    with pytest.raises(DPHoneyStageError, match="ledger"):
        stage.inject(messages=(Message(role="user", content="hello"),), turn_index=0)
