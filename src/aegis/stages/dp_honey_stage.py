from __future__ import annotations

import time
from dataclasses import dataclass

from aegis.canaries.ledger import HoneytokenLedger, inject_honeytokens
from aegis.core.contracts import (
    Action,
    CapabilityStatus,
    DetectorComponent,
    DetectorResult,
    JsonValue,
    Message,
    NormalizedTurn,
    SensitiveSpan,
)
from aegis.core.orchestrator import ModelResponse
from aegis.detectors.canary import CanaryRecord, InMemoryCanaryRegistry
from aegis.stages import StageMetadata
from detect.dp_honey.conformal import ConformalThreshold, is_fuzzy_outlier
from detect.dp_honey.scanner import PlantedHoneytoken, ScannerJsonValue, scan_planted_values

PRE_FORWARD_METADATA = StageMetadata(phase="pre_forward", always_on=True, requires_whitebox=False)
POST_OUTPUT_METADATA = StageMetadata(phase="post_output", always_on=True, requires_whitebox=False)
_TurnKey = tuple[str, str, int]


class DPHoneyStageError(ValueError):
    """Raised when the DP-HONEY stage is configured incorrectly."""


@dataclass(frozen=True)
class DPHoneyInjectionResult:
    """DP-HONEY injection output split into model-forward and audit-safe views."""

    model_messages: tuple[Message, ...]
    audit_messages: tuple[Message, ...]
    sensitive_spans: tuple[SensitiveSpan, ...]
    canary_records: tuple[CanaryRecord, ...]

    def canary_registry(self) -> InMemoryCanaryRegistry:
        return InMemoryCanaryRegistry(records=self.canary_records)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "audit_messages": [message.to_dict() for message in self.audit_messages],
            "model_message_count": len(self.model_messages),
            "sensitive_spans": [span.to_dict() for span in self.sensitive_spans],
            "canary_records": [_canary_record_summary(record) for record in self.canary_records],
        }


class DPHoneyStage:
    """Combined DP-HONEY injection and planted-value output scanner."""

    pre_forward_phase = PRE_FORWARD_METADATA.phase
    post_output_phase = POST_OUTPUT_METADATA.phase
    always_on = True
    requires_whitebox = False

    def __init__(
        self,
        detector_name: str = "dp_honey",
        *,
        ledger: HoneytokenLedger | None = None,
        registry: InMemoryCanaryRegistry | None = None,
        fuzzy_threshold: ConformalThreshold | None = None,
    ) -> None:
        if detector_name == "":
            raise DPHoneyStageError("detector_name must not be empty.")
        self.detector_name = detector_name
        self._ledger = ledger
        self._registry = registry
        self._fuzzy_threshold = fuzzy_threshold
        self._model_messages_by_turn: dict[_TurnKey, tuple[Message, ...]] = {}

    def inject(self, messages: tuple[Message, ...], turn_index: int) -> DPHoneyInjectionResult:
        """Plant tokens before forwarding and return an audit-safe message view."""
        if self._ledger is None:
            raise DPHoneyStageError("ledger is required for DP-HONEY injection.")
        injection = inject_honeytokens(messages=messages, ledger=self._ledger, turn_index=turn_index)
        self._registry = injection.canary_registry()
        return DPHoneyInjectionResult(
            model_messages=injection.messages,
            audit_messages=_audit_safe_messages(messages=injection.messages, records=injection.canary_records),
            sensitive_spans=injection.sensitive_spans,
            canary_records=injection.canary_records,
        )

    def annotate(self, turn: NormalizedTurn) -> NormalizedTurn:
        """Inject model-forward messages while keeping the audited turn redacted."""
        injection = self.inject(messages=turn.messages, turn_index=turn.turn_index)
        self._model_messages_by_turn[_turn_key(turn)] = injection.model_messages
        return NormalizedTurn(
            trace_id=turn.trace_id,
            session_id=turn.session_id,
            turn_index=turn.turn_index,
            capability_mode=turn.capability_mode,
            model=turn.model,
            messages=injection.audit_messages,
            tool_calls=turn.tool_calls,
            sensitive_spans=turn.sensitive_spans + injection.sensitive_spans,
            metadata=turn.metadata,
        )

    def model_forward_messages_for(self, turn: NormalizedTurn) -> tuple[Message, ...] | None:
        """Return raw injected messages for model forwarding only."""
        return self._model_messages_by_turn.get(_turn_key(turn))

    def evaluate(self, turn: NormalizedTurn, model_response: ModelResponse | None) -> DetectorResult:
        started_at = time.perf_counter()
        if model_response is None:
            return _result(
                detector_name=self.detector_name,
                score=0.0,
                confidence=1.0,
                action=Action.ALLOW,
                status=CapabilityStatus.DEGRADED,
                reason="model_response_required",
                session_id=turn.session_id,
                evidence={},
                started_at=started_at,
            )
        if self._registry is None:
            return _result(
                detector_name=self.detector_name,
                score=0.0,
                confidence=1.0,
                action=Action.ALLOW,
                status=CapabilityStatus.DEGRADED,
                reason="canary_registry_not_configured",
                session_id=turn.session_id,
                evidence={},
                started_at=started_at,
            )

        scan_result = scan_planted_values(
            text=model_response.output_text,
            honeytokens=_records_to_planted(self._registry.records()),
        )
        if scan_result.exact_found:
            matches: list[JsonValue] = [_scanner_json_to_aegis(match.to_dict()) for match in scan_result.exact_matches]
            return _result(
                detector_name=self.detector_name,
                score=1.0,
                confidence=1.0,
                action=Action.BLOCK,
                status=CapabilityStatus.ACTIVE,
                reason="dp_honey_exact_leak_detected",
                session_id=turn.session_id,
                evidence={
                    "match_count": len(scan_result.exact_matches),
                    "matches": matches,
                    "fuzzy_score": scan_result.fuzzy_score,
                },
                started_at=started_at,
            )

        if self._fuzzy_threshold is not None and is_fuzzy_outlier(scan_result.fuzzy_score, self._fuzzy_threshold):
            matches = [_scanner_json_to_aegis(match.to_dict()) for match in scan_result.fuzzy_matches]
            return _result(
                detector_name=self.detector_name,
                score=scan_result.fuzzy_score,
                confidence=1.0 - self._fuzzy_threshold.alpha,
                action=Action.BLOCK,
                status=CapabilityStatus.ACTIVE,
                reason="dp_honey_fuzzy_leak_detected",
                session_id=turn.session_id,
                evidence={
                    "match_count": len(scan_result.fuzzy_matches),
                    "matches": matches,
                    "fuzzy_score": scan_result.fuzzy_score,
                    "q_hat": self._fuzzy_threshold.q_hat,
                    "alpha": self._fuzzy_threshold.alpha,
                    "calibration_count": self._fuzzy_threshold.calibration_count,
                },
                started_at=started_at,
            )

        return _result(
            detector_name=self.detector_name,
            score=scan_result.fuzzy_score,
            confidence=1.0,
            action=Action.ALLOW,
            status=CapabilityStatus.ACTIVE,
            reason="no_dp_honey_leak_detected",
            session_id=turn.session_id,
            evidence={
                "match_count": 0,
                "matches": [],
                "fuzzy_score": scan_result.fuzzy_score,
            },
            started_at=started_at,
        )


def _records_to_planted(records: tuple[CanaryRecord, ...]) -> tuple[PlantedHoneytoken, ...]:
    return tuple(
        PlantedHoneytoken(
            token_id=record.canary_id,
            value=record.value,
            sha256=record.sha256,
            credential_type=record.credential_type,
            source=record.source,
            metadata=record.metadata,
        )
        for record in records
    )


def _turn_key(turn: NormalizedTurn) -> _TurnKey:
    return turn.trace_id, turn.session_id, turn.turn_index


def _audit_safe_messages(messages: tuple[Message, ...], records: tuple[CanaryRecord, ...]) -> tuple[Message, ...]:
    safe_messages: list[Message] = []
    for message in messages:
        content = message.content
        for record in records:
            content = content.replace(record.value, f"[DP_HONEY:{record.canary_id}]")
        safe_messages.append(Message(role=message.role, content=content))
    return tuple(safe_messages)


def _canary_record_summary(record: CanaryRecord) -> dict[str, JsonValue]:
    return {
        "canary_id": record.canary_id,
        "credential_type": record.credential_type,
        "sha256": record.sha256,
        "source": record.source,
        "metadata": record.metadata,
    }


def _result(
    detector_name: str,
    score: float,
    confidence: float,
    action: Action,
    status: CapabilityStatus,
    reason: str,
    session_id: str,
    evidence: dict[str, JsonValue],
    started_at: float,
) -> DetectorResult:
    merged_evidence: dict[str, JsonValue] = {"reason": reason, "session_id": session_id}
    merged_evidence.update(evidence)
    return DetectorResult(
        detector_name=detector_name,
        component=DetectorComponent.DP_HONEY,
        score=score,
        confidence=confidence,
        recommended_action=action,
        capability_required=None,
        capability_status=status,
        evidence=merged_evidence,
        latency_ms=(time.perf_counter() - started_at) * 1000.0,
    )


def _scanner_json_to_aegis(value: ScannerJsonValue) -> JsonValue:
    if isinstance(value, list):
        return [_scanner_json_to_aegis(item) for item in value]
    if isinstance(value, dict):
        return {key: _scanner_json_to_aegis(item) for key, item in value.items()}
    return value
