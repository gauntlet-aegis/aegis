from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from aegis.core.contracts import Action, CapabilityStatus, DetectorComponent, DetectorResult, JsonValue, NormalizedTurn
from aegis.core.orchestrator import ModelResponse
from aegis.detectors.canary import CanaryRecord, InMemoryCanaryRegistry


class NimbusDetectorError(ValueError):
    """Raised when NIMBUS detector configuration or state is invalid."""


@dataclass(frozen=True)
class LeakageEstimate:
    leakage_bits: float
    overlap_ratio: float
    matched_ngram_count: int
    total_ngram_count: int


class LeakageEstimator(Protocol):
    def estimate(self, protected_value: str, output_text: str) -> LeakageEstimate:
        """Estimate marginal leakage for one protected value and one output."""


class CharNGramLeakageEstimator:
    def __init__(self, ngram_lengths: tuple[int, ...], max_bits_per_turn: float) -> None:
        if len(ngram_lengths) == 0:
            raise NimbusDetectorError("ngram_lengths must not be empty.")
        for ngram_length in ngram_lengths:
            if ngram_length <= 0:
                raise NimbusDetectorError("ngram_lengths must contain only positive integers.")
        if max_bits_per_turn <= 0.0:
            raise NimbusDetectorError("max_bits_per_turn must be positive.")
        self._ngram_lengths = ngram_lengths
        self._max_bits_per_turn = max_bits_per_turn

    def estimate(self, protected_value: str, output_text: str) -> LeakageEstimate:
        protected_ngrams = _character_ngrams(value=protected_value, ngram_lengths=self._ngram_lengths)
        if len(protected_ngrams) == 0:
            return LeakageEstimate(
                leakage_bits=0.0,
                overlap_ratio=0.0,
                matched_ngram_count=0,
                total_ngram_count=0,
            )

        output_ngrams = _character_ngrams(value=output_text, ngram_lengths=self._ngram_lengths)
        matched_ngram_count = len(protected_ngrams.intersection(output_ngrams))
        total_ngram_count = len(protected_ngrams)
        overlap_ratio = matched_ngram_count / total_ngram_count
        leakage_bits = min(self._max_bits_per_turn, overlap_ratio * self._max_bits_per_turn)
        return LeakageEstimate(
            leakage_bits=leakage_bits,
            overlap_ratio=overlap_ratio,
            matched_ngram_count=matched_ngram_count,
            total_ngram_count=total_ngram_count,
        )


class InMemoryNimbusSessionStore:
    def __init__(self) -> None:
        self._bits_by_session_canary: dict[tuple[str, str], float] = {}

    def add_leakage_bits(self, session_id: str, canary_id: str, leakage_bits: float) -> float:
        _validate_session_key(session_id=session_id, canary_id=canary_id)
        if leakage_bits < 0.0:
            raise NimbusDetectorError("leakage_bits must be non-negative.")
        key = (session_id, canary_id)
        cumulative_bits = self._bits_by_session_canary.get(key, 0.0) + leakage_bits
        self._bits_by_session_canary[key] = cumulative_bits
        return cumulative_bits

    def cumulative_bits(self, session_id: str, canary_id: str) -> float:
        _validate_session_key(session_id=session_id, canary_id=canary_id)
        return self._bits_by_session_canary.get((session_id, canary_id), 0.0)


@dataclass(frozen=True)
class _NimbusCanaryEvaluation:
    record: CanaryRecord
    estimate: LeakageEstimate
    cumulative_bits: float
    budget_ratio: float
    recommended_action: Action


class NimbusLeakageDetector:
    def __init__(
        self,
        detector_name: str,
        registry: InMemoryCanaryRegistry,
        session_store: InMemoryNimbusSessionStore,
        estimator: LeakageEstimator,
        budget_bits: float,
        warn_ratio: float,
        sanitize_ratio: float,
        block_ratio: float,
    ) -> None:
        if detector_name == "":
            raise NimbusDetectorError("detector_name must not be empty.")
        if budget_bits <= 0.0:
            raise NimbusDetectorError("budget_bits must be positive.")
        _validate_thresholds(warn_ratio=warn_ratio, sanitize_ratio=sanitize_ratio, block_ratio=block_ratio)
        self.detector_name = detector_name
        self._registry = registry
        self._session_store = session_store
        self._estimator = estimator
        self._budget_bits = budget_bits
        self._warn_ratio = warn_ratio
        self._sanitize_ratio = sanitize_ratio
        self._block_ratio = block_ratio

    def evaluate(self, turn: NormalizedTurn, model_response: ModelResponse | None) -> DetectorResult:
        started_at = time.perf_counter()
        if model_response is None:
            return self._result(
                turn=turn,
                score=0.0,
                recommended_action=Action.ALLOW,
                capability_status=CapabilityStatus.DEGRADED,
                evidence={
                    "reason": "model_response_required",
                    "session_id": turn.session_id,
                },
                started_at=started_at,
            )

        records = self._registry.records()
        if len(records) == 0:
            return self._result(
                turn=turn,
                score=0.0,
                recommended_action=Action.ALLOW,
                capability_status=CapabilityStatus.DEGRADED,
                evidence={
                    "reason": "canary_registry_empty",
                    "session_id": turn.session_id,
                    "tracked_canary_count": 0,
                },
                started_at=started_at,
            )

        evaluations = tuple(
            self._evaluate_record(turn=turn, model_response=model_response, record=record) for record in records
        )
        selected_evaluation = max(evaluations, key=_evaluation_rank)
        return self._result(
            turn=turn,
            score=selected_evaluation.budget_ratio,
            recommended_action=selected_evaluation.recommended_action,
            capability_status=CapabilityStatus.ACTIVE,
            evidence=self._evidence(turn=turn, evaluation=selected_evaluation, tracked_canary_count=len(records)),
            started_at=started_at,
        )

    def _evaluate_record(
        self,
        turn: NormalizedTurn,
        model_response: ModelResponse,
        record: CanaryRecord,
    ) -> _NimbusCanaryEvaluation:
        estimate = self._estimator.estimate(protected_value=record.value, output_text=model_response.output_text)
        if estimate.leakage_bits < 0.0:
            raise NimbusDetectorError("estimator returned negative leakage_bits.")
        cumulative_bits = self._session_store.add_leakage_bits(
            session_id=turn.session_id,
            canary_id=record.canary_id,
            leakage_bits=estimate.leakage_bits,
        )
        budget_ratio = min(1.0, cumulative_bits / self._budget_bits)
        recommended_action = _action_for_ratio(
            budget_ratio=budget_ratio,
            warn_ratio=self._warn_ratio,
            sanitize_ratio=self._sanitize_ratio,
            block_ratio=self._block_ratio,
        )
        return _NimbusCanaryEvaluation(
            record=record,
            estimate=estimate,
            cumulative_bits=cumulative_bits,
            budget_ratio=budget_ratio,
            recommended_action=recommended_action,
        )

    def _evidence(
        self,
        turn: NormalizedTurn,
        evaluation: _NimbusCanaryEvaluation,
        tracked_canary_count: int,
    ) -> dict[str, JsonValue]:
        return {
            "reason": _reason_for_action(evaluation.recommended_action),
            "session_id": turn.session_id,
            "canary_id": evaluation.record.canary_id,
            "credential_type": evaluation.record.credential_type,
            "sha256": evaluation.record.sha256,
            "source": evaluation.record.source,
            "turn_leakage_bits": evaluation.estimate.leakage_bits,
            "cumulative_leakage_bits": evaluation.cumulative_bits,
            "budget_bits": self._budget_bits,
            "budget_ratio": evaluation.budget_ratio,
            "warn_ratio": self._warn_ratio,
            "sanitize_ratio": self._sanitize_ratio,
            "block_ratio": self._block_ratio,
            "overlap_ratio": evaluation.estimate.overlap_ratio,
            "matched_ngram_count": evaluation.estimate.matched_ngram_count,
            "total_ngram_count": evaluation.estimate.total_ngram_count,
            "tracked_canary_count": tracked_canary_count,
        }

    def _result(
        self,
        turn: NormalizedTurn,
        score: float,
        recommended_action: Action,
        capability_status: CapabilityStatus,
        evidence: dict[str, JsonValue],
        started_at: float,
    ) -> DetectorResult:
        return DetectorResult(
            detector_name=self.detector_name,
            component=DetectorComponent.NIMBUS,
            score=score,
            confidence=1.0,
            recommended_action=recommended_action,
            capability_required=None,
            capability_status=capability_status,
            evidence=evidence,
            latency_ms=(time.perf_counter() - started_at) * 1000.0,
        )


def _character_ngrams(value: str, ngram_lengths: tuple[int, ...]) -> set[str]:
    ngrams: set[str] = set()
    for ngram_length in ngram_lengths:
        for index in range(len(value) - ngram_length + 1):
            ngrams.add(value[index : index + ngram_length])
    return ngrams


def _validate_session_key(session_id: str, canary_id: str) -> None:
    if session_id == "":
        raise NimbusDetectorError("session_id must not be empty.")
    if canary_id == "":
        raise NimbusDetectorError("canary_id must not be empty.")


def _validate_thresholds(warn_ratio: float, sanitize_ratio: float, block_ratio: float) -> None:
    for field_name, value in (
        ("warn_ratio", warn_ratio),
        ("sanitize_ratio", sanitize_ratio),
        ("block_ratio", block_ratio),
    ):
        if value < 0.0 or value > 1.0:
            raise NimbusDetectorError(f"{field_name} must be in [0.0, 1.0].")
    if warn_ratio > sanitize_ratio or sanitize_ratio > block_ratio:
        raise NimbusDetectorError("thresholds must satisfy warn_ratio <= sanitize_ratio <= block_ratio.")


def _action_for_ratio(budget_ratio: float, warn_ratio: float, sanitize_ratio: float, block_ratio: float) -> Action:
    if budget_ratio >= block_ratio:
        return Action.BLOCK
    if budget_ratio >= sanitize_ratio:
        return Action.SANITIZE
    if budget_ratio >= warn_ratio:
        return Action.WARN
    return Action.ALLOW


def _reason_for_action(action: Action) -> str:
    reasons: dict[Action, str] = {
        Action.ALLOW: "cumulative_leakage_within_budget",
        Action.WARN: "cumulative_leakage_warn_budget_crossed",
        Action.SANITIZE: "cumulative_leakage_sanitize_budget_crossed",
        Action.BLOCK: "cumulative_leakage_block_budget_crossed",
        Action.ESCALATE: "cumulative_leakage_escalate_budget_crossed",
    }
    return reasons[action]


def _evaluation_rank(evaluation: _NimbusCanaryEvaluation) -> tuple[int, float, float]:
    action_rank: dict[Action, int] = {
        Action.ALLOW: 0,
        Action.WARN: 1,
        Action.SANITIZE: 2,
        Action.BLOCK: 3,
        Action.ESCALATE: 4,
    }
    return (
        action_rank[evaluation.recommended_action],
        evaluation.budget_ratio,
        evaluation.estimate.leakage_bits,
    )
