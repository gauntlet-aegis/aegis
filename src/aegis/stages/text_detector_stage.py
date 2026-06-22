from __future__ import annotations

from aegis.core.contracts import DetectorResult, NormalizedTurn
from aegis.core.orchestrator import ModelResponse
from aegis.detectors.canary import InMemoryCanaryRegistry, TextCanaryDetector
from aegis.stages import StageMetadata

METADATA = StageMetadata(phase="post_output", always_on=True, requires_whitebox=False)


class TextDetectorStage:
    """Cheap post-output canary/verbatim detector used as the encoded-attack baseline."""

    phase = METADATA.phase
    always_on = METADATA.always_on
    requires_whitebox = METADATA.requires_whitebox

    def __init__(self, detector_name: str, registry: InMemoryCanaryRegistry) -> None:
        self.detector_name = detector_name
        self._detector = TextCanaryDetector(detector_name=detector_name, registry=registry)

    def evaluate(self, turn: NormalizedTurn, model_response: ModelResponse | None) -> DetectorResult:
        return self._detector.evaluate(turn=turn, model_response=model_response)
