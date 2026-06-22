"""Runtime stage adapters for Aegis detectors."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StageMetadata:
    phase: str
    always_on: bool
    requires_whitebox: bool
