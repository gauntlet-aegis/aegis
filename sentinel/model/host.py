"""Model-host abstraction: one codebase, a config toggle (PRD §4.1).

WhiteBoxHost hosts Qwen in-process for activation hooks; BlackBoxHost forwards to an
OpenAI-compatible API and exposes no activations. The factory picks one from config.mode.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import torch

from sentinel.config import Settings
from sentinel.events.schema import Mode


@dataclass
class GenResult:
    text: str
    activations: dict[int, torch.Tensor] | None = None  # layer_idx -> [n_readout, hidden]
    token_count: int = 0
    latency_ms: float = 0.0
    readout_kinds: list[str] = field(default_factory=list)


class ModelHost(ABC):
    mode: Mode

    @abstractmethod
    def generate(self, messages: list[dict]) -> GenResult: ...

    @property
    def num_hidden_layers(self) -> int:  # pragma: no cover - overridden where meaningful
        return 0


def make_host(settings: Settings) -> ModelHost:
    if settings.mode == Mode.WHITEBOX:
        from sentinel.model.whitebox import WhiteBoxHost

        return WhiteBoxHost(settings)
    from sentinel.model.blackbox import BlackBoxHost

    return BlackBoxHost(settings)
