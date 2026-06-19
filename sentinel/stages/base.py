"""The uniform plug-in contract every detection layer implements.

CIFT, DP-HONEY, the text detector, and NIMBUS all expose the same ``Stage`` interface so the
orchestrator never knows their internals. Black-box mode simply drops any stage whose
``requires_whitebox`` is True. Day-1 stubs satisfy this protocol and return benign so the
pipeline + dashboard run end-to-end before any ML exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import torch

from sentinel.events.schema import LayerResult

if TYPE_CHECKING:
    from sentinel.proxy.context import TurnContext


class Phase(str, Enum):
    """When in the per-turn pipeline a stage runs (PRD §5 ordering)."""

    PRE_FORWARD = "pre_forward"  # DP-HONEY injection
    POST_FORWARD_PRE_OUTPUT = "post_forward_pre_output"  # CIFT (acts before tokens are returned)
    POST_OUTPUT = "post_output"  # text detector, NIMBUS


@dataclass
class StageInput:
    """Everything a stage may need for one turn."""

    ctx: "TurnContext"
    activations: dict[int, torch.Tensor] | None = None  # layer_idx -> readout states; None in black-box
    output_text: str | None = None  # set only at POST_OUTPUT


@dataclass
class StageOutput:
    """What a stage returns to the orchestrator."""

    result: LayerResult  # appended to TurnEvent.layers
    mutated_output: str | None = None  # set by a SANITIZE stage to rewrite the output
    halt: bool = False  # True => orchestrator stops running further stages (abort/block)


@runtime_checkable
class Stage(Protocol):
    name: str
    phase: Phase
    requires_whitebox: bool  # CIFT True; everything else False

    def run(self, inp: StageInput) -> StageOutput: ...
