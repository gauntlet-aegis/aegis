"""Forward-hook plumbing for white-box activation capture.

The HookManager registers forward hooks on a chosen set of decoder blocks and stashes each
block's hidden-state output for the *current* forward pass. The white-box host reads these
buffers after the prefill (final-prompt-token readout) and after the first decode step
(first-decision readout) — see ``WhiteBoxHost.generate``.
"""

from __future__ import annotations

import torch


def hooked_layer_indices(num_hidden_layers: int) -> list[int]:
    """The last floor(0.25*L) decoder blocks (PRD §6.2). Computed at runtime, never hardcoded."""
    n = max(1, num_hidden_layers // 4)
    return list(range(num_hidden_layers - n, num_hidden_layers))


class HookManager:
    def __init__(self, model, layers: list[int]) -> None:
        self.model = model
        self.layers = layers
        self._buf: dict[int, torch.Tensor] = {}
        self._handles: list = []

    def _make_hook(self, li: int):
        def hook(_module, _inputs, output):
            hs = output[0] if isinstance(output, tuple) else output
            self._buf[li] = hs.detach()

        return hook

    def arm(self) -> None:
        self.disarm()
        for li in self.layers:
            block = self.model.model.layers[li]
            self._handles.append(block.register_forward_hook(self._make_hook(li)))

    def current(self) -> dict[int, torch.Tensor]:
        """Hidden states captured during the most recent forward pass, per hooked layer."""
        return self._buf

    def disarm(self) -> None:
        for h in self._handles:
            h.remove()
        self._handles.clear()
