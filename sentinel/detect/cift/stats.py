"""Streaming (Welford) per-feature mean/variance of benign readout activations, per layer.

Streaming avoids ever materializing the full [N_prompts * n_readout, hidden] activation matrix
and is friendly to MPS allocation. Variance is floored at a low percentile so dead features don't
blow up the elementwise division in the Mahalanobis step.
"""

from __future__ import annotations

import torch


class Welford:
    """Per-feature running mean/M2 for one layer."""

    def __init__(self, dim: int) -> None:
        self.n = 0
        self.mean = torch.zeros(dim, dtype=torch.float64)
        self.m2 = torch.zeros(dim, dtype=torch.float64)

    def update(self, x: torch.Tensor) -> None:
        x = x.double()
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    def finalize(self, var_floor_pct: float = 1.0) -> dict[str, torch.Tensor]:
        var = self.m2 / max(1, self.n - 1)
        floor = torch.quantile(var[var > 0], var_floor_pct / 100.0) if (var > 0).any() else torch.tensor(1e-6)
        var = torch.clamp(var, min=float(floor))
        return {"mu": self.mean.float(), "var": var.float()}


class WelfordSet:
    """A Welford accumulator per hooked layer."""

    def __init__(self, layers: list[int], hidden: int) -> None:
        self.layers = layers
        self._w = {li: Welford(hidden) for li in layers}

    def update(self, activations: dict[int, torch.Tensor]) -> None:
        for li in self.layers:
            h = activations[li]
            if h.dim() == 1:
                h = h.unsqueeze(0)
            for row in h:
                self._w[li].update(row.cpu())

    def finalize(self) -> dict[int, dict[str, torch.Tensor]]:
        return {li: w.finalize() for li, w in self._w.items()}
