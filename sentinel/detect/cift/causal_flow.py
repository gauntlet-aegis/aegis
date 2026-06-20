"""Causal Flow Score: per-layer diagonal-covariance Mahalanobis deviation of readout activations.

Everything here is elementwise (eq. 2 with diagonal covariance) — no matrix inverse, so nothing
touches the MPS-flaky linear-algebra kernels. We fit (mu, var) on benign activations; the CFS for
a layer is the max Mahalanobis deviation over the turn's readout positions; the K layer-scores are
z-scored (against benign CFS stats) into the feature vector the probe consumes.
"""

from __future__ import annotations

import torch

EPS = 1e-6


def mahalanobis_diag(h: torch.Tensor, mu: torch.Tensor, var: torch.Tensor) -> torch.Tensor:
    """Diagonal Mahalanobis distance. h: [..., hidden] -> [...]; mu/var: [hidden]."""
    z = (h - mu) / torch.sqrt(var + EPS)
    return torch.sqrt((z * z).sum(dim=-1))


def causal_flow_scores(
    activations: dict[int, torch.Tensor],
    stats: dict[int, dict[str, torch.Tensor]],
    layers: list[int],
) -> torch.Tensor:
    """Raw per-layer CFS = max Mahalanobis over readout positions. Returns [K] in ``layers`` order."""
    out = []
    for li in layers:
        h = activations[li]  # [n_readout, hidden]
        if h.dim() == 1:
            h = h.unsqueeze(0)
        d = mahalanobis_diag(h.float(), stats[li]["mu"], stats[li]["var"])  # [n_readout]
        out.append(d.max())
    return torch.stack(out)


def normalize_cfs(cfs: torch.Tensor, cfs_norm: dict[str, torch.Tensor]) -> torch.Tensor:
    """Z-score raw CFS by benign per-layer mean/std so layers are on a comparable scale."""
    return (cfs - cfs_norm["mean"]) / (cfs_norm["std"] + EPS)
