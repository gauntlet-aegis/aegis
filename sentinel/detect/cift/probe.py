"""The CIFT probe: a tiny MLP over the K per-layer Causal Flow Scores.

K -> 128 -> 64 -> 1. Trained BCE + a group-lasso penalty over the K input columns so whole
layers zero out — that supports the "few high-weight layers" claim and the mean-ablation
deliverable. The probe is small enough to train and run on CPU; only feature extraction touches
MPS.
"""

from __future__ import annotations

import torch
from torch import nn


class CFTProbe(nn.Module):
    def __init__(self, k: int = 7) -> None:
        super().__init__()
        self.k = k
        self.net = nn.Sequential(
            nn.Linear(k, 128),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x).squeeze(-1)  # logit

    def group_lasso(self) -> torch.Tensor:
        """Sum of L2 norms of the first-layer weight columns (one group per input feature)."""
        w = self.net[0].weight  # [128, k]
        return torch.linalg.vector_norm(w, dim=0).sum()
