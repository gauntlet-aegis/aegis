"""Runtime CIFT detector: activations -> probability of credential-seeking intent.

Loads the fitted benign stats (mu/var + CFS normalization) and the trained probe. The stage
calls ``score(activations)`` and compares to ``threshold``.
"""

from __future__ import annotations

import torch

from sentinel.detect.cift.causal_flow import causal_flow_scores, normalize_cfs
from sentinel.detect.cift.probe import CFTProbe


class CIFTDetector:
    def __init__(self, stats: dict, cfs_norm: dict, probe: CFTProbe, layers: list[int],
                 threshold: float) -> None:
        self.stats = stats
        self.cfs_norm = cfs_norm
        self.probe = probe.eval()
        self.layers = layers
        self.threshold = threshold

    @torch.no_grad()
    def features(self, activations: dict[int, torch.Tensor]) -> torch.Tensor:
        cfs = causal_flow_scores(activations, self.stats, self.layers)
        return normalize_cfs(cfs, self.cfs_norm)

    @torch.no_grad()
    def score(self, activations: dict[int, torch.Tensor]) -> tuple[float, list[float]]:
        z = self.features(activations)
        prob = torch.sigmoid(self.probe(z.unsqueeze(0))).item()
        return prob, z.tolist()

    @classmethod
    def load(cls, stats_path: str, probe_path: str, threshold: float) -> "CIFTDetector | None":
        import os

        if not (os.path.exists(stats_path) and os.path.exists(probe_path)):
            return None
        s = torch.load(stats_path, weights_only=False)
        p = torch.load(probe_path, weights_only=False)
        probe = CFTProbe(k=p["k"])
        probe.load_state_dict(p["state_dict"])
        return cls(s["stats"], s["cfs_norm"], probe, s["layers"], threshold)
