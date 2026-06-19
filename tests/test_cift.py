import torch

from sentinel.detect.cift.causal_flow import (
    causal_flow_scores,
    mahalanobis_diag,
    normalize_cfs,
)
from sentinel.detect.cift.detector import CIFTDetector
from sentinel.detect.cift.probe import CFTProbe
from sentinel.model.hooks import hooked_layer_indices


def test_hooked_layers_last_quarter():
    assert hooked_layer_indices(28) == [21, 22, 23, 24, 25, 26, 27]
    assert hooked_layer_indices(4) == [3]
    assert hooked_layer_indices(2) == [1]  # max(1, L//4)


def test_mahalanobis_diag_known_value():
    h = torch.tensor([3.0, 4.0])
    mu = torch.zeros(2)
    var = torch.ones(2)
    assert abs(mahalanobis_diag(h, mu, var).item() - 5.0) < 1e-4


def test_causal_flow_scores_shape_and_order():
    layers = [21, 22]
    stats = {li: {"mu": torch.zeros(4), "var": torch.ones(4)} for li in layers}
    acts = {21: torch.zeros(2, 4), 22: torch.ones(2, 4) * 2}
    cfs = causal_flow_scores(acts, stats, layers)
    assert cfs.shape == (2,)
    assert cfs[0].item() == 0.0  # zeros -> zero deviation
    assert cfs[1].item() > 0.0


def test_probe_forward_and_group_lasso():
    probe = CFTProbe(k=7)
    out = probe(torch.randn(5, 7))
    assert out.shape == (5,)
    assert probe.group_lasso().item() >= 0.0


def test_detector_score_returns_probability():
    layers = [21, 22]
    stats = {li: {"mu": torch.zeros(4), "var": torch.ones(4)} for li in layers}
    cfs_norm = {"mean": torch.zeros(2), "std": torch.ones(2)}
    det = CIFTDetector(stats, cfs_norm, CFTProbe(k=2), layers, threshold=0.5)
    acts = {21: torch.randn(2, 4), 22: torch.randn(2, 4)}
    prob, per_layer = det.score(acts)
    assert 0.0 <= prob <= 1.0
    assert len(per_layer) == 2
