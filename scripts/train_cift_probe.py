"""Train the CIFT probe on cached CFS features; calibrate threshold; report AUROC.

  .venv/bin/python scripts/train_cift_probe.py

Deliverables printed/saved: overall test AUROC, per-layer AUROC (paper Fig. 2), the group-lasso
layer weights (which layers carry the signal), and a threshold calibrated at a fixed benign FPR.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch
from sklearn.metrics import roc_auc_score

from sentinel.config import load_settings
from sentinel.detect.cift.probe import CFTProbe


def _auroc(y, s) -> float:
    y = y.numpy() if hasattr(y, "numpy") else y
    s = s.detach().numpy() if hasattr(s, "detach") else s
    if len(set(y.tolist())) < 2:
        return float("nan")
    return float(roc_auc_score(y, s))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default="data/cift/features.pt")
    ap.add_argument("--epochs", type=int, default=300)
    ap.add_argument("--lam", type=float, default=1e-3)
    ap.add_argument("--fpr", type=float, default=0.01)
    args = ap.parse_args()

    s = load_settings()
    d = torch.load(args.features, weights_only=False)
    X, y, is_test, raw, layers = d["features"], d["labels"], d["is_test"], d["raw_cfs"], d["layers"]
    Xtr, ytr = X[~is_test], y[~is_test].float()
    Xte, yte = X[is_test], y[is_test]

    torch.manual_seed(0)
    probe = CFTProbe(k=X.shape[1])
    opt = torch.optim.Adam(probe.parameters(), lr=1e-3)
    bce = torch.nn.BCEWithLogitsLoss()
    for ep in range(args.epochs):
        probe.train()
        opt.zero_grad()
        loss = bce(probe(Xtr), ytr) + args.lam * probe.group_lasso()
        loss.backward()
        opt.step()

    probe.eval()
    with torch.no_grad():
        s_te = torch.sigmoid(probe(Xte))
        s_tr_benign = torch.sigmoid(probe(Xtr[ytr == 0]))
    auroc = _auroc(yte, s_te)

    # Per-layer AUROC on the test set (each raw CFS column alone).
    per_layer = {int(layers[k]): _auroc(yte, raw[is_test][:, k]) for k in range(len(layers))}

    # Threshold at a fixed benign FPR (on train benign).
    q = torch.quantile(s_tr_benign, 1 - args.fpr).item() if len(s_tr_benign) else 0.5

    Path("data/cift").mkdir(parents=True, exist_ok=True)
    torch.save({"k": X.shape[1], "state_dict": probe.state_dict()}, s.cift.probe_path)
    Path("data/cift/threshold.json").write_text(json.dumps({"threshold": q, "fpr": args.fpr}))

    weights = torch.linalg.vector_norm(probe.net[0].weight.detach(), dim=0)
    print(f"probe test AUROC = {auroc:.3f}   threshold(@{args.fpr:.0%} FPR) = {q:.3f}")
    print("per-layer AUROC:", {li: round(v, 3) for li, v in per_layer.items()})
    print("group-lasso layer weights:",
          {int(layers[i]): round(float(weights[i]), 3) for i in range(len(layers))})
    print(f"saved probe -> {s.cift.probe_path}")


if __name__ == "__main__":
    main()
