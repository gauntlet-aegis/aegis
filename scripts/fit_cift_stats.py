"""Extract readout activations, fit benign diagonal-covariance stats, cache CFS features.

One model pass over the whole dataset (cached in RAM):
  1. Welford mu/var per hooked layer on benign TRAIN activations.
  2. raw Causal Flow Score per prompt using those stats.
  3. CFS normalization (mean/std) from benign TRAIN CFS.
Saves stats.pt (mu/var + cfs_norm + layers) and features.pt (z-scored features + labels + split).

  PYTORCH_ENABLE_MPS_FALLBACK=1 .venv/bin/python scripts/fit_cift_stats.py
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch

from sentinel.config import load_settings
from sentinel.detect.cift.causal_flow import causal_flow_scores, normalize_cfs
from sentinel.detect.cift.stats import WelfordSet
from sentinel.model.whitebox import WhiteBoxHost


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="data/cift/dataset.jsonl")
    ap.add_argument("--test-frac", type=float, default=0.2)
    args = ap.parse_args()

    s = load_settings()
    records = [json.loads(l) for l in open(args.dataset)]
    host = WhiteBoxHost(s)
    layers = host.hooked
    hidden = host.model.config.hidden_size
    print(f"model L={host.num_hidden_layers} hidden={hidden} hooked={layers}")

    # One extraction pass.
    acts: list[dict[int, torch.Tensor]] = []
    for i, r in enumerate(records):
        acts.append(host.readout(r["messages"]))
        if (i + 1) % 100 == 0:
            print(f"  extracted {i + 1}/{len(records)}")

    n = len(records)
    # Deterministic stride split (records were already shuffled at build time).
    stride = max(2, round(1 / args.test_frac)) if args.test_frac > 0 else n + 1
    is_test = torch.tensor([(i % stride) == 0 for i in range(n)])
    labels = torch.tensor([r["label"] for r in records])

    # 1. Welford on benign TRAIN.
    ws = WelfordSet(layers, hidden)
    for i in range(n):
        if labels[i] == 0 and not is_test[i]:
            ws.update(acts[i])
    stats = ws.finalize()

    # 2. raw CFS per prompt.
    raw = torch.stack([causal_flow_scores(acts[i], stats, layers) for i in range(n)])  # [N,K]

    # 3. CFS normalization from benign TRAIN.
    mask = (labels == 0) & (~is_test)
    cfs_norm = {"mean": raw[mask].mean(0), "std": raw[mask].std(0)}
    feats = torch.stack([normalize_cfs(raw[i], cfs_norm) for i in range(n)])  # [N,K]

    Path("data/cift").mkdir(parents=True, exist_ok=True)
    torch.save({"layers": layers, "hidden": hidden, "stats": stats, "cfs_norm": cfs_norm},
               s.cift.stats_path)
    torch.save({"features": feats, "raw_cfs": raw, "labels": labels, "is_test": is_test,
                "families": [r["family"] for r in records], "layers": layers},
               "data/cift/features.pt")
    print(f"saved stats -> {s.cift.stats_path} and features -> data/cift/features.pt")
    print(f"train benign={int(mask.sum())}  test={int(is_test.sum())}")


if __name__ == "__main__":
    main()
