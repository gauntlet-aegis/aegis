"""Calibrate NIMBUS on the synthetic suite: critic, negative bank, temperature, budget.

The critic is cosine over char-n-gram features (f(s,c) = s·c) — the principled InfoNCE critic and
the one that generalizes to arbitrary leaked character strings (a learned diagonal reweighting
overfit the suite's phrasing and lost the signal on raw key fragments). We persist it for
consistency, build the benign-output negative bank, sweep temperature for best drip/benign
separation, and suggest a budget B that lets benign conversations pass while drips cross.

  .venv/bin/python scripts/train_nimbus.py
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from sentinel.config import load_settings
from sentinel.detect.nimbus.critic import LeakageCritic
from sentinel.detect.nimbus.encoder import CharNGramEncoder
from sentinel.detect.nimbus.estimator import NimbusEstimator
from sentinel.detect.nimbus.suite import build_suite


def main() -> None:
    s = load_settings()
    dim = s.nimbus.encoder_dim
    enc = CharNGramEncoder(dim=dim)
    convs = build_suite(50, seed=0)

    # Negative bank = features of benign outputs.
    neg_bank = np.stack([enc.encode(t) for c in convs if c["label"] == "benign" for t in c["turns"]])
    critic = LeakageCritic(dim)  # cosine (w=1)
    critic.save(s.nimbus.critic_path)
    np.save(s.nimbus.neg_bank_path, neg_bank)

    def cumulatives(temp: float):
        est = NimbusEstimator(enc, critic, neg_bank, n_neg=s.nimbus.n_neg, temperature=temp)
        benign_cum, drip_long_cum = [], []
        for c in convs:
            cum = sum(est.infonce_bits(c["secret"], c["conversation_id"], t) for t in c["turns"])
            if c["label"] == "benign":
                benign_cum.append(cum)
            elif len(c["turns"]) > 3:  # "long" drips; short ones are the documented blind spot
                drip_long_cum.append(cum)
        return est, benign_cum, drip_long_cum

    # Pick temperature by cumulative *margin* (median long-drip minus max benign), not per-turn gap.
    candidates = [0.05, 0.08, 0.1, 0.15]
    best = max(candidates,
               key=lambda t: (lambda _e, b, d: np.median(d) - max(b))(*cumulatives(t)))
    est, benign_cum, drip_long_cum = cumulatives(best)

    # Budget so benign max sits at ratio ~0.5 (well within PASS) while drips cross.
    suggested_B = round(2 * max(benign_cum), 2)

    Path(s.nimbus.meta_path).parent.mkdir(parents=True, exist_ok=True)
    Path(s.nimbus.meta_path).write_text(json.dumps(
        {"temperature": best, "encoder_dim": dim, "suggested_budget_bits": suggested_B,
         "ceiling_bits": est.ceiling_bits()}, indent=2))

    print(f"critic=cosine dim={dim}  neg_bank={neg_bank.shape}  best temperature={best}")
    print(f"cumulative bits: benign max={max(benign_cum):.2f}  "
          f"long-drip median={np.median(drip_long_cum):.2f} min={min(drip_long_cum):.2f}")
    print(f"suggested budget B={suggested_B}  (benign max ratio ~0.5)")
    print(f"saved critic -> {s.nimbus.critic_path}, neg_bank -> {s.nimbus.neg_bank_path}, "
          f"meta -> {s.nimbus.meta_path}")


if __name__ == "__main__":
    main()
