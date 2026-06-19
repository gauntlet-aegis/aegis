"""Calibrate the DP-HONEY fuzzy-channel threshold via split conformal.

Computes nonconformity scores (best partial honeytoken overlap) on a benign-output corpus and
sets the threshold so benign FPR <= alpha. Self-contained: uses a synthetic benign corpus so it
runs without the model loaded.

  .venv/bin/python scripts/calibrate_dp_honey.py
"""

from __future__ import annotations

import numpy as np

from sentinel.config import load_settings
from sentinel.detect.dp_honey.conformal import calibrate_threshold, empirical_coverage, save_threshold
from sentinel.detect.dp_honey.generator import fit_all, make_generator
from sentinel.detect.dp_honey.scanner import CrossEncodingScanner

_BENIGN = [
    "Your account is active and the latest invoice was emailed to you.",
    "To reset a password, open settings and choose security, then reset.",
    "The refund policy allows cancellation within thirty days of renewal.",
    "Common causes of failed logins include caps lock and expired sessions.",
    "Here is a two sentence summary of today's open support tickets.",
    "Please share your order number so we can locate the shipment.",
    "The API returned a 429 because the rate limit was exceeded briefly.",
    "We migrated the database last night; read replicas are healthy now.",
]


def benign_corpus(n: int, rng: np.random.Generator) -> list[str]:
    out = []
    for _ in range(n):
        k = rng.integers(1, 4)
        out.append(" ".join(rng.choice(_BENIGN, size=k)))
    return out


def main() -> None:
    s = load_settings()
    rng = np.random.default_rng(0)
    models = fit_all(epsilon=s.dp_honey.epsilon)
    gen = make_generator(models)
    tokens = [gen(f) for f in ("openai_key", "aws_access_key", "github_pat", "db_password")]

    scanner = CrossEncodingScanner()
    scores = []
    for text in benign_corpus(400, rng):
        hits = scanner.scan(text, tokens)
        scores.append(max((h.fragment_ratio for h in hits), default=0.0))

    threshold = calibrate_threshold(scores, alpha=s.dp_honey.alpha)
    coverage = empirical_coverage(scores, threshold)
    save_threshold(s.dp_honey.threshold_path, threshold, s.dp_honey.alpha, coverage)
    print(f"benign nonconformity: max={max(scores):.3f} mean={np.mean(scores):.3f}")
    print(f"conformal threshold (alpha={s.dp_honey.alpha}) = {threshold:.3f}  coverage={coverage:.3f}")
    print(f"saved -> {s.dp_honey.threshold_path}")


if __name__ == "__main__":
    main()
