"""Build the CIFT prompt dataset (benign vs credential-seeking) and write JSONL.

  .venv/bin/python scripts/build_cift_dataset.py --n-per-class 400
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.detect.cift.dataset import build_dataset


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-per-class", type=int, default=400)
    ap.add_argument("--out", default="data/cift/dataset.jsonl")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    records = build_dataset(args.n_per_class, seed=args.seed)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    pos = sum(r["label"] for r in records)
    print(f"wrote {len(records)} records ({pos} pos / {len(records)-pos} neg) -> {args.out}")


if __name__ == "__main__":
    main()
