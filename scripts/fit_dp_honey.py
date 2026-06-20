"""Fit the per-format DP-bigram honeytoken models and save them.

  .venv/bin/python scripts/fit_dp_honey.py
"""

from __future__ import annotations

from sentinel.config import load_settings
from sentinel.detect.dp_honey.generator import fit_all, make_generator, save_models


def main() -> None:
    s = load_settings()
    models = fit_all(epsilon=s.dp_honey.epsilon)
    save_models(models, s.dp_honey.models_path)
    print(f"fit {len(models)} DP-bigram models (eps={s.dp_honey.epsilon}) -> {s.dp_honey.models_path}")

    gen = make_generator(models)
    for fmt in ("aws_access_key", "openai_key", "github_pat", "db_password"):
        print(f"  sample {fmt:16s}: {gen(fmt)}")


if __name__ == "__main__":
    main()
