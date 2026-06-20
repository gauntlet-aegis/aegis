# DP-HONEY generator

Synthetic, **shape-only** honeytoken generator for the Aegis capstone's
credential-leak detection layer. It produces format-compatible decoys — strings
that *look like* AWS keys, JWTs, GitHub tokens, and so on — using a declarative
grammar plus a differential-privacy-noised character bigram model.

> ⚠️ **Safety boundary.** Every value this package emits is **synthetic** and
> **shape-only**. Outputs are **never** provider-valid, signed, decryptable,
> authenticated, or usable credentials. Do **not** treat any output as a real
> secret, and **never** train this package on real credentials. The example
> tokens in this README are illustrative and non-functional.

---

## What this is (and is not)

This package is **only** the *generator* slice of DP-HONEY. It builds decoys and
the model artifacts/metrics around them. It is intentionally small and auditable.

### Out of scope

These belong to other teammates / future work and are **not** implemented here:

- Scanner implementation and cross-encoding detection
- Conformal calibration
- Eq.5 catch-probability **accounting**
- Runtime **gateway** integration
- **Tool-call** scanning
- Provider-valid credential generation
- Real secret corpus ingestion

---

## Install

Requires **Python ≥ 3.11** and **NumPy**.

```bash
# from the repository root
pip install -e .            # runtime (numpy)
pip install -e ".[dev]"     # + pytest for the test suite
```

You can also run everything without installing, straight from the repo root,
because the package is import- and `-m`-runnable in place.

---

## Quickstart (CLI)

Run as a module: `python -m detect.dp_honey <command>` (or `dp-honey <command>`
after `pip install`). All token-producing commands print a synthetic/non-functional
banner to **stderr**, so piping stdout stays clean.

```bash
# 1. Discover the registered shape-only formats
python -m detect.dp_honey list-formats

# 2. Preview the synthetic training corpus for a format
python -m detect.dp_honey preview-corpus --format github-ghp --count 3 --seed 0

# 3. Generate decoys directly (trains a model on the fly, then samples)
python -m detect.dp_honey generate --format aws-access-key-id --count 2 --seed 1
#   AKIA7X3K9Q0EXAMPLE00     (illustrative; output is synthetic & random)
#   AKIA2M8VJ5R1EXAMPLE00

# 4. Train a reusable model artifact (refuses overwrite without --force)
python -m detect.dp_honey train --format github-ghp --out models/ghp.json \
    --epsilon 1.0 --clip 1.0 --corpus-size 200 --seed 7

# 5. Generate from a saved artifact (no retraining)
python -m detect.dp_honey generate --model models/ghp.json --count 5 --seed 1

# 6. Inspect an artifact's metadata + snapshot/hash status (lenient)
python -m detect.dp_honey inspect-model --model models/ghp.json

# 7. Strictly validate an artifact (exit 0 = valid, nonzero = rejected)
python -m detect.dp_honey validate --model models/ghp.json

# 8. Compute realism / sanity metrics for a batch (JSON)
python -m detect.dp_honey report --format github-ghp --count 100 --seed 1
```

`generate` is capped at 10000 (it streams one token at a time); `report` is
capped at 5000 (metrics require materializing the whole batch). Oversized counts
exit nonzero *before* any generation work begins.

---

## Quickstart (Python API)

```python
from detect.dp_honey import (
    generate_honeytokens, build_model, train_model,
    save_model, load_model, compute_report, list_formats,
)

# Simplest: train on the fly and sample (deterministic in the seeds).
tokens = generate_honeytokens("github-ghp", count=5, sample_seed=1, train_seed=7)

# Build a reusable model, save it, reload it, and sample without retraining.
model = build_model("aws-access-key-id", epsilon=1.0, clip=1.0, corpus_size=200, train_seed=7)
save_model(model, "models/aws.json", force=True)
reloaded = load_model("models/aws.json")
same = generate_honeytokens(model=reloaded, count=5, sample_seed=1)

# Sanity metrics for a batch.
report = compute_report(reloaded.sample(100, seed=1), reloaded)
print(report["validity_rate"], report["char_entropy_bits"])
```

`generate_honeytokens` is the high-level entry point; `train_model` (explicit
corpus), `build_model`, `save_model`, and `load_model` are the lower-level helpers.

---

## Model artifact schema (v1)

Artifacts are transparent, diffable JSON — never pickles — and **fail closed** on
load. The canonical form is reproducible from its training inputs (no timestamp).

| Group | Keys | Purpose |
| ----- | ---- | ------- |
| identity | `schema_version`, `generator` | schema + producing package/version |
| format | `format.slug`, `format.registry_version`, `format.spec_hash`, `format.spec_snapshot` | format identity + drift detection |
| privacy | `privacy.epsilon`, `privacy.clip`, `privacy.corpus_size`, `privacy.train_seed`, `privacy.trained_at` (always `null` in v1), `privacy.mechanism` | DP/training settings |
| alphabet | `alphabet.start_token`, `alphabet.symbols` | variable-character alphabet |
| transitions | `transitions` | normalized `P(next \| prev)` rows |
| safety | `safety.synthetic_only`, `safety.provider_valid`, `safety.note` | provenance + disclaimer |

Loading rejects (with a typed error, before any generation): bad JSON, missing
fields, unknown `schema_version`, **format snapshot/hash drift**, unknown format
slug, invalid alphabet membership, out-of-range privacy metadata, and non-finite /
negative / non-normalized transition probabilities.

> `inspect-model` is **lenient** and always exits 0 — it reports
> `snapshot_status: OK | DRIFT | UNKNOWN_FORMAT` for debugging. Use `validate`
> (which exits nonzero on any problem) as the pass/fail gate in scripts.

---

## Format compatibility matrix

Every format below is **shape-only**: structurally compatible with the named
secret family but never a real, valid, or usable credential.

| Slug | Name | Shape sketch | Provider-valid? |
| ---- | ---- | ------------ | --------------- |
| `aws-access-key-id` | AWS Access Key ID | `AKIA` + 16×[A–Z0–9] | No — shape only |
| `aws-secret-access-key` | AWS Secret Access Key | 40×[A–Za–z0–9/+] | No — shape only |
| `oauth-bearer` | OAuth Bearer Token | 40×[A–Za–z0–9-_] | No — shape only |
| `generic-sk` | Generic sk- API Key | `sk-` + 48×[A–Za–z0–9] | No — shape only |
| `database-password` | Database Password | 20×mixed (≥1 lower/upper/digit) | No — shape only |
| `jwt` | JWT-shaped Token | base64url(20).(40).(43), unsigned | No — shape only |
| `ssh-private-key` | SSH Private Key (marker) | PEM armor + 64×base64url body | No — shape only |
| `stripe-sk-live` | Stripe sk_live_ Secret Key | `sk_live_` + 24×[A–Za–z0–9] | No — shape only |
| `github-ghp` | GitHub Personal Access Token | `ghp_` + 36×[A–Za–z0–9] | No — shape only |

`jwt` produces an **unsigned**, non-verifiable shape; `ssh-private-key` produces a
PEM-armored **marker** with a short synthetic body, not a real or decryptable key.

---

## Determinism & privacy notes

- **Determinism:** the same `(format, epsilon, clip, corpus_size, train_seed)`
  yields the same model, and the same `(model, count, sample_seed)` yields the
  same tokens. Determinism holds for the same code + dependency versions; it is
  not promised across NumPy major versions.
- **Privacy:** training clips each example's per-cell bigram contribution to
  `clip`, then adds `Laplace(clip / epsilon)` noise, projects to ≥0, and
  normalizes. This is a research-grade DP **sketch** over bigram counts
  (`epsilon` is the per-cell budget), not a formally audited end-to-end guarantee.
- **Realism metrics** (`report`) are sanity checks for a synthetic generator —
  **not** proof of indistinguishability from real credentials.

---

## Demo path

A committed, synthetic golden artifact lives at
`tests/fixtures/dp_honey/golden_model.json` (an `aws-access-key-id` model). It
needs no retraining:

```bash
python -m detect.dp_honey inspect-model --model tests/fixtures/dp_honey/golden_model.json
python -m detect.dp_honey validate    --model tests/fixtures/dp_honey/golden_model.json
python -m detect.dp_honey generate    --model tests/fixtures/dp_honey/golden_model.json --count 5 --seed 1
python -m detect.dp_honey report      --model tests/fixtures/dp_honey/golden_model.json --count 100 --seed 1
```

Locally trained artifacts belong under `models/` (gitignored). The fixture under
`tests/fixtures/dp_honey/` is the only model committed to the repo.

---

## Testing

```bash
python -m pytest
```

(CI via GitHub Actions is deferred follow-up work, tracked in `TODOS.md`; local
`pytest` is the documented verification path for now.)
