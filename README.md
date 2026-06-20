# Sentinel (aegis)

A credential-exfiltration **defense proxy** that sits between an LLM agent and the model and
catches credential leaks at three independent layers, with a live dashboard showing every attack
land or get caught. Built to the spec in [`docs/PRD_credential_exfiltration_proxy.md`](docs/PRD_credential_exfiltration_proxy.md);
implementation plan in [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md); current
build status / handoff in [`docs/STATUS.md`](docs/STATUS.md).

```
 red-team / scripted agent ──▶  SENTINEL PROXY  ──▶  (hosted Qwen2.5-1.5B  |  API model)
                                  1. DP-HONEY inject honeytokens (real secret never seen by model)
                                  2. forward pass  ── CIFT hooks activations @ readout positions
                                  3. CIFT: credential-access intent  → block PRE-OUTPUT
                                  4. text filter (verbatim) + DP-HONEY canary (any encoding)
                                  5. NIMBUS: cumulative multi-turn leakage vs budget
                                       │  per-turn TurnEvent (SSE)
                                       ▼
                                  LIVE DASHBOARD  (http://127.0.0.1:8000/)
```

| Layer | Catches | Mode | Where |
|---|---|---|---|
| **CIFT** | the model *reaching* for a credential, before a token renders | white-box | `sentinel/detect/cift/` |
| **DP-HONEY** | a planted honeytoken leaking in *any* encoding | white + black-box | `sentinel/detect/dp_honey/` |
| **NIMBUS** | a secret leaking *slowly across turns* under the per-turn radar | white + black-box | `sentinel/detect/nimbus/` |

---

## Quick start

**Prereqs:** macOS on Apple Silicon (MPS), [`uv`](https://docs.astral.sh/uv/). First model load downloads ~3.1 GB.

```bash
# 1. Create the venv (Python 3.12 — NOT 3.14; ML wheels need 3.12) and install
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e ".[dev]"

# 2. Day-0 gate: prove MPS + forward hooks work (also warms the model download)
PYTORCH_ENABLE_MPS_FALLBACK=1 .venv/bin/python scripts/spike_mps.py      # expect "GATE: PASS ✅"

# 3. Generate detector artifacts (data/ is gitignored, so regenerate after a fresh clone)
.venv/bin/python scripts/fit_dp_honey.py            # DP-bigram honeytoken models      (fast)
.venv/bin/python scripts/calibrate_dp_honey.py      # conformal fuzzy threshold        (fast)
.venv/bin/python scripts/train_nimbus.py            # NIMBUS critic + neg-bank + budget (fast)
.venv/bin/python scripts/build_cift_dataset.py                            # benign vs cred-seeking prompts
PYTORCH_ENABLE_MPS_FALLBACK=1 .venv/bin/python scripts/fit_cift_stats.py  # model pass (~3-6 min)
.venv/bin/python scripts/train_cift_probe.py        # probe + threshold (prints AUROC)

# 4. Run the proxy + dashboard
PYTORCH_ENABLE_MPS_FALLBACK=1 .venv/bin/python scripts/run_proxy.py
#    open http://127.0.0.1:8000/  in a browser

# 5. In another terminal, drive a campaign through it
.venv/bin/python scripts/run_demo.py --campaign encoding   # the CIFT "encoded attack" hero moment
.venv/bin/python scripts/run_demo.py --campaign drip       # multi-turn drip
.venv/bin/python scripts/run_demo.py --campaign benign     # control

# tests
.venv/bin/python -m pytest -q                              # 25 passing
```

> The proxy runs even with **no artifacts** — each detector degrades to a benign stub if its files
> are missing. Run the step-3 scripts to bring the real detectors online.

---

## Repo layout

```
sentinel/
  events/     schema.py (TurnEvent contract), bus.py (SSE pub/sub), sinks.py (JSONL)
  model/      host.py (ABC + factory), whitebox.py (Qwen+MPS+hooks), blackbox.py (API), hooks.py
  proxy/      app.py (FastAPI), orchestrator.py (pipeline + graduated response),
              context.py, honeytoken.py (ledger + injection), response.py, bootstrap.py (load detectors)
  stages/     base.py (Stage protocol), registry.py, <cift|text|dp_honey|nimbus>_stage.py
  detect/
    cift/     causal_flow.py, stats.py (Welford), probe.py, dataset.py, detector.py
    dp_honey/ formats.py, bigram.py (DP), scanner.py (cross-encoding), conformal.py, generator.py
    nimbus/   encoder.py (char n-gram), critic.py (cosine), estimator.py (InfoNCE bits), suite.py
  redteam/    taxonomy.py (encodings), attacks.py (payloads), agent.py (scripted agent + campaigns)
scripts/      spike_mps, run_proxy, run_demo, build_cift_dataset, fit_cift_stats, train_cift_probe,
              fit_dp_honey, calibrate_dp_honey, train_nimbus
configs/      default.yaml (white-box), blackbox.yaml (API-only)
dashboard/    index.html (single-file SSE UI)
tests/        25 tests (schema, orchestrator, honeytoken, taxonomy, dp_honey, cift, nimbus)
```

---

## Modes

One codebase, a config toggle (`mode: whitebox | blackbox`). White-box hosts Qwen in-process for
CIFT activation hooks; black-box forwards to an OpenAI-compatible API and the registry drops CIFT.

```bash
PYTORCH_ENABLE_MPS_FALLBACK=1 .venv/bin/python scripts/run_proxy.py                          # white-box
OPENAI_API_KEY=sk-... .venv/bin/python scripts/run_proxy.py --config configs/blackbox.yaml   # black-box
```

Runtime env overrides: `SENTINEL_MODE`, `SENTINEL_PORT`, `SENTINEL_DEVICE`. Key MPS flags:
`PYTORCH_ENABLE_MPS_FALLBACK=1`, `TOKENIZERS_PARALLELISM=false`.

---

## How a turn flows

1. **Honeytoken injection** — `{{CREDENTIAL:name:fmt}}` placeholders in the incoming context are
   replaced with DP-generated honeytokens; the real secret (if supplied) is scrubbed. The model
   only ever sees fakes (PRD §4.3).
2. **Forward pass** — white-box captures activations at the readout positions (final-prompt token +
   first-decision token) via forward hooks on the last 7/28 decoder layers.
3. **CIFT** scores credential-access intent and can **block before the output is returned**.
4. **text filter** (verbatim) + **DP-HONEY** (encoding-robust canary) scan the output.
5. **NIMBUS** updates the conversation's cumulative leakage budget (warn/sanitize/block).
6. **Graduated response** takes the most-severe action; a `TurnEvent` is emitted to the dashboard.

See [`docs/STATUS.md`](docs/STATUS.md) for results, calibration values, design decisions, and the
remaining work (M7 eval figures, M8 black-box comparison).
