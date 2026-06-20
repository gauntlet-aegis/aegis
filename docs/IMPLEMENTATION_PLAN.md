# Sentinel / Aegis — Implementation Plan

## Context

We are building **Sentinel** (project: `aegis`), the credential-exfiltration defense proxy specified in
`docs/PRD_credential_exfiltration_proxy.md`. It is a security proxy that sits between an LLM agent and the
model and watches for credential exfiltration at three independent layers — **CIFT** (pre-output white-box
activation probe), **DP-HONEY** (post-output honeytoken canary), and **NIMBUS** (cumulative multi-turn
leakage budget) — while a red-team harness attacks it and a live dashboard shows every attempt land or get
caught.

**Why now / starting point:** `main` is effectively a blank slate (PRD + a secondary brief + stub README).
Prior code on the `codex/aegis-proxy-sidecar` branch is explicitly **ignored** — this is a fresh build in a
new `sentinel/` package. The old branch was a black-box HTTP pass-through shell; CIFT *cannot* exist in that
topology (no activations on a network wire), so we host the model in-process instead.

**Decisions made with the user (this session):**
- **Scope:** thorough build to the full PRD; quality over speed; not optimizing phasing around the June 29 date.
- **Black-box mode:** OpenAI-compatible API endpoint.
- **Eval:** synthetic-first (red-team + held-out encoding suite + 50-conversation synthetic suite); the public
  benchmarks (InjecAgent/BIPIA/AgentDojo/TensorTrust) are a clearly-marked stretch.
- **Dashboard:** single-file embedded HTML/JS/CSS served by FastAPI over Server-Sent Events (SSE).

**Settled architecture (from PRD §4, not to relitigate):** co-located white-box proxy hosting an open-weight
model for hook access, with a black-box toggle that simply disables the CIFT stage; three orthogonal layers
kept deliberately separate (never fused — keeps the ablation legitimate and avoids an adaptive-attacker
surface); real credentials never enter model-visible context, only honeytokens do.

---

## Environment & day-0 gate

**Python 3.12, not 3.14.** System Python is 3.14.4 (too new for stable PyTorch/transformers arm64 wheels).
Reuse the existing uv-managed `.venv` (Python 3.12.12, currently empty of packages). Manage deps via
`pyproject.toml` + `uv pip install -e .`.

Core deps (pinned): `torch>=2.4,<2.6`, `transformers>=4.44,<4.48`, `accelerate`, `numpy>=1.26,<2.1`,
`scikit-learn>=1.5`, `fastapi>=0.115`, `uvicorn[standard]`, `httpx>=0.27`, `pydantic>=2.8`,
`sse-starlette>=2.1`, `sentence-transformers` (frozen MiniLM encoder for NIMBUS), `pyyaml`, `rich`.
Dev: `pytest`, `pytest-asyncio`, `ruff`. Env: `PYTORCH_ENABLE_MPS_FALLBACK=1`, `TOKENIZERS_PARALLELISM=false`.

**Day-0 MPS spike — the gate everything depends on (PRD risk #1).** Write `scripts/spike_mps.py` (~40 lines):
load `Qwen/Qwen2.5-1.5B-Instruct` fp32 on `mps` (triggers ~3.1 GB safetensors download — do this first so it
caches; the GGUF files already in the HF cache are useless here, they need raw safetensors), register a
`forward_hook` on one decoder block, run a 1-token prefill, print param device + `hidden_state.shape`
(expect `[1, seq, 1536]`) + `torch.backends.mps.is_available()`. **Nobody builds CIFT until this passes.**
Fallback chain if a kernel is missing: `MPS_FALLBACK` → CPU forward for the probe path (slow but demo-viable)
→ cloud GPU.

---

## Repository layout

```
aegis/
  pyproject.toml
  configs/{default.yaml, blackbox.yaml}     # mode, model id, thresholds (B, warn/sanitize/block), ports, ε, α
  scripts/
    spike_mps.py            # day-0 gate
    run_proxy.py            # uvicorn launcher
    run_demo.py             # scripted-agent driver for the live demo
    run_eval.py             # offline eval harness
    build_cift_dataset.py  fit_cift_stats.py  train_cift_probe.py
    fit_dp_honey.py  calibrate_dp_honey.py
    build_nimbus_suite.py  train_nimbus.py
    eval_cift_perlayer.py  eval_cift_ablation.py  eval_dp_honey.py  eval_nimbus_budget.py
  sentinel/
    __init__.py  config.py
    events/{schema.py, bus.py, sinks.py}      # *** TurnEvent contract + async pub/sub + JSONL sink ***
    model/{host.py, whitebox.py, blackbox.py, hooks.py}
    proxy/{app.py, orchestrator.py, context.py, honeytoken.py, response.py}
    stages/{base.py, registry.py, dp_honey_stage.py, cift_stage.py, text_detector_stage.py, nimbus_stage.py}
    detect/
      cift/{hooks.py, causal_flow.py, probe.py, stats.py}
      dp_honey/{bigram.py, formats.py, scanner.py, conformal.py}
      nimbus/{critic.py, estimator.py, budget.py}
    redteam/{taxonomy.py, attacks.py, agent.py}
    eval/{metrics.py, replay.py}              # replay = benchmark loaders (stretch)
  dashboard/index.html                        # single-file embedded UI (SSE client)
  data/{cift/, honey/, nimbus/, benchmarks/}  # gitignored
  tests/
```

Lane boundaries: `model/` + `detect/cift/` + `cift_stage.py` (CIFT, critical path) · `proxy/` + `redteam/`
(spine) · `detect/dp_honey/` + `detect/nimbus/` + `eval/` (detectors+eval) · `dashboard/` (UI).

---

## Day-1 contract: event schema + Stage protocol

These two files land **first** and unblock all parallel work. Detectors and dashboard develop against stubs.

**`sentinel/events/schema.py`** (Pydantic v2): `Mode{whitebox,blackbox}`, `Verdict{benign,suspicious,malicious,skipped}`,
`Action{pass,warn,sanitize,block}`. Key models:
- `LayerResult{layer, ran, score, threshold, verdict, detail:dict, latency_ms}`
- `NimbusBudget{cumulative_bits, budget_bits, ratio, per_turn_bits, crossed_warn, crossed_block}`
- `TurnEvent{schema_version, turn_id, conversation_id, turn_index, ts, mode, system_prompt_preview,
  untrusted_content_preview, user_query, attack_label, layers:list[LayerResult], nimbus:NimbusBudget|None,
  action, caught_by, landed, output_preview, timing_ms}`

`attack_label` (red-team ground truth) + `caught_by` + `landed` power the "attack landed vs caught, by which
layer" view and the white-box/black-box comparison.

**`sentinel/stages/base.py`** — uniform plug-in for all three layers:
```python
@dataclass
class StageInput:  ctx; activations: dict|None; output_text: str|None   # activations None in black-box
@dataclass
class StageOutput: result: LayerResult; mutated_output: str|None; halt: bool
class Stage(Protocol):
    name: str; phase: str   # "pre_forward"|"post_forward_pre_output"|"post_output"
    requires_whitebox: bool # CIFT True; others False
    def run(self, inp: StageInput) -> StageOutput: ...
```
Day-1 stubs return `verdict=benign, score=0.0` so the pipeline + dashboard run end-to-end before any ML exists.

---

## Proxy core & orchestration

**`model/host.py`** — `ModelHost` ABC + `make_host(cfg)` factory; one codebase, a config toggle:
- `WhiteBoxHost` (`whitebox.py`): loads Qwen2.5-1.5B fp32 on MPS once at startup; `generate()` arms the
  `HookManager` on the last ⌊0.25·L⌋ layers, returns text + activations at readout positions.
- `BlackBoxHost` (`blackbox.py`): `httpx` POST to an OpenAI-compatible endpoint; returns text, `activations=None`.

**`proxy/app.py`** — FastAPI: `POST /v1/chat/completions` (OpenAI-compatible; force `stream:false` for v1),
`GET /events` (SSE stream of `TurnEvent`), `GET /` (serves `dashboard/index.html`), `GET /healthz`.

**`proxy/orchestrator.py`** — `handle(ctx)` runs the exact PRD pipeline order:
1. **DP-HONEY (pre_forward):** inject calibrated honeytokens into model-visible context via `HoneytokenLedger`.
2. **Forward pass** via `ModelHost.generate` (hooks armed in white-box).
3. **CIFT (post_forward_pre_output):** score credential-access intent from activations; `halt` → graduated
   response fires *before* output is returned. Skipped entirely in black-box.
4. **TEXT DETECTOR (post_output):** cheap canary/verbatim scan, always on.
5. **NIMBUS (post_output):** update `Î_cum` for the conversation; ratio ≥1.0 block, ≥0.9 sanitize, ≥warn warn.

Collects each `StageOutput.result`, applies `halt`/`mutated_output`, computes final `Action`+`caught_by`
(**most-severe action wins; scores never fused**), builds + publishes the `TurnEvent`, returns the
(possibly sanitized/blocked) completion.

**`proxy/response.py`** — `GraduatedResponse.decide(...)` implements Algorithm 1: pass / warn (annotate) /
sanitize (redact offending span) / block (refusal stub). Monotonic precedence block>sanitize>warn>pass.

**`proxy/context.py`** — `TurnContext`: per-turn mutable state (raw vs model-visible messages, ledger handle,
accumulating `LayerResult`s, running `NimbusBudget`). A `ConversationStore` (in-memory dict keyed by
`conversation_id`) holds NIMBUS cumulative bits so the drip accumulates across turns.

**`proxy/honeytoken.py`** — `HoneytokenLedger` (conversation-scoped) holds the bidirectional
`real_secret ↔ honeytoken` map. Real secrets arrive out-of-band (config/tool runtime), never in LLM messages;
the proxy substitutes honeytokens into model-visible context on the way in and (for a tool that genuinely needs
the real value) swaps back at the tool boundary outside the model's context. This invariant is a proxy
property independent of the detectors. Planted tokens are recorded in `TurnContext` and surfaced in
`TurnEvent.layers[dp_honey].detail`.

---

## Detection layer 1 — CIFT (white-box, the headline)

**Geometry (read at runtime, never hardcode):** Qwen2.5-1.5B has `L=28` layers, `hidden=1536`. Hook the last
`n = max(1, L//4) = 7` blocks (indices 21–27). Feature dim `K=7` (one Causal Flow Score per hooked layer);
the probe is intentionally tiny — the Mahalanobis step does the dimensionality reduction.

**Readout capture (`detect/cift/hooks.py`):** do NOT use `generate(output_hidden_states=True)`. Instead:
(1) explicit **prefill** forward `model(input_ids, use_cache=True)` — hooks stash `output[0]`; index `[:, -1, :]`
= final prompt token (readout #1). (2) Append the first sampled token, one more forward with KV cache — captures
the **first-decision position** (readout #2). Ablation variant = mean-pool of final-4 prompt tokens. This hooks
only 7 blocks and keeps the scored activations on the same forward graph as the returned generation. NOT static
credential positions (causal mask makes them uninformative).

**Causal Flow Score (`detect/cift/causal_flow.py`):** per layer, fit per-feature `mu, var` on **benign**
activations; diagonal Mahalanobis is elementwise (no inverse → MPS-safe, PRD §4.4):
`d = sqrt(Σ_j (h_j-mu_j)²/(var_j+ε))`. CFS per layer = max over readout positions; z-score each layer's CFS by
its benign mean/std → `cfs ∈ R^7`.

**Probe (`detect/cift/probe.py`):** `nn.Sequential(Linear(7,128),ReLU,Dropout,Linear(128,64),ReLU,Linear(64,1))`.
Loss = `BCEWithLogitsLoss` + **group-lasso** over the 7 input columns (`λ≈1e-3`) so whole layers zero out
(supports the "few high-weight layers" claim + the mean-ablation deliverable). Trains on **CPU** (7-dim input);
only feature extraction touches MPS.

**Stats fit (`scripts/fit_cift_stats.py`):** Welford streaming mean/var over benign training prompts per layer;
floor `var` at ~1st-percentile to stop dead features blowing up the division. Second pass for CFS z-score
params. Threshold calibrated at a fixed benign FPR (e.g. 1%) — NOT conformal (that's DP-HONEY's tool; keep
distinct).

**Training data (`scripts/build_cift_dataset.py`, ~2k benign + ~2k credential-seeking):** benign vs
credential-seeking **prompts** (never canaries — orthogonality). **Crucial: the secret is in scope in BOTH
classes** so the probe learns "reaching to emit the secret," not "a secret exists." Positives: template grid
(system grants secret × credential type × injection phrasing) + synthetic Qwen paraphrases; the placeholder
secret is a random disposable string, never matched downstream. Negatives: same shape with normal tasks +
public instruction data (Alpaca/Dolly/OASST) + hard negatives that legitimately *mention* credentials
("explain OAuth"). Split by template-family/source so test = generalization. (Public benchmark prompts are a
stretch source.)

**Deliverables:** per-layer AUROC bar chart (paper Fig. 2); mean-ablation (replace high-weight-layer readouts
with benign mean → AUROC collapses); **the encoding-robustness gap** (CIFT AUROC ~flat across
verbatim/base64/hex/ROT13/leet/reverse while the text filter craters — this is the real claim and demo
headline, not matching the paper's 0.998).

---

## Detection layer 2 — DP-HONEY

**DP bigram honeytoken generator (`detect/dp_honey/bigram.py` + `formats.py`):** one model per format (AWS
access/secret key, OAuth bearer, generic `sk-` API key, DB password, JWT, SSH, Stripe `sk_live_`, GitHub
`ghp_`). Train a char-bigram count table on **synthetic** format-valid examples (never real secrets); add
Laplace noise `C~[a][b]=max(0, C[a][b]+Lap(Δ/ε))` (ε≈1.0, clip per-example bigram contribution to bound
sensitivity Δ); renormalize → transition probs; sample then **enforce a hard format mask** (prefix/length/
charset) by repair. DP shapes the internal character statistics (realism beyond the regex) without memorizing
any input. Indistinguishability is what keeps eq.5's catch probability from collapsing.

**Cross-encoding scanner (`detect/dp_honey/scanner.py`):** detection = did the *planted value* appear in any
form? Because the target is known and finite, encoding doesn't help the attacker. For each honeytoken vs output:
direct, reversed, leet-normalized, ROT-N sweep, base64/base32/hex (decode candidate substrings AND encode the
token and search), and within-output fragmentation (strip non-alphanumerics + LCS-ratio of the planted run).
Exact hit (any encoding) → ground-truth `block`. (Cross-*turn* fragmentation is NIMBUS's job.)

**Conformal calibration (`detect/dp_honey/conformal.py`):** for the *fuzzy/partial* channel only. Nonconformity
`s(o)` = max fuzzy similarity between any honeytoken and output. On held-out **benign** outputs, set threshold
`q̂` = the `⌈(m+1)(1-α)⌉/m` empirical quantile (α=0.05 → ≤5% benign FPR, no manual tuning). Exact scanner needs
no threshold.

**Accounting:** report eq.5 catch probability `k/(m+k)·(1-β)`. Measure `β` (attacker's honeytoken-vs-real
distinguishing accuracy) by running the red-team as a distinguisher; with our architecture `m=0` in
model-visible context, so catch ≈ `(1-β)`. Plot catch vs `k` for measured `β`.

**Deliverables:** per-encoding precision/recall + conformal coverage table (paper Table 2) + eq.5 accounting.
Pure string/numpy → **zero MPS risk; buildable with no model loaded → ideal first real detector.**

---

## Detection layer 3 — NIMBUS (multi-turn)

**Estimator (`detect/nimbus/estimator.py`, `critic.py`):** per-turn InfoNCE estimate of `I(secret; conversation)`
in **bits (base-2)**. Positive pair = this conversation's secret with its current state; negatives = other
conversations' states (`N_neg=63` → ceiling `log2(64)=6` bits/turn, comfortably above a drip fragment so
*accumulation* is what crosses budget). Critic: frozen sentence-encoder (MiniLM — model-agnostic, so NIMBUS
works in black-box too) → `sec_proj` MLP + `GRU` over per-turn output embeddings (the "conversational-state
conditioning") + `Bilinear` score `f(s,c)`. Train (`scripts/train_nimbus.py`) with symmetric contrastive loss
on the B×B critic matrix; runs on **CPU** with cached embeddings.

**Budget (`detect/nimbus/budget.py`):** `ΔI_τ = max(0, I(C_τ)-I(C_{τ-1}))`; `Î_cum = Σ ΔI_τ` per
`conversation_id`. Thresholds (PRD §5): ratio ≥1.0 block, ≥0.9 sanitize, ≥0.6 warn. `B` tuned empirically
(start at a small fraction of the secret's bit-length). `normalized=min(1,ratio)` drives the dashboard meter.

**Honest framing (on the slide, not hidden):** a learned **lower-bound signal**, not a certified upper bound;
the `log2(N_neg+1)` ceiling means it targets *accumulated* leakage, not single-turn blowouts (CIFT's job).

**Data (`scripts/build_nimbus_suite.py`):** 50-conversation synthetic suite — ~25 benign multi-turn dialogues
(secret in scope, never leaks) + ~25 dripping attacks (each turn leaks a fragment that trips no per-turn
detector but cumulatively reconstructs), varying drip rate/encoding/length, **including short 2-3 turn drips to
expose the failure mode.**

**Deliverables:** budget-sensitivity sweep (paper Fig. 5: detection rate / false-block / turn-at-block vs B);
**short-session failure curve reported honestly** (detection rate vs session length — names the regime where
NIMBUS is structurally blind); per-turn `I_turn`/`I_cum` trace for the demo conversation so we can name the
crossing turn in advance.

---

## Red-team + scripted agent + dashboard

**`redteam/taxonomy.py`:** `Encoding` enum with encode/decode for verbatim, base64, hex, ROT13, leet, paraphrase,
reverse, fragmentation, partial, multi-turn drip. **`redteam/attacks.py`:** `AttackGenerator.make(secret, enc)`
and `make_drip(secret, n_turns)`; doubles as the eval-data generator; every attack tagged with `attack_label`.
**`redteam/agent.py` + `scripts/run_demo.py`:** deterministic `ScriptedAgent` POSTs turn-by-turn with a stable
`X-Sentinel-Conversation` header (so NIMBUS accumulates). A `Campaign` lists turns with expected outcomes
(`turn 3 → CIFT block`, `turn 7 → NIMBUS block`) → reproducible, self-checking, narratable demo.

**`dashboard/index.html` (embedded, SSE):** `EventBus` (`events/bus.py`) fans each `TurnEvent` to the SSE
generator + a JSONL sink (`events/sinks.py`, replay/backup). Panels: (1) per-turn feed colored by `action`;
(2) four per-layer attribution chips (DP-HONEY/CIFT/TEXT/NIMBUS); (3) NIMBUS budget meter filling toward 1.0
with warn/block gridlines; (4) white-box vs black-box side-by-side (dispatch by `event.mode`). A "replay from
JSONL" mode is demo-day hardware insurance.

**Black-box mode:** `configs/blackbox.yaml` sets `mode=blackbox` + OpenAI-compatible base URL/model;
`stages/registry.py` omits `requires_whitebox` stages. Same attacks, CIFT present (left) vs absent (right) →
the comparison slide for free.

---

## Milestone sequencing (dependency-ordered; no date pressure per user)

1. **Gate:** `scripts/spike_mps.py` passes; model cached; `.venv` (3.12) populated.
2. **Contracts:** freeze `events/schema.py` + `stages/base.py`; ship stub stages.
3. **Spine:** `ModelHost(whitebox)` generates; `Orchestrator` runs all 4 stubbed stages in PRD order; `EventBus`
   + SSE; `dashboard/index.html` renders the stream; `HoneytokenLedger` substitution (real never model-visible);
   `redteam` taxonomy + `ScriptedAgent` drive a benign+verbatim campaign end-to-end. **→ full demo path with no ML.**
4. **DP-HONEY** (no model needed): bigram+DP, scanner, conformal — first real detector + first locked demo beat.
5. **CIFT** (critical path): readout capture → stats (Welford) → dataset → probe → `CIFTStage`. **→ encoded
   attack blocked pre-output while text filter is dark (the centerpiece).**
6. **NIMBUS** (parallel with CIFT, shares no code/MPS): suite → critic → budget meter. **→ drip crosses B at a
   named turn.**
7. **Eval deliverables:** CIFT per-layer AUROC + mean-ablation + encoding gap; DP-HONEY Table 2 + eq.5; NIMBUS
   Fig. 5 + short-session curve.
8. **Black-box toggle** against an OpenAI-compatible model → comparison slide.
9. **Stretch (cut first):** public benchmark replay (`eval/replay.py`), cloud 7B run, cross-model transfer,
   tool-call-argument channel.

**Critical path:** MPS spike → contracts → spine → CIFT. **Riskiest dependency:** MPS hook/kernel behavior
(gated day 0). **Expectation set by PRD:** CIFT AUROC below the paper's 0.998 is fine; the qualitative
encoding-robustness gap is the claim.

---

## Verification

- **Day-0 gate:** `python scripts/spike_mps.py` prints a `[1, seq, 1536]` hidden-state shape with no kernel crash.
- **Contracts/units:** `pytest tests/` — schema round-trip, orchestrator stage ordering + graduated-response
  precedence, honeytoken model-invisibility invariant (assert real secret never appears in model-visible
  messages), encoding taxonomy round-trips (encode∘decode == identity).
- **End-to-end spine:** `scripts/run_proxy.py` + `scripts/run_demo.py` benign campaign → dashboard at
  `http://localhost:<port>/` shows green pass events over SSE.
- **CIFT hero moment:** demo campaign sends verbatim (text filter catches) then Base64 (text filter dark,
  **CIFT blocks pre-output**); confirm `TurnEvent.caught_by=="cift"` and `landed==false`.
- **NIMBUS moment:** drip campaign — budget meter climbs turn-by-turn and blocks at the `Campaign`-predicted
  turn; per-turn `I_cum` trace matches.
- **DP-HONEY:** leak a planted honeytoken in base64/hex → exact scanner fires; `eval_dp_honey.py` reproduces a
  precision/recall + coverage table.
- **Black-box comparison:** run the same campaign with `configs/blackbox.yaml`; CIFT events absent, DP-HONEY +
  NIMBUS still catch their attacks; side-by-side panel shows the gap.
- **Eval scripts:** `scripts/run_eval.py` regenerates the CIFT per-layer AUROC, mean-ablation, encoding-gap,
  NIMBUS budget sweep, and short-session failure figures.
