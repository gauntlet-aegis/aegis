# Sentinel — Build Status & Handoff

_Last updated: 2026-06-19. Branch: `plan/sentinel-implementation`._

This is the working log + handoff for the Sentinel build. It records what's done, the key results,
the non-obvious decisions made along the way, and exactly how to pick up **M7 (eval deliverables)**
and **M8 (black-box comparison)**. See the [README](../README.md) to run things and
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for the full plan.

## Snapshot

| Milestone | Status | Commit |
|---|---|---|
| M1 Environment + day-0 MPS gate | ✅ done | `cd08656` |
| M2 Day-1 contracts (event schema + Stage protocol) | ✅ done | `cd08656` |
| M3 End-to-end spine with stubs | ✅ done | `cd08656` |
| M4 DP-HONEY layer | ✅ done | `a19599f` |
| M5 CIFT layer (headline) | ✅ done | `00327e0` |
| M6 NIMBUS layer | ✅ done | `8d264c2` |
| **M7 Eval deliverables** | ⬜ **not started** | — |
| **M8 Black-box toggle + comparison** | ⬜ **architecture ready, not run** | — |

25 tests passing (`.venv/bin/python -m pytest -q`). Python 3.12.12 in `.venv`.

## Headline results (verified)

- **CIFT probe test AUROC = 0.993** (paper: 0.998). Benign prompts score ~0.18; every encoded
  attack (verbatim/base64/hex/rot13/reverse) scores 0.998–1.000 and is **blocked pre-output**. The
  per-layer single-layer AUROCs are modest (best layer 22 ≈ 0.65) — the MLP genuinely *combines*
  the per-layer Causal Flow Scores. Threshold calibrated at 1% benign FPR ≈ **0.711**.
- **DP-HONEY** cross-encoding scanner catches the planted honeytoken in every string encoding
  (unit-tested); integration test proves an encoded leak is blocked (`caught_by=dp_honey`) while
  the verbatim text filter is dark. Conformal fuzzy threshold ≈ **0.111** (α=0.05).
- **NIMBUS** on the synthetic suite: a long drip climbs cumulative budget
  `PASS(0.47) → WARN(0.88) → BLOCK(1.00)` and blocks at a nameable turn; benign conversations stay
  flat (max ratio ~0.18). Calibration: **encoder dim 8192, temperature 0.05, budget B=4.66**
  (benign max cumulative 2.33 → ratio 0.5; long-drip median 8.51).

## Calibration values (current)

| Layer | Values | Source |
|---|---|---|
| CIFT | hooked layers 21–27 (last 7/28), threshold 0.711 @1% FPR | `scripts/train_cift_probe.py`, `data/cift/threshold.json` |
| DP-HONEY | ε=1.0 (DP), α=0.05, fuzzy threshold 0.111 | `configs/default.yaml`, `data/honey/threshold.json` |
| NIMBUS | dim 8192, temp 0.05, N_neg 63, budget 4.66 bits | `configs/default.yaml`, `data/nimbus/meta.json` |

Artifacts live under `data/` (gitignored — regenerate with the step-3 scripts in the README).

## Key design decisions made during the build (non-obvious)

1. **CIFT runs *before* the text filter and catches verbatim too.** Because CIFT acts pre-output, in
   white-box mode it catches the credential-seeking *reach* for every encoding including verbatim,
   so `caught_by` is `cift` for all attack turns (not `text`). The "text filter catches verbatim
   then goes dark on encoding" contrast is what the **black-box** comparison (no CIFT) will show.
2. **Real-model compliance is weak — and that strengthens the thesis.** Qwen-1.5B complies poorly
   with encoding instructions (asked to reverse the key it emits a 4-char fragment; asked to
   base64 it often dumps the key verbatim or a prefix). Post-output text/canary detection is
   therefore unreliable against a fumbling model, but **CIFT catches the reach regardless of whether
   the model completes the encoding**. This is the PRD's anticipated "outside the lab" finding.
3. **NIMBUS uses a char-n-gram encoder + cosine critic, not a semantic encoder + learned critic.**
   The secret is a random string, so semantic (MiniLM) embeddings don't capture that an output
   fragment is *part of* the secret; hashed char-n-grams do. A learned diagonal critic (logistic
   over s⊙c) **overfit the suite's phrasing and lost the signal on raw key fragments** — cosine
   `f(s,c)=s·c` is the robust, generalizing choice. Larger encoder dim (8192) crushes hash-collision
   noise so benign conversations don't falsely accumulate budget.
4. **Honeytoken injection is an orchestrator/ledger property, not a Stage.** DP-HONEY's "inject"
   step in the PRD is done by the orchestrator via `HoneytokenLedger` + `inject_honeytokens`
   (placeholder `{{CREDENTIAL:name:fmt}}` substitution). DP-HONEY the *Stage* only detects
   (post-output). This keeps the Stage abstraction clean (all detectors are post-forward/post-output).
5. **Detectors degrade to stubs.** `bootstrap.build_detectors` loads each artifact if present, else
   the stage returns benign. The proxy always runs end-to-end; layers come online as artifacts land.
6. **Two-step readout capture, not `generate(output_hidden_states=True)`.** `WhiteBoxHost.readout`
   does prefill + one decode step with hooks on only the 7 hooked layers — byte-exact control of the
   final-prompt and first-decision positions, on the same forward graph that produces the output.

## Known limitations / honest findings (report these, don't hide them)

- **NIMBUS short-session blind spot:** short drips (2–3 turns) don't accumulate enough to cross the
  budget — structural (per-turn InfoNCE is ceiling-bounded at log2(N+1)=6 bits). The suite
  deliberately includes short drips to surface this; M7 should quantify it (detection vs session
  length). This is the paper's acknowledged limitation.
- **Live gradual drip:** the real model dumps a key prefix in one shot rather than dripping, so the
  *gradual* budget climb is best shown via suite replay (deterministic), not the live proxy.
- **CIFT numbers are on our prompt distribution.** 0.993 is strong but measured on our templated
  benign-vs-credseek set (secret in scope in both classes). Generalization to public benchmarks is
  an M7 stretch.

## How to resume

### M7 — Eval deliverables (offline, no external deps)
Goal: the figures/tables for the presentation. Suggested new scripts under `scripts/` + a
`scripts/run_eval.py` umbrella. Building blocks already exist:
- **CIFT per-layer AUROC (paper Fig. 2):** already printed by `train_cift_probe.py`; the raw
  per-prompt CFS + labels are cached in `data/cift/features.pt` (`raw_cfs`, `labels`, `is_test`,
  `layers`). Write `scripts/eval_cift_perlayer.py` to render the bar chart from that cache.
- **CIFT mean-ablation:** replace high-weight-layer readouts with the benign mean (`stats[li]["mu"]`
  in `data/cift/stats.pt`) and show AUROC collapse. Use `CIFTDetector`/`causal_flow` helpers.
- **Encoding-robustness gap (the real claim):** run the red-team encoding suite through CIFT vs the
  text baseline; CIFT AUROC should stay flat across encodings while text recall craters. Reuse
  `redteam/taxonomy.py` + `WhiteBoxHost.readout` + `CIFTDetector`.
- **DP-HONEY Table 2 + eq.5:** per-encoding precision/recall of `CrossEncodingScanner` + conformal
  coverage; eq.5 catch probability `k/(m+k)·(1-β)` with β measured by a distinguisher. New
  `scripts/eval_dp_honey.py`.
- **NIMBUS budget sweep (Fig. 5) + short-session curve:** sweep `B`, plot detection / false-block /
  turn-at-block, and detection-vs-session-length. Replay `detect/nimbus/suite.build_suite()` through
  `NimbusStage` (see the verification snippet pattern in the M6 work). New `scripts/eval_nimbus.py`.

### M8 — Black-box toggle + comparison
The toggle is verified: `build_pipeline(Mode.BLACKBOX, …)` returns `[text, dp_honey, nimbus]`
(CIFT dropped). To finish:
1. Set `OPENAI_API_KEY` (or point `configs/blackbox.yaml` `blackbox.base_url`/`model` at any
   OpenAI-compatible endpoint).
2. Run `... scripts/run_proxy.py --config configs/blackbox.yaml` and drive the same campaigns.
3. **Comparison slide:** same attacks, white-box vs black-box. In black-box the encoded attacks
   should sail past the (dark) text filter and **land** (no CIFT), while DP-HONEY/NIMBUS still catch
   what they can. The dashboard already has a black-box column (events dispatch by `event.mode`);
   to show both at once, run two proxies (ports 8000 white / 8001 black) or aggregate both event
   streams into one dashboard.

## Useful pointers
- Event contract: `sentinel/events/schema.py` (`TurnEvent`, `LayerResult`, `NimbusBudget`).
- Stage contract: `sentinel/stages/base.py` (`Stage`, `StageInput`, `StageOutput`, `Phase`).
- Pipeline order + graduated response: `sentinel/proxy/orchestrator.py`, `sentinel/proxy/response.py`.
- Detector loading/toggle: `sentinel/proxy/bootstrap.py`, `sentinel/stages/registry.py`.
- Campaigns + expected outcomes: `sentinel/redteam/agent.py`.
