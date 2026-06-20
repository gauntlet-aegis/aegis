# PRD — Credential-Exfiltration Defense Proxy (working title: *Sentinel*)

**Gauntlet AI Capstone · Week 1 Planning Document**
**Team size:** 4 · **Plan due:** Wed Jun 17, 11:59 PM · **Live demo:** Mon Jun 29 (10 min)
**Inspiration:** Chauhan & Revankar, *"Caught in the Act(ivation): Toward Pre-Output and Multi-Turn Detection of Credential Exfiltration by LLM Agents"* (AIWILD @ ICML 2026)

---

## 1. One-line summary

A security proxy that sits between an LLM agent and the model and watches for credential exfiltration at three independent layers — pre-output intent (white-box), post-output canary tripwire (any model), and cumulative multi-turn leakage — while a red-team agent continuously attacks it and a live dashboard shows every attempt land or get caught.

## 2. Problem & motivation

LLM agents routinely place credentials (API keys, DB passwords, OAuth tokens) in the same context window as untrusted retrieved content. An adversarial payload hidden in that content can steer the agent into revealing the secret — indirect prompt injection. Most deployed defenses operate on input or output **text**, which the attacker defeats by encoding (Base64/hex/ROT13), paraphrasing, or dripping the secret one fragment per turn across many turns. The text filter goes blind exactly when it matters.

The source paper argues — and we adopt as our thesis — that credential exfiltration is **not** a single per-turn text-classification problem. The model may *access* a secret before rendering it; the rendered form may be disguised; and leakage may accumulate slowly. A credible defense therefore needs **defense in depth**: model-internal monitoring, calibrated canaries, and temporal accounting, each catching a failure mode the others miss.

## 3. What we are building (and what we are not)

**We are building** a deployable defensive proxy plus the adversary that proves it works. This combines two things that are really one thing: a defense, and the red-team that generates its evaluation data. The red-team is not a separate project — it is *how we know the defense earned its numbers*.

**We are not building:** a faithful line-by-line reproduction of the paper, a formal information-flow proof, or a fully autonomous production agent. The paper is explicitly preliminary (small in-house multi-turn suite, no cross-model transfer, an information estimator that is a signal not a bound). Those gaps are our opportunity, not our obligation to close completely.

**Capstone direction:** primarily **B — a philosophically different take on agents** ("don't trust the agent's output; instrument the channel between the agent and the model — an immune system in the data path"). The evaluation carries a **C** flavor (attack the same problem from white-box and black-box angles and compare what each catches), which the paper's CIFT-only / API-only / full-pipeline split hands us directly.

## 4. Core architectural decisions (already made)

These are settled and frame the whole build. They were debated explicitly; the rationale is recorded here so the team doesn't relitigate them mid-sprint.

### 4.1 Topology — co-located white-box proxy, with a black-box toggle

The proxy hosts an **open-weight model itself** (raw Hugging Face `transformers`) so it has forward-hook access to activations. This is the only topology in which CIFT — the paper's strongest and most demo-worthy component — can run at all; there are no activations on a network wire.

A **black-box / API-only mode is a config toggle, not a second system.** Pointed at a closed API, the proxy simply disables the CIFT stage and runs DP-HONEY + NIMBUS + text filters (the paper's "API-only" config). Same codebase, one stage present or absent. This gives us the direction-C comparison slide for free: same attack, white-box vs. black-box, here's the gap.

> **Non-goal:** building two separate systems. That is how a 4-person / 10-day project dies. One proxy; CIFT is a toggleable stage.

### 4.2 Three orthogonal detection layers — kept deliberately separate

Per the paper's §7 ("The three components are complementary but not redundant"), the layers are **not** fused. Each catches a different failure mode and is evaluated independently.

| Layer | Question it answers | Mode | Signal |
|---|---|---|---|
| **CIFT** | Is the model *reaching for* a credential, before any token is emitted? | White-box only | Activation features at readout positions; benign vs. credential-seeking |
| **DP-HONEY** | Did a planted fake secret leak downstream, in *any* form? | White- & black-box | Deterministic canary tripwire on the output |
| **NIMBUS** | Is the secret leaking *slowly across turns* under the per-turn radar? | White- & black-box | Cumulative InfoNCE-based leakage score vs. budget |

**Explicitly rejected: fusing DP-HONEY into CIFT.** Using canary leakage as a training/runtime signal for the probe would (a) collapse the defense-in-depth the paper advocates, (b) create a circular dependency — CIFT is supposed to fire *before* any canary is touched — and (c) open an adaptive-attacker surface (an attacker who learns the probe was trained on canaries can craft around it). CIFT is trained on benign vs. credential-seeking **prompts**, exactly as the paper does. The layers stay orthogonal, which is also what makes the ablation eval (each layer's individual contribution) legitimate rather than a single blended number hiding which layer does the work.

### 4.3 The honeytoken's role (so nobody's confused mid-build)

A honeytoken is a fake secret that has *no legitimate reason to ever be used*, so any interaction with it is evidence of an intruder. It flips the detection problem: instead of recognizing every possible disguised leak (unbounded attack space), we watch one known planted value (finite, exact-match). Encoding the secret doesn't help the attacker — we match the *planted value*, not a pattern.

Two jobs, both DP-HONEY's: **detection** (canary appears downstream → caught, ground truth) and **indistinguishability** (the fake must be realistic enough that the attacker can't filter it out — this is what the DP bigram models + conformal calibration are for). Per eq. (5), the catch probability is `k/(m+k)·(1−β)`; it collapses if the attacker has a functional cue distinguishing real from fake. Therefore: **real credentials flow through the tool runtime and never enter model-visible context; only honeytokens are model-visible.** This is an architectural property of the proxy, independent of the detectors.

### 4.4 Model & runtime

- **Model:** Qwen2.5-1.5B-Instruct (validated in the paper), **fp32 on Apple Silicon MPS**, no quantization (unneeded at this size; removes a variable).
- **Framework:** raw HF `transformers` for hook access — *not* Ollama/llama.cpp, which don't expose clean per-layer hidden states.
- **CIFT math:** diagonal-covariance Mahalanobis (eq. 2) — elementwise, no matrix inverse, which sidesteps the one linear-algebra op historically flaky on MPS. The paper already uses diagonal covariance (full is rank-deficient), so we're paper-aligned, not cutting a corner.
- **Scale-up path (optional, eval only):** a cloud 7B run at the very end if we want bigger headline numbers. Not on the critical path.
- **MPS escape hatches:** `PYTORCH_ENABLE_MPS_FALLBACK=1` for missing kernels; CPU forward pass for the probe if needed (slow but demo-viable); cloud as last resort.

### 4.5 Protected-traffic source — mixed

- **Live demo:** a **scripted/simulated agent** we fully control — a harness with a system prompt, a (honey)credential in context, and incoming "tool outputs" some of which are poisoned by the red-team. Deterministic and demo-safe: we know exactly which turn the multi-turn attack crosses NIMBUS's budget and can narrate it live. From the proxy's point of view it is indistinguishable from a real agent.
- **Offline eval:** **benchmark replay** — TensorTrust, InjecAgent, BIPIA, AgentDojo prompts plus a held-out encoding suite — for numbers comparable to the paper.

> **Non-goal:** a full autonomous tool-using agent on the critical path. Highest-variance dependency, and not where our novelty lives. Our novelty is the defense layer.

## 5. System architecture

```
                          ┌─────────────────────────────────────────────┐
   RED-TEAM AGENT         │                 SENTINEL PROXY                │
   (attacker +    ──────► │                                               │
    eval-data gen)        │  1. DP-HONEY: inject calibrated honeytokens   │
                          │     into model-visible context                │
   SCRIPTED AGENT         │  2. ── forward pass (hosted Qwen2.5) ──        │
   (legit traffic) ─────► │     CIFT: hook activations @ readout          │
                          │     positions → credential-access score       │
                          │     ├─ flag → abort / graduated response      │
                          │     └─ else → generate                        │
                          │  3. TEXT DETECTOR: scan output for canary      │
                          │  4. NIMBUS: update cumulative leakage Î_cum    │
                          │     ├─ Î_cum/B ≥ 1.0 → block                   │
                          │     └─ ≥ 0.9 → sanitize                        │
                          └───────────────────┬───────────────────────────┘
                                              │  events (per-turn)
                                              ▼
                                   ┌────────────────────────┐
                                   │   LIVE DASHBOARD        │
                                   │  attacks landing/caught │
                                   │  per-layer attribution  │
                                   │  NIMBUS budget meter    │
                                   └────────────────────────┘
```

Black-box mode: stage 2 (CIFT) is skipped; stages 1, 3, 4 run unchanged against an API model.

## 6. Components — scope per layer

### 6.1 Proxy core
The request/response interceptor and orchestration. Hosts the model in white-box mode, forwards to an API in black-box mode. Owns honeytoken-injection bookkeeping, runs the detection stages in order, emits a structured per-turn event stream to the dashboard. Implements the graduated response (pass / warn / sanitize / block) from the paper's Algorithm 1.

### 6.2 CIFT (white-box)
Forward hooks on the last ⌊0.25·L⌋ layers; pool hidden states over **readout positions** (final prompt token + first pre-generation decision position; ablation: final 4 tokens) — *not* static credential positions (causal mask makes those uninformative). Per-layer diagonal-covariance Mahalanobis deviation → Causal Flow Score → small MLP probe (K→128→64→1), trained BCE + sparsity penalty on benign vs. credential-seeking prompts. Deliverable includes the per-layer AUROC analysis (paper Fig. 2) and a mean-ablation sanity check on high-weight layers.

### 6.3 DP-HONEY
Per-format character bigram models with Laplace noise (ε-DP over the count table) to generate realistic fakes; split-conformal calibration of the text detector threshold (target coverage from held-out benign nonconformity scores). Output: precision/recall + coverage table (paper Table 2), and the `k/(m+k)·(1−β)` accounting.

### 6.4 NIMBUS
Per-turn InfoNCE leakage estimate (base-2, bits) with a conversational-state-conditioned critic; cumulative `Î_cum` tracked against budget B with warn/sanitize/block thresholds. Honest framing: a learned **lower-bound signal**, not a certified upper bound; InfoNCE ceiling (`log2(N_neg+1)`) means it targets *accumulated* leakage, not single-turn blowouts (those are CIFT's job). Output: the 50-conversation synthetic suite, the budget-sensitivity sweep (paper Fig. 5), and the **short-session failure mode** reported honestly.

### 6.5 Red-team agent
Generates attacks across the held-out evasion taxonomy: verbatim, Base64, hex, ROT13, leet, paraphrase, reverse, fragmentation, partial reproduction, and **multi-turn dripping**. Doubles as the eval-data generator. The dripping attacks are what exercise NIMBUS; the encoding attacks are what make CIFT shine vs. text filters.

### 6.6 Live dashboard
Real-time view of the per-turn event stream: each attack shown landing or caught, **which layer caught it**, the NIMBUS cumulative budget meter filling toward the block threshold, and a side-by-side white-box vs. black-box panel. This is the #1 presentation priority.

## 7. The demo (working the backward from June 29)

The presentation hinges on one moment. The red-team tries to exfiltrate a credential **verbatim** → the text filter catches it (unimpressive, anyone can grep). The red-team **Base64-encodes** it → the text filter goes dark, the output looks like harmless gibberish — **and CIFT lights up red anyway**, because it saw the model *reach for the secret* before a single token rendered. The audience watches the encoded attack sail past the obvious defense and get caught by the internal one.

Then the **multi-turn drip**: each turn looks benign, every per-turn detector stays quiet, and the **NIMBUS budget meter** climbs turn by turn until it crosses the threshold and blocks — at a turn we can point to in advance.

Finally the **comparison slide**: same attacks, white-box vs. black-box mode, here's exactly what white-box buys you.

## 8. Success criteria

**Must-have (project succeeds):**
- End-to-end proxy intercepts traffic and runs all three layers in white-box mode.
- CIFT detects at least Base64/hex/ROT13-encoded exfiltration that the text baseline misses (reproduce the *qualitative* Fig. 3 gap; exact AUROC secondary).
- DP-HONEY canary fires on a leaked planted token in encoded form.
- NIMBUS blocks at least one multi-turn drip that per-turn detectors miss.
- Live dashboard shows the above in real time.

**Should-have:**
- Black-box mode toggle working against one API model.
- Per-layer ablation table (each layer's individual contribution).
- Conformal calibration removing manual threshold tuning.

**Nice-to-have (cut first under time pressure):**
- Cloud 7B eval run for bigger headline numbers.
- Cross-model transfer test.
- Tool-call-argument channel (the paper's acknowledged blind spot) — strong "future work" slide either way.

## 9. Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| MPS lacks a kernel / hook misbehaves | Medium | **Day-0 30-min spike**: load 1.5B on `mps`, hook one layer, generate one token, print hidden-state shape. Fallback: `MPS_FALLBACK`, CPU probe, or cloud. De-risk before anyone builds on top. |
| CIFT numbers don't reach paper's 0.998 | Medium | Expected and fine — paper's number is a lab setup with known credential positions. The *qualitative* encoding-robustness gap is the real claim. "We tried CIFT outside the lab assumption and here's what broke" is a *stronger* finding. |
| Live demo hardware fails | Medium | Pre-warmed cloud GPU as demo-day backup even if dev is local; record a backup video. |
| NIMBUS critic underperforms on tiny synthetic suite | Medium | Report short-session failure honestly (it's in the paper too); budget-sensitivity sweep shows the tradeoff rather than a single fragile number. |
| Scope creep into a real agent | Medium | Scripted agent is the contract. Real agent is explicitly a non-goal. |
| 4 people, 10 days | High | Layers are independent by design → parallelizable. Shared event-schema contract defined day 1 so dashboard + detectors develop against a stub. |

## 10. Tech stack

- **Model / ML:** Python, PyTorch (MPS), Hugging Face `transformers`, NumPy/scikit-learn for probe + calibration.
- **Proxy / orchestration:** Python (FastAPI) for the proxy so it shares a process with the model; structured event emission over WebSocket/SSE.
- **Dashboard:** lightweight web frontend (React or similar) consuming the event stream.
- **Benchmarks:** TensorTrust, InjecAgent, BIPIA, AgentDojo + custom held-out encoding suite + 50-conversation synthetic multi-turn suite.

## 11. Open items (deliberately unresolved)

- **Work division across the 4 of us** — to be assigned. Suggested principle: match the hardest-to-fake skill (PyTorch/activations) to the riskiest component (CIFT); proxy + agent orchestration + red-team loop is the backend/agent lane; dashboard is a parallel full-stack lane; eval/benchmark harness is a fourth. Final assignment TBD by the team.
- Exact budget B and NIMBUS thresholds — tune empirically.
- Which single API model for black-box mode.
- Whether to attempt the cloud 7B eval at all.

## 12. Deliverables (capstone)

1. **This planning document** — due Wed Jun 17, 11:59 PM.
2. **Live presentation** — 10 min, Mon Jun 29: the demo in §7, the comparison slide, honest limitations, and a "future work" slide (tool-call-argument channel, cross-model transfer, multi-session budget persistence).
