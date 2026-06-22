# Aegis — Clean-Room Rebuild from `docs/aegis-plan.pdf`

## Context

We are rebuilding **Aegis** from scratch, treating it as a **greenfield** project whose single
source of truth is `docs/aegis-plan.pdf` (the "Aegis — Runtime Credential Defense for LLM Agents"
PRD + Project Plan, Gauntlet capstone, demo date 2026-06-29). The current repo contents (a prior
`sentinel/` implementation) are being discarded because they drifted from the PDF's architecture
(the PDF is **SDK-first, Inspect→Score→Enforce, with tool-call argument exfiltration as the headline
differentiator**; the old code was a layered NIMBUS/CIFT/DP-HONEY proxy).

**Why this matters / intended outcome.** Market research (3 parallel studies, 2025–2026) confirms a
real, ownable gap. The space is saturated with *detection-first* text filters (Lakera, LLM Guard,
Cloudflare/Portkey/Kong AI gateways) and a wave of academic firewalls (ClawGuard, CaMeL,
LlamaFirewall, Progent, "Firewalls Are All You Need", OCELOT, SecureClaw, CapSeal). **No shipping
product integrates all of:** (1) tool-call **argument-level** credential exfiltration detection,
(2) **honeytokens** as a first-class runtime defense, (3) **cumulative multi-turn** leakage
accounting, and (4) a **credential broker** that keeps raw secrets out of model context — behind one
**explainable, deployable, closed-API-compatible** SDK + gateway. Aegis owns that integration.

**Decisions locked with the user:**
- **Ambition:** PDF MVP spine **+ own the market gap** (push the 4 differentiators hard) **+ research
  extensions** (encoding-aware taint tracking, OCELOT-style least-disclosure budgets, schema-aware
  tool/MCP validation). Deterministic detectors remain authoritative; ML is never required to block.
- **Build method:** the **`/factory` skill** consumes this plan as its spec/brief (greenfield rule).
- **Dashboard:** UI is gated — **`VIEWS.md` + Figma mocks + user approval first**, then build.
- **Provider:** deterministic **mock/scripted provider** (authoritative for tests + demo) **plus a
  live Claude adapter** (`ANTHROPIC_API_KEY`). **No PyTorch** (P2 in PDF; torch has no wheel for this
  x86 macOS venv). CIFT and the ML risk probe ship as documented, non-blocking adapter interfaces.

## Positioning (bake into README + demo narrative)

> *Aegis treats tool-call argument credential exfiltration as a first-class threat and combines
> honeytokens, cumulative cross-turn leakage accounting, and a credential broker into one
> explainable runtime layer that works on closed-API models — preventing leakage at dispatch time
> rather than detecting it after the fact.*

Claim discipline (from PDF §12): demo-grade, not production. The leakage ledger is a learned
cumulative **signal**, not a formal information-flow bound. CIFT-style activation probing is a
documented stretch, not an MVP dependency.

## Scope

**In scope (MVP core — PDF §3.6, §4, §6):**
- Python **SDK** as the security source of truth, with three guards returning `AegisDecision`:
  `guard_request(messages, tools, session_id, metadata)`,
  `guard_tool_call(tool_name, arguments, session_id, metadata)`,
  `guard_response(output, session_id, metadata)`.
- Normalized `AegisEvent` (fields per PDF §4.3) and `AegisDecision` (action, risk score, reasons,
  detector hits, optional sanitized payload, trace id).
- **Inspect→Score→Enforce** pipeline; most-severe-action-wins; deterministic detectors authoritative.
- Detectors (PDF §6.2): secret-pattern scanner; encoding scanner (base64/hex/URL/split-token →
  decode *then* scan); honeytoken detector (exact + normalized); **tool-call argument scanner**
  (`send_email`, `http_request`, `query_database`); **Nimbus-lite** cumulative leakage ledger;
  ML-probe interface (stub); CIFT adapter interface (stub).
- **Credential broker** (PDF §6.5): opaque `secret://service/name` handles, local fake secret store
  (env vars / test JSON), resolved only at the tool boundary; if a raw secret reaches a log/context,
  redact + emit critical trace + force a non-allow decision unless explicit local-test mode.
- **Honeytokens** (push hard): DP-calibrated, format-matched generation for AWS, OAuth bearer,
  `sk-` API keys, JWT, Stripe `sk_live_`, GitHub `ghp_`; injected only into model-visible context;
  detected in outputs **and** tool arguments; incident linkage (which call / what context).
- **YAML policy** (PDF §6.3–6.4): 4 independent rule types (detector score threshold, tool-arg
  condition, canary hit, leakage-budget threshold), modes `observe` / `balanced` / `strict`.
- **FastAPI gateway** wrapping the SDK; **provider abstraction** (mock authoritative + Claude live).
- **Eval harness** (PDF §7): scenario categories (benign, encoded single-turn, multi-turn drip,
  tool-call arg exfil, canary touches, benign secret-handle, false-positive benign text); metrics
  (detection rate by category, false blocks, warnings, latency, detector-hit distribution, evidence
  completeness); **local JSONL/Markdown artifacts required**, Braintrust optional; baseline-vs-
  protected comparison + demo metrics table.
- **Observability:** JSONL trace sink with redaction + log hygiene.

**In scope (research extensions — the "own it" layer):**
- **Encoding-aware taint/provenance tracking:** tag message spans trusted/untrusted/mixed; track
  credential-shaped values across turns and through encode/decode transforms; raise risk when an
  untrusted-originating value reaches a tool-call argument.
- **OCELOT-style least-disclosure `SANITIZE`:** when the leakage budget or a detector trips, choose
  the minimal intervention (redact → generalize → substitute → drop) instead of a blunt block.
- **Schema-aware tool/MCP validation:** validate tool-call arguments against declared JSON schemas;
  flag unbounded/oversized string params and RCE-shaped values before dispatch.

**Out of scope (PDF §3.5):** production secret-manager/rotation/tenancy/billing/IAM; a policy DSL or
visual editor; LLM-judge-as-sole-detector; PyTorch/CIFT white-box as a hard dependency; Rust gateway
perf work; supporting every framework/provider/schema.

## Architecture & repo layout (fresh)

```
aegis/
  docs/aegis-plan.pdf              # KEPT (only surviving file)
  PLAN.md                          # this plan, mirrored at repo root (exec step 1)
  VIEWS.md                         # dashboard views, before any UI code
  README.md  pyproject.toml
  aegis/                           # SDK package (source of truth)
    sdk.py  events.py  decision.py  pipeline.py
    detectors/{base,secret_pattern,encoding,honeytoken,tool_call_args,ledger,ml_probe,cift_adapter}.py
    taint.py                       # provenance/taint (research ext)
    broker/{store,handles}.py
    honeytokens/{generator,registry}.py
    policy/{engine,schema,modes}.py  policy/default.yaml
    providers/{base,mock,claude}.py
    gateway/app.py                 # FastAPI; calls SDK, never re-implements logic
    eval/{runner,scorers,report,braintrust}.py  eval/scenarios/*.yaml
    obs/trace.py                   # JSONL sink + redaction
  dashboard/                       # Streamlit/custom — built AFTER Figma mock approval
  tests/                           # unit + integration + eval, no live LLM required
  scripts/{run_gateway,run_demo,run_eval}.py
```

**Stack:** Python 3.12, uv, FastAPI, Pydantic v2, PyYAML, httpx, `anthropic` SDK, pytest, Streamlit
(dashboard), Braintrust (optional, env-gated). No torch.

## Execution sequencing (after plan approval)

1. **Branch + clean-room.** Create branch `rebuild/aegis-from-plan`. Remove every tracked file
   **except** `docs/aegis-plan.pdf` (and `.git`); other branches retain the old history.
2. **Write `PLAN.md` to repo root** (mirror of this file) — per user instruction.
3. **Scaffold** the package skeleton + `pyproject.toml` + `README.md` (with the positioning above).
4. **Run `/factory`** with this PLAN.md as the brief to build the **non-UI security core** end-to-end
   (SDK, detectors, taint, broker, honeytokens, policy, gateway, providers, eval, traces) with tests
   and verification gates.
5. **Dashboard gate:** author `VIEWS.md`, produce **Figma mocks**, get **user approval** (global
   rule). Only then build the dashboard (via `/factory` or directly), pixel-verified.
6. **Demo + eval artifacts:** baseline-vs-protected run, metrics table, JSONL/Markdown report,
   demo script. Open a PR.

## Verification

- `pytest` green: detector unit tests (secret/encoding/honeytoken/tool-arg/ledger), policy mapping
  across the 3 modes, broker invariant (raw secret never in model-visible context), taint
  propagation, and an **integration test** proving a vulnerable baseline leaks a fake secret while
  the protected path blocks direct + encoded + tool-arg + honeytoken exfiltration and **allows**
  benign secret-handle usage. All runnable **without a live LLM**.
- `scripts/run_demo.py` runs the end-to-end baseline-vs-protected comparison and writes local JSONL +
  Markdown artifacts (works with no network / no Braintrust / no ML).
- Latency budget: detector+policy overhead targeted < 50 ms/turn (simple detectors < 10 ms).
- Every non-allow decision carries structured evidence + a human-readable reason (100%).

## Risks & mitigations

- **`/factory` + clean-room ordering:** branch and delete *before* `/factory` so it scaffolds onto a
  clean tree; keep `docs/aegis-plan.pdf` as the in-repo spec.
- **Dashboard blocks momentum:** core is built first; UI is deferred behind the Figma gate.
- **Scope creep from research extensions:** they layer on the deterministic core and never gain
  blocking authority on their own (PDF non-goal #6); ship as additive signals + richer `SANITIZE`.
- **Over-claiming:** README/demo use the PDF's disciplined framing (signal, not proof; demo-grade).
- **torch unavailable on this venv:** ML probe + CIFT are interface stubs only; documented as stretch.
