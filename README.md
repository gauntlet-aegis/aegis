# Aegis — Runtime Credential Defense for LLM Agents

Aegis is a **drop-in security layer for LLM agents** that treats **tool-call argument credential
exfiltration as a first-class threat**. It combines honeytokens, cumulative cross-turn leakage
accounting, and a credential broker into one **explainable runtime layer that works on closed-API
models** — preventing leakage *at dispatch time* rather than detecting it after the fact.

> **Why this exists.** The market is full of detection-first text filters and AI gateways (Lakera,
> LLM Guard, Cloudflare/Portkey/Kong) and a wave of academic firewalls (ClawGuard, CaMeL,
> LlamaFirewall, Progent). None of them ship the *integration* of (1) tool-call **argument**-level
> credential detection, (2) **honeytokens** as a first-class runtime defense, (3) **cumulative
> multi-turn** leakage accounting, and (4) a **credential broker** that keeps raw secrets out of
> model context. Aegis owns that integration.

## How it works

Aegis is **SDK-first**: the Python SDK owns every security decision; the FastAPI gateway and the
eval harness are thin callers of the same SDK. Each guard runs an **Inspect → Score → Enforce**
pipeline and returns a structured `AegisDecision`.

```python
from aegis.sdk import Aegis

aegis = Aegis.from_config("aegis/policy/default.yaml")   # mode: observe | balanced | strict
decision = aegis.guard_tool_call("send_email", {"to": "x@y.z", "body": "key=AKIA..."}, session_id="s1")
if not decision.allowed:
    print(decision.action, decision.reasons)             # e.g. BLOCK ['credential in tool argument ...']
```

Three guard points: `guard_request(messages, tools, …)`, `guard_tool_call(tool_name, arguments, …)`,
`guard_response(output, …)`.

## Defenses

- **Tool-call argument scanner** (marquee) — inspects structured arguments to `send_email`,
  `http_request`, `query_database` before dispatch; encoding- and provenance-aware.
- **Secret-pattern + encoding scanners** — credential shapes, decoded from base64/hex/URL/split-token.
- **Honeytokens** — DP-calibrated, format-matched canaries detected in output *and* tool args.
- **Nimbus-lite ledger** — per-session cumulative leakage budget for low-and-slow multi-turn drips.
- **Credential broker** — opaque `secret://service/name` handles resolved only at the tool boundary.
- **Taint tracking** — flags credential-shaped values that originated in untrusted content.

Deterministic detectors are **authoritative**; the optional ML risk probe and CIFT activation
adapter are non-blocking interfaces.

## Quick start

```bash
uv venv --python 3.12 .venv && VIRTUAL_ENV=.venv uv pip install -e ".[dev]"
.venv/bin/pytest -q                       # full suite, no live LLM required
.venv/bin/python scripts/run_demo.py      # baseline-vs-protected; writes local JSONL + Markdown
```

## Design decisions & divergences from the PDF

The PDF (`docs/aegis-plan.pdf`) is the spec, but several things it left open, simplified, or that we
deliberately diverged from are worth calling out:

1. **Action ordering & "most severe wins."** The PDF lists `ALLOW/WARN/SANITIZE/BLOCK/ESCALATE`
   but not their ordering or how to combine them. We model `Action` as an `IntEnum` with
   `ESCALATE > BLOCK` (escalate = block **plus** out-of-band human review) so combination is a plain
   `max()`. Detector **scores are never numerically fused** — only the ordinal action is combined.

2. **Forwarding semantics (`allowed` vs `forwardable` vs `blocks`).** The PDF doesn't define what
   each action does to traffic. We define: **WARN annotates and forwards** (so observe mode, which
   clamps everything to WARN, never blocks); **SANITIZE rewrites** (least-disclosure); **BLOCK/
   ESCALATE refuse**. The gateway gates on `blocks`, not on "clean allow."

3. **Credential broker scope (divergence).** The PDF says a raw secret in prompt/logs must force a
   non-allow decision. We scoped the broker's *forced, mode-bypassing* escalation to **actual store
   secret values only**. Generic credential *shapes* are the `secret_pattern` detector's job and flow
   through the normal, mode-governed policy — otherwise observe mode could never "just observe," and
   the broker would double-count the pattern detector.

4. **NIMBUS-lite is a deterministic heuristic, not InfoNCE/ML (divergence).** The research NIMBUS
   uses an InfoNCE mutual-information estimator. Per the PDF's own non-goals (ML must not be required
   to block; cumulative leakage is "a signal, not a formal bound"), we ship a deterministic, no-ML
   cumulative ledger (new high-entropy fragments accrue; a full secret trips instantly). It is
   honestly labeled a heuristic suspicion signal.

5. **CIFT & the ML risk probe are interface stubs (no PyTorch).** The PDF marks white-box activation
   probing and the ML probe as P2/stretch and says PyTorch must not be a hard dependency. We ship
   them as documented, non-blocking adapter interfaces only. (Also: `torch` has no wheel for this
   x86-64 macOS dev environment.)

6. **"DP-calibrated" honeytokens are demo-grade.** We generate format-matched canaries with a
   Laplace-noised character-bigram model trained on **synthetic** format-valid samples (never real
   credentials), then enforce a hard format mask. This is DP-*flavored* and calibrated for the demo,
   **not** a rigorous differential-privacy guarantee.

7. **Policy refinement: wildcard defers to dedicated rules.** Beyond the PDF's "independent rules,
   most-severe wins," a wildcard `detector_score_threshold` does **not** govern detectors that have a
   dedicated rule type (`nimbus_lite`→`leakage_budget_threshold`, `honeytoken`→`canary_hit`), so the
   graduated leakage thresholds (0.6/0.9/1.0) aren't overridden by the generic score block.

8. **Trust/taint convention.** The PDF names `trusted/untrusted/mixed` but not how it's derived. We
   default `system`/`developer`/`assistant` roles to **trusted** and `user`/`tool` roles to
   **untrusted** (overridable per message), and provenance checks are **encoding-aware** (a value's
   decoded forms are traced to their origin) — a research extension beyond the PDF.

9. **Eval baseline = observe mode of the same system.** "Baseline vs protected" is implemented as
   **observe vs balanced** mode of the *same* detectors/policy (only the posture differs) — a clean
   apples-to-apples comparison rather than a separately-built vulnerable agent.

10. **Dashboard deferred (sequencing divergence).** The PDF specifies a Streamlit dashboard (FR-11,
    P1). It is intentionally **not** built in this pass; per project UI rules it is gated behind a
    `VIEWS.md` + approved-mock step and will follow separately.

11. **Stack specifics the PDF left open.** Python 3.12, `uv` + `hatchling`, MIT license, and a
    deterministic mock provider (authoritative for tests/demo) alongside a lazy-imported Claude
    adapter (default model `claude-opus-4-8`).

## Claim discipline

Aegis is **demo-grade, not production-grade**. The cumulative leakage ledger is a learned *signal*,
not a formal information-flow bound. CIFT-style activation probing is a documented stretch, not a
dependency. See `docs/aegis-plan.pdf` for the full PRD and `PLAN.md` for the build plan.
