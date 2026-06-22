# Aegis Dashboard — VIEWS

Verbal description of every view in the Aegis demo dashboard (PDF FR-11, sections 7/11). The
dashboard is a **read-only observability surface** over the SDK/gateway — it shows decisions and
evidence; it never makes security decisions itself. It reads live `TurnEvent`/`AegisDecision`
records from the gateway (SSE or polled) and from the local JSONL trace/eval artifacts (replay
mode — the demo's hardware insurance).

Design intent: a single-page app with a left **nav rail** selecting one of the views below, a
persistent **header** (product name, current **policy mode** chip — observe/balanced/strict, and a
Live/Replay toggle). Action colors are consistent everywhere: ALLOW = green, WARN = amber,
SANITIZE = orange, BLOCK = red, ESCALATE = dark red/purple.

---

## V1 — Live Decision Feed (default view)

A reverse-chronological stream of guarded turns. Each row is one guarded boundary
(request / tool_call / response) and shows:
- **Action badge** (colored as above) and the **phase** icon.
- **Scenario / attack label** (e.g. "tool_call_arg_exfil", "benign") when present.
- **Caught-by**: the detector(s) that fired (chips: secret_pattern, encoding, tool_call_args,
  honeytoken, nimbus_lite).
- **Risk score** (0–1) as a small bar, and **latency** (ms).
- Truncated, **redacted** input summary (never raw secrets).
Clicking a row opens **V2**. Top of the view: small counters (total turns, blocked, escalated,
warnings) and a filter (by action / phase / scenario).

## V2 — Decision Detail (drill-down)

Everything about one turn, for the "100% of non-allow decisions carry evidence" requirement:
- Header: action badge, phase, scenario label, `trace_id`, timestamp, total latency.
- **Per-detector table**: detector name · score · confidence · verdict · recommended action ·
  latency · structured **evidence** (expandable JSON — matched kinds, decoded preview, canary
  id/location, per-arg tool findings, leakage ratio). Redacted previews only.
- **Policy reasons**: the human-readable reason lines that produced the final action, plus which
  rules fired and the active mode.
- **Inbound vs returned**: the redacted input summary and, when SANITIZE, the sanitized payload
  (least-disclosure result) side by side; when BLOCK/ESCALATE, the refusal text.

## V3 — Baseline vs Protected (the demo headline)

Side-by-side comparison of the same scenarios run in **observe** (baseline: records, never blocks —
the vulnerable agent) vs **balanced** (protected). Two aligned columns; each scenario row shows the
baseline action (typically WARN = leaked) next to the protected action (BLOCK/ESCALATE/SANITIZE),
with the evidence. This is the "baseline leaks, Aegis stops it" slide, rendered live.

## V4 — Metrics & Eval Summary

The eval harness output (`artifacts/eval/`): 
- **Detection rate by category** (bar chart across the 7 categories).
- **False blocks** and **warnings** on benign categories (the trust metric).
- **Average gateway latency** (vs the <50 ms target).
- **Detector-hit distribution** (which detectors carry the load).
- **Evidence completeness** (% of non-allow decisions with structured evidence).
A small banner restates claim discipline: leakage budget is a learned signal, not a formal bound.

## V5 — Policy & Detectors panel

Reference/inspection view (not interactive enforcement):
- Current **mode** and the loaded **YAML rules** (the 4 rule types) rendered readably.
- The registered **detectors** and their phases; the **honeytoken registry** (canary id · service ·
  format · planted location) and the **credential broker** handles in play (handles only, never
  secret values).

---

## Empty / error / loading states
- **No events yet** (Live): a centered hint to run `scripts/run_demo.py` or drive the gateway.
- **Replay with no artifacts**: hint to run `scripts/run_eval.py`.
- **Gateway unreachable** (Live): non-blocking banner; offer Replay mode.
