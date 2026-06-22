# NIMBUS budget meter — dashboard contract

Coordination note for the **M3 · Dashboard: layer chips + NIMBUS budget meter** task. Bind the
meter against these exact fields on `event.nimbus` (the `NimbusBudget` model in
`sentinel/events/schema.py`). Source of truth is `sentinel/stages/nimbus_stage.py`.

## ⚠️ Field-name correction

The task description says the meter is "driven by `nimbus.normalized`". **There is no `normalized`
field.** Use **`nimbus.ratio`** — it is already clamped to `[0, 1]` and is exactly the meter fill
fraction. Coding against `normalized` returns `undefined`.

## Fields to bind

| Field | Type | Use |
|---|---|---|
| `ratio` | float, **0..1 (pre-clamped)** | **Meter fill fraction.** Drive the bar from this. |
| `cumulative_bits` (Î_cum) | float | Numerator of the "Î_cum / B bits" label. |
| `budget_bits` (B) | float | Denominator. `ratio = Î_cum / B`, capped at 1.0. |
| `per_turn_bits` (ΔI) | float | This turn's increment — good for a per-turn "drip" delta animation. |
| `crossed_warn` | bool | Latch meter color at/after the warn line. |
| `crossed_block` | bool | Latch meter color at/after the block line. |

## Gridlines — three, not two

The task mentions warn/block; there are **three** thresholds (`nimbus_stage.py`):

| Line | Ratio | Action | Suggested color |
|---|---|---|---|
| WARN | **0.6** | warn | yellow |
| SANITIZE | **0.9** | sanitize | orange |
| BLOCK | **1.0** | block | red |

There is **no** `crossed_sanitize` bool — derive sanitize state from `ratio >= 0.9`.

## Gotchas

- **Overflow past budget:** `nimbus.ratio` caps at 1.0. If you want to show the meter blowing past
  the budget, the **unclamped** ratio (can exceed 1.0) is in the nimbus layer's
  `layers[].detail["ratio"]`.
- **Null guard:** `event.nimbus` can be `null` on a turn where the NIMBUS stage didn't run — guard
  before reading the meter.
- **Both modes:** NIMBUS runs in white-box *and* black-box, so the meter is live in both.

## Calibration

The trained config uses **B = 4.66 bits** (`data/nimbus/meta.json`); the un-trained stub uses
`16.0`. For the demo conversation, the per-turn `I_turn` / `I_cum` trace and the crossing turn come
from the M7 NIMBUS eval (`scripts/eval_nimbus_budget.py`) — ask Chris for the exact crossing turn to
annotate the meter in advance.
