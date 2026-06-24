# Runtime DP-HONEY V4.1 CIFT Milestone

## Purpose

This checkpoint replaces the historical DP-HONEY-lite token source with the
merged Aegis runtime DP-HONEY generator while preserving the V4.1
selector-window data geometry. The goal is to test whether the CIFT-like
activation signal survives when the prompt rows are backed by the runtime
canary implementation rather than the local deterministic token helper.

The generated rows remain synthetic offline evaluation data. They are useful
for CIFT training and regression comparison, not evidence that the runtime
detector is production-ready.

## Artifacts

| Artifact | Path |
|---|---|
| Raw structured prompts | `introspection/data/prompts_dp_honey_runtime_v4_1.jsonl` |
| Selector-window prompts | `introspection/data/prompts_dp_honey_runtime_v4_1_selector_windows.jsonl` |
| Activation features | `introspection/data/activations/qwen3_0_6b_dp_honey_runtime_v4_1_selector_windows.pt` |
| Full-train bundle | `introspection/data/models/cift_qwen3_0_6b_dp_honey_runtime_v4_1_selector_window_layer_15_v1.pkl` |

The raw and selector-window datasets each contain 144 rows: 48 `benign`, 48
`secret_present_safe`, and 48 `exfiltration_intent` rows across the same six
V4.1 pressure families.

## Result

The best layer sweep again selects `readout_window_layer_15` for
`safe_secret_vs_exfiltration`.

| Dataset | Activation Macro F1 | Activation Accuracy | Word TF-IDF Macro F1 | Char TF-IDF Macro F1 |
|---|---:|---:|---:|---:|
| DP-HONEY-lite V4.1 selector windows | 0.7646 | 0.7875 | 0.1172 | 0.2851 |
| Runtime DP-HONEY V4.1 selector windows | 0.8387 | 0.8438 | 0.0667 | 0.1657 |

The runtime-backed run improves the activation probe by 0.0741 macro F1 and
0.0563 accuracy on the target task while the text baselines get weaker. That is
the direction we want from a CIFT-style monitor: the useful signal is less
recoverable from prompt surface text and more recoverable from hidden-state
features at the selected readout window.

The benign-versus-secret-related task remains saturated for both activation and
word TF-IDF. It is still an integration check, not the main detector-quality
claim.

## Error Profile

On `safe_secret_vs_exfiltration`, the runtime-backed activation probe makes 17
grouped out-of-fold errors. The confusion matrix is:

```text
[37, 11]
[6, 42]
```

The main pressure slices are:

| Slice | Errors | Examples | Accuracy |
|---|---:|---:|---:|
| `incident_ticket` exfiltration | 5 | 8 | 0.3750 |
| `access_review` exfiltration | 3 | 8 | 0.6250 |
| `audit_export` safe-secret | 3 | 8 | 0.6250 |
| `database_uri` exfiltration | 6 | 24 | 0.7500 |
| no-payload exfiltration | 6 | 24 | 0.7500 |

This is a cleaner error profile than the lite V4.1 run, where
`support_transcript` exfiltration dominated the failures. The new primary target
is `incident_ticket` exfiltration, with secondary attention to database-URI and
no-payload exfiltration cases.

## Current Claim

The runtime DP-HONEY generator is now usable as the canary source for offline
CIFT training data. On the current V4.1 selector-window task, it improves the
activation-over-text gap and produces a stronger full-train CIFT-like bundle.

Do not promote this model as a production detector yet. The next evidence needed
is either a sealed-holdout evaluation of a frozen candidate or a runtime-spine
integration check that captures the same readout-window features from live
`NormalizedTurn` objects.
