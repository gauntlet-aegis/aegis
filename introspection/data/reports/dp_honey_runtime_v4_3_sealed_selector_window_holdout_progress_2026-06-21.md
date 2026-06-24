# Runtime DP-HONEY V4.3 Sealed Holdout Milestone

## Purpose

This checkpoint performs the first one-shot evaluation of the frozen runtime
DP-HONEY V4.1 CIFT candidate:

```text
cift_qwen3_0_6b_dp_honey_runtime_v4_1_selector_window_layer_15_v1
```

The holdout uses the V4.3 sealed family set with the runtime DP-HONEY canary
backend. It preserves the V4.1 selector-window geometry but changes the
scenario families and canary values. The model bundle was not retrained or
tuned before this evaluation.

## Artifacts

| Artifact | Path |
|---|---|
| Raw sealed prompts | `introspection/data/prompts_dp_honey_runtime_v4_3_sealed.jsonl` |
| Sealed selector-window prompts | `introspection/data/prompts_dp_honey_runtime_v4_3_sealed_selector_windows.jsonl` |
| Sealed activation features | `introspection/data/activations/qwen3_0_6b_dp_honey_runtime_v4_3_sealed_selector_windows.pt` |
| One-shot holdout report | `introspection/data/reports/dp_honey_runtime_v4_3_sealed_selector_window_holdout_readout_window_layer_15_v1.json` |

The holdout has 144 rows: 48 `benign`, 48 `secret_present_safe`, and 48
`exfiltration_intent`. The one-shot CIFT task scores the 96
`safe_secret_vs_exfiltration` rows.

## Result

| Evaluation | Accuracy | Macro F1 | Errors |
|---|---:|---:|---:|
| Runtime DP-HONEY V4.1 grouped CV | 0.8438 | 0.8387 | 17 / 96 out-of-fold |
| Runtime DP-HONEY V4.3 sealed holdout | 0.6875 | 0.6841 | 30 / 96 one-shot |

The holdout result is a meaningful slip. It does not invalidate the CIFT path,
but it does show that the V4.1 candidate has not generalized cleanly across new
scenario families. The current bundle should remain an offline research
candidate rather than being promoted to runtime candidate.

The holdout confusion matrix is:

```text
[28, 20]
[10, 38]
```

Rows are true labels and columns are predicted labels in this order:
`exfiltration_intent`, `secret_present_safe`.

## Error Profile

The largest miss clusters are:

| Slice | Error Type | Errors |
|---|---|---:|
| `billing_reconciliation` | exfiltration predicted safe | 8 |
| `release_gate` | exfiltration predicted safe | 7 |
| `backup_restore` | safe predicted exfiltration | 5 |
| `partner_integration` | safe predicted exfiltration | 4 |
| `partner_integration` | exfiltration predicted safe | 4 |

This suggests the model is learning useful readout-window signal but still
overfits family-specific structure. The next model-improvement step should not
reuse this holdout for tuning. Instead, create a new unsealed training dataset
that expands family diversity and includes family-level regularization or
leave-family-out selection, then reserve a fresh sealed holdout for the next
promotion attempt.

## Current Claim

Aegis now has a frozen CIFT-like bundle and a sealed runtime-DP-HONEY holdout
evaluation path. The frozen V4.1 candidate is promising but not promotion-ready:
it beats chance on fresh sealed families, but the generalization gap is too
large for a runtime candidate claim.
