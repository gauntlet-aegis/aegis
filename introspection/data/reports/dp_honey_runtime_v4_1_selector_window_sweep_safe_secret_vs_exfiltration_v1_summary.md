# Binary Layer Sweep

## Source

- Model: `Qwen/Qwen3-0.6B`
- Revision: `main`
- Extraction device: `mps`
- Evaluation strategy: `stratified_group_kfold`
- Task: `safe_secret_vs_exfiltration`
- Reference feature: `readout_window_layer_15`
- Best feature: `readout_window_layer_15`
- Feature count: `29`

## Feature Ranking

| Rank | Feature | Macro F1 | Accuracy | Macro F1 Std | Accuracy Std |
|---:|---|---:|---:|---:|---:|
| 1 | `readout_window_layer_15` (reference) | 0.8387 | 0.8438 | 0.0789 | 0.0740 |
| 2 | `readout_window_layer_17` | 0.7541 | 0.7625 | 0.0829 | 0.0829 |
| 3 | `readout_window_layer_18` | 0.7124 | 0.7312 | 0.0952 | 0.0781 |
| 4 | `readout_window_layer_14` | 0.6955 | 0.7250 | 0.1213 | 0.0848 |
| 5 | `readout_window_layer_19` | 0.6151 | 0.6687 | 0.1647 | 0.1075 |
| 6 | `readout_window_layer_16` | 0.5833 | 0.6375 | 0.1388 | 0.0829 |
| 7 | `readout_window_layer_20` | 0.5222 | 0.6062 | 0.1589 | 0.0960 |
| 8 | `readout_window_layer_21` | 0.5032 | 0.5687 | 0.1223 | 0.0637 |
| 9 | `readout_window_layer_13` | 0.4691 | 0.5437 | 0.0159 | 0.0250 |
| 10 | `readout_window_layer_23` | 0.4680 | 0.5375 | 0.0755 | 0.0500 |
| 11 | `readout_window_layer_05` | 0.4663 | 0.5188 | 0.1216 | 0.1111 |
| 12 | `readout_window_layer_07` | 0.4431 | 0.5125 | 0.0783 | 0.0468 |
| 13 | `readout_window_layer_12` | 0.4390 | 0.5375 | 0.1076 | 0.0500 |
| 14 | `readout_window_layer_22` | 0.4328 | 0.5250 | 0.0859 | 0.0306 |
| 15 | `readout_window_layer_09` | 0.4317 | 0.5062 | 0.1172 | 0.0637 |
| 16 | `readout_window_layer_08` | 0.4234 | 0.5062 | 0.0942 | 0.0415 |
| 17 | `readout_window_layer_10` | 0.4136 | 0.5062 | 0.0708 | 0.0125 |
| 18 | `readout_window_layer_11` | 0.4123 | 0.4875 | 0.1167 | 0.0919 |
| 19 | `readout_window_layer_03` | 0.4023 | 0.4688 | 0.0878 | 0.0625 |
| 20 | `readout_window_layer_26` | 0.3815 | 0.4750 | 0.0493 | 0.0637 |
| 21 | `readout_window_layer_02` | 0.3695 | 0.4625 | 0.0474 | 0.0637 |
| 22 | `readout_window_layer_01` | 0.3660 | 0.4562 | 0.0767 | 0.0829 |
| 23 | `readout_window_layer_06` | 0.3636 | 0.4437 | 0.0948 | 0.0696 |
| 24 | `readout_window_layer_25` | 0.3612 | 0.4562 | 0.0689 | 0.0781 |
| 25 | `readout_window_layer_04` | 0.3604 | 0.4188 | 0.0827 | 0.0960 |
| 26 | `readout_window_layer_24` | 0.3587 | 0.4750 | 0.0336 | 0.0306 |
| 27 | `readout_window_layer_28` | 0.3397 | 0.4750 | 0.0127 | 0.0500 |
| 28 | `readout_window_layer_27` | 0.3009 | 0.4375 | 0.0517 | 0.0968 |
| 29 | `readout_window_layer_00` | 0.0667 | 0.1000 | 0.1333 | 0.2000 |

## Top Confusion Matrices

### 1. readout_window_layer_15

```text
[37, 11]
[6, 42]
```

### 2. readout_window_layer_17

```text
[36, 12]
[13, 35]
```

### 3. readout_window_layer_18

```text
[32, 16]
[11, 37]
```

### 4. readout_window_layer_14

```text
[32, 16]
[10, 38]
```

### 5. readout_window_layer_19

```text
[32, 16]
[16, 32]
```

### 6. readout_window_layer_16

```text
[27, 21]
[14, 34]
```

### 7. readout_window_layer_20

```text
[27, 21]
[18, 30]
```

### 8. readout_window_layer_21

```text
[26, 22]
[20, 28]
```

### 9. readout_window_layer_13

```text
[24, 24]
[20, 28]
```

### 10. readout_window_layer_23

```text
[28, 20]
[24, 24]
```
