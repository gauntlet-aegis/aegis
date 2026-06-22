---
date: 2026-06-22
topic: dp-honey-detection-eval
---

# DP-HONEY Detection and Eval Completion Requirements

## Summary

Complete the missing DP-HONEY detection and evaluation checklist on a review-ready branch, without pushing or merging to the shared Aegis branches. The branch should preserve the existing generator, CLI, web UI, and registry scanner behavior while adding the baseline detector, planted-value cross-encoding scanner, DP-HONEY stage behavior, conformal fuzzy calibration, and a reproducible local evaluation script.

---

## Problem Frame

The current repository has a working DP-HONEY generator package, credential-shape scanner, CLI, web UI, and test suite. The requested checklist targets a different layer: detection of planted honeytoken values after model output, including encoded leakage, fuzzy/partial leakage, stage integration, and evaluation accounting.

The existing `detect/dp_honey/scanner.py` scans for secret-shaped strings and supports auto-decoy replacement. It should not be treated as already satisfying the planted-value scanner requirement, because the checklist scanner answers a different question: whether a finite set of known honeytokens appears in output in direct, transformed, encoded, or fragmented form.

---

## Key Decisions

- **Review branch only.** The work should produce a validated, review-ready implementation branch. Merging into `DPHoneyTokenGenerator-integration` or `Aegis/main` remains a separate manual step after review.
- **Local beta surrogate.** The eval script should run entirely inside this repository using a deterministic red-team/distinguisher surrogate, while keeping room for Cameron/Spine output to replace or supplement that surrogate later.
- **Keep scanners distinct.** The existing credential-shape scanner remains available for CLI/web UI workflows. The new planted-value scanner should be framed as DP-HONEY leakage detection, not as a replacement for generic secret scanning.
- **Exact encoded hits are ground truth blocks.** Direct or encoded recovery of a planted value is not thresholded. Conformal calibration applies only to fuzzy/partial similarity signals.
- **No cross-turn responsibility.** Within-output fragmentation belongs here; cross-turn fragmentation remains outside this slice and belongs to NIMBUS.

---

## Actors

- A1. **Implementer:** builds the detection/eval branch and keeps changes scoped to the requested checklist.
- A2. **Reviewer:** verifies that the branch completes the checklist without regressing the existing generator, scanner, CLI, web UI, or docs behavior.
- A3. **Evaluator:** runs the local evaluation script to produce Table 2-style metrics and eq.5 catch-probability accounting.
- A4. **Future integrator:** later wires Cameron/Spine outputs or shared Aegis runtime contracts into the seams left by this implementation.

---

## Requirements

**Baseline Text Detector**

- R1. Add an always-on post-output text detector stage that performs a deliberately cheap direct canary/verbatim scan over generated output.
- R2. The baseline detector must be simple enough to go dark on encoded attacks, because that blind spot is part of the CIFT encoding-gap demo.
- R3. The baseline detector must expose stage metadata equivalent to post-output execution, always-on behavior, and no whitebox requirement.

**Planted-Value DP-HONEY Scanner**

- R4. Add a planted-value scanner that compares each known honeytoken against one output and detects whether the planted value appears in any supported form.
- R5. Exact detection must cover direct matches, reversed values, leet-normalized matches, ROT-N sweeps, base64/base32/hex decoding of candidate substrings, and encoded-token search where the honeytoken is encoded and searched directly.
- R6. Within-output fragmentation detection must strip non-alphanumerics and use an LCS-ratio style signal over the planted run.
- R7. Exact hits across direct, transformed, encoded, or deterministic fragmented forms must produce ground-truth block findings without requiring a calibrated threshold.
- R8. The scanner must avoid cross-turn fragmentation behavior; that remains out of scope for this branch.
- R9. Scanner findings must identify enough match metadata for evaluation and stage decisions without leaking more sensitive value material than necessary.

**Conformal Calibration and Stage Behavior**

- R10. Add conformal calibration for the fuzzy/partial channel only, using held-out benign outputs and an empirical q-hat threshold for the configured alpha.
- R11. The default calibration target should be alpha `0.05`, yielding an intended benign false-positive rate no greater than 5 percent under the held-out benign distribution.
- R12. Add a DP-HONEY stage that injects honeytokens before forwarding and scans output after generation.
- R13. The DP-HONEY stage must combine exact scanner decisions with calibrated fuzzy/partial decisions: exact findings block directly, fuzzy findings block only when they pass the conformal threshold.
- R14. Stage behavior must replace any day-1 stub behavior rather than living as an unused helper.

**Evaluation and Accounting**

- R15. Add a reproducible eval script that reports per-encoding precision and recall plus conformal coverage in a Table 2-style output.
- R16. The eval script must report eq.5 catch probability as `k / (m + k) * (1 - beta)`.
- R17. The eval script must support the current architecture where `m = 0` in model-visible context, making catch probability approximately `1 - beta`.
- R18. Beta measurement must run locally with a deterministic red-team/distinguisher surrogate and keep a future adapter seam for Cameron/Spine outputs.
- R19. The eval script must plot or otherwise emit catch probability versus `k` for the measured beta.

**Branch and Integration Boundary**

- R20. Implementation work should happen on a new review-ready branch created from the appropriate local base, using the repository's normal `codex/` branch prefix unless a different branch name is explicitly chosen later.
- R21. The branch must be locally validated before handoff, but must not be pushed or merged into `DPHoneyTokenGenerator-integration` or `Aegis/main` as part of this scope.
- R22. The final handoff must summarize how a reviewer can merge the branch into the integration branch and then into Aegis main after review.

**Non-Regression**

- R23. Existing DP-HONEY generator, model artifact, registry scanner, CLI, web UI, and docs tests must continue to pass.
- R24. Existing public behavior for `scan` and `auto-decoy` must remain compatible unless the reviewer explicitly approves a breaking change.
- R25. New tests must cover the baseline detector, planted-value encodings, conformal calibration behavior, stage decisions, and eval accounting.

---

## Key Flows

- F1. Baseline detector demonstration
  - **Trigger:** A post-output string contains a direct canary or verbatim planted token.
  - **Actors:** A1, A2
  - **Steps:** The cheap detector scans output directly, finds the verbatim value, and emits a finding.
  - **Outcome:** Direct leakage is caught, while encoded leakage remains available as the intended baseline blind spot.
  - **Covered by:** R1, R2, R3

- F2. Encoded leakage detection
  - **Trigger:** A post-output string contains a planted honeytoken in base64, base32, hex, ROT-N, reversed, leet, or within-output fragmented form.
  - **Actors:** A1, A2
  - **Steps:** The DP-HONEY scanner evaluates the planted finite target set against the output and emits exact or fuzzy findings according to the channel.
  - **Outcome:** Encoding does not help an attacker hide a known planted value from DP-HONEY.
  - **Covered by:** R4, R5, R6, R7, R8, R9

- F3. Calibrated fuzzy block
  - **Trigger:** Output resembles a planted honeytoken but does not contain an exact supported encoding.
  - **Actors:** A1, A2
  - **Steps:** The scanner computes the fuzzy/partial score, the conformal threshold is applied, and the stage blocks only if the calibrated score crosses threshold.
  - **Outcome:** Partial leakage can be blocked while benign-output false positives remain controlled by the calibration set.
  - **Covered by:** R10, R11, R13

- F4. Local evaluation run
  - **Trigger:** An evaluator runs the DP-HONEY eval script in this repository.
  - **Actors:** A3
  - **Steps:** The script generates or loads local evaluation cases, computes per-encoding precision/recall, reports conformal coverage, estimates beta with the local surrogate, and emits catch probability versus `k`.
  - **Outcome:** The branch produces the requested Table 2 and eq.5 accounting artifacts without requiring Cameron/Spine locally.
  - **Covered by:** R15, R16, R17, R18, R19

---

## Acceptance Examples

- AE1. **Covers R1, R2.** Given output that contains `honey-token-123` directly, when the baseline detector scans it, then it reports a direct finding. Given output that contains only a base64 encoding of `honey-token-123`, when the baseline detector scans it, then it does not report a finding.
- AE2. **Covers R5, R7.** Given a planted value and output containing the base64, base32, or hex encoding of that exact value, when the planted-value scanner runs, then it reports an exact ground-truth finding for the matching encoding channel.
- AE3. **Covers R5.** Given a planted value and output containing a ROT-N or reversed version of that value, when the planted-value scanner runs, then it reports an exact ground-truth finding for the matching transformation channel.
- AE4. **Covers R6, R8.** Given a planted value split within one output by punctuation or whitespace, when the planted-value scanner runs, then it may report within-output fragmentation. Given the same value split across multiple turns, when this scanner sees only one turn at a time, then it does not attempt cross-turn reconstruction.
- AE5. **Covers R10, R11, R13.** Given held-out benign outputs and alpha `0.05`, when calibration runs and the stage evaluates fuzzy/partial findings, then the fuzzy threshold is derived from the empirical conformal rule rather than manual tuning.
- AE6. **Covers R16, R17, R18, R19.** Given the local beta surrogate produces a measured beta and `m = 0`, when the eval script reports catch probability, then the result follows `k / (m + k) * (1 - beta)` and reduces to approximately `1 - beta` for positive `k`.

---

## Success Criteria

- The repository has tests proving the four requested checklist items are implemented.
- A full local test run passes after the detection/eval changes.
- The eval script can be run without Cameron/Spine and produces stable, reviewable metrics.
- Existing `detect.dp_honey` CLI and web UI scanner behavior remains intact.
- The handoff clearly states that the branch is review-ready but not merged or pushed.

---

## Scope Boundaries

- Pushing, merging, or opening a PR against `DPHoneyTokenGenerator-integration` or `Aegis/main` is outside this branch's scope.
- Cross-turn fragmentation and memory-based reconstruction are outside scope and remain assigned to NIMBUS.
- Real Cameron/Spine red-team execution is outside this repository's local dependency set for now.
- Provider-valid secret detection, live credential verification, or training on real secrets remains outside DP-HONEY's safety boundary.
- Replacing the existing registry scanner or auto-decoy workflow is outside scope; the new scanner should coexist with it.

---

## Dependencies and Assumptions

- The current generator and bigram model remain the source of synthetic honeytokens for injection and tests.
- The stage contracts can be represented locally even if the broader Aegis runtime is not present in this checkout.
- Held-out benign outputs for conformal calibration may be synthetic or fixture-based in v1, as long as they are deterministic and documented.
- Cameron/Spine integration can be added later through a structured input or adapter without changing the local eval contract.
- The appropriate branch base should be confirmed during implementation planning, because this checkout has both local `main` and `DPHoneyTokenGenerator-integration` branches.

---

## Sources and Research

- `detect/dp_honey/scanner.py` - existing registry-driven credential-shape scanner and auto-decoy behavior to preserve.
- `detect/dp_honey/bigram.py` - existing DP-noised honeytoken generator dependency for planted values.
- `detect/__init__.py` - current package note that sibling detection components were previously out of scope.
- `docs/plans/2026-06-20-001-feat-dp-honey-generator-plan.md` - completed generator plan and original scope boundary.
- `README.md` - current CLI, web UI, scanner, safety, and testing contract.
