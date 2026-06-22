# Edge Cases — Findings & Remediation

Scope: the Aegis runtime credential-defense **core** (non-UI) — detectors, broker, honeytokens,
policy, taint, pipeline, sdk, gateway, providers. Date: 2026-06-22.

Surface map: trust boundaries are the three SDK guards (`guard_request`/`guard_tool_call`/
`guard_response`) and the FastAPI gateway `POST /v1/chat/completions`. Untrusted input = chat
messages, model output, and (critically) model-emitted tool-call arguments. Sinks = the forwarded
tool call, the returned response text, and the JSONL trace. External dep = the model provider.
Shared state = the per-session `LeakageLedger` and the `HoneytokenRegistry`.

Categories walked: input/length, encoding/normalization, idempotency/duplicates, concurrency/state,
resource/DoS (ReDoS, recursion, memory), failure/error-paths, security/exfiltration, type-confusion,
data-integrity, config/environment-drift. (Time/date and UI categories N/A to this layer.)

Enumeration: three read-only sub-agents, each repro'ing candidates by running Python against the
code. Triage + fixes by the main thread. Regression tests in `tests/test_edge_cases.py` (17 tests).

## Findings (critical → low)

### EC-1 — Opaque store secret in a tool-call argument bypassed the marquee defense  [critical | high]
- **Category:** security / exfiltration. **Location:** `pipeline.py` broker guard ran only on
  REQUEST/RESPONSE; `tool_call_args` matched only credential *shapes*.
- **Trigger:** `guard_tool_call("send_email", {"body": <raw store secret with no shape>})`.
- **Impact:** the exact marquee attack (steered agent smuggling a broker secret out via a tool call)
  was ALLOWED and forwarded.
- **Remediation:** broker guard now also runs on TOOL_CALL (`pipeline.py`). **Status:** fixed.
  **Verified:** `test_opaque_store_secret_in_tool_arg_is_caught` (now ESCALATE).

### EC-2 — Deeply nested tool args crashed the guard (RecursionError)  [high | medium]
- **Category:** resource / never-crash. **Location:** `events.py` `_flatten` (unbounded recursion).
- **Trigger:** ~1k+-deep nested dict in tool arguments → `RecursionError` → gateway 500.
- **Remediation:** depth-bounded `_flatten` (`_MAX_FLATTEN_DEPTH=60`; deeper structure stringified).
  **Status:** fixed. **Verified:** `test_deeply_nested_tool_args_do_not_crash`.

### EC-3 — Unicode (zero-width / homoglyph) splitting evaded all shape detectors  [high | high]
- **Category:** encoding/normalization. **Location:** `secret_pattern.find_secrets`,
  `encoding.decodings` (no NFKC).
- **Remediation:** new `detectors/normalize.py` (`nfkc_strip`); both normalize before scanning;
  `decodings` adds the normalized form; honeytoken match normalizes too. **Status:** fixed.
  **Verified:** `test_zero_width_spliced_secret_is_detected`, `test_nfkc_collapses_homoglyphs`.

### EC-4 — Double/triple base64 encoding evaded the encoding scanner  [high | med]
- **Category:** encoding. **Location:** `encoding.decodings` nesting bounded at depth 1.
- **Remediation:** nesting raised to `_MAX_DECODE_DEPTH=2` (still [:8]-fan-out bounded).
  **Status:** fixed. **Verified:** `test_double_encoded_secret_is_decoded`.

### EC-5 — Secret chunked across tool-arg leaves evaded the marquee scanner  [high | med]
- **Category:** input/security. **Location:** `tool_call_args` per-leaf scan only.
- **Trigger:** `body=[secret[:13], secret[13:]]` — each leaf benign, reconstructs when joined.
- **Remediation:** per-field reconstruction scan (multi-leaf fields concatenated and re-scanned).
  **Status:** fixed. **Verified:** `test_secret_chunked_across_tool_args_is_caught`.
  **Residual:** a secret split across two *different named* fields is not reconstructed (rare) —
  accepted; noted here.

### EC-6 — Broker over-redaction / false ESCALATE on a 1–2 char store secret  [high | med]
- **Category:** length boundary / masking. **Location:** `broker.scan_model_visible`, `trace.redact`.
- **Remediation:** min-length floor (≥4) before substring leak-match and before redaction.
  **Status:** fixed. **Verified:** `test_broker_short_store_secret_does_not_false_escalate`,
  `test_redact_skips_short_secret`.

### EC-7 — Provider exception returned a bare gateway 500  [medium | high]
- **Category:** external failure. **Location:** `gateway/app.py` provider call unwrapped.
- **Remediation:** wrapped `provider.complete` → graceful refusal with `provider_error: true`.
  **Status:** fixed. **Verified:** `test_gateway_provider_error_is_graceful`.

### EC-8 — SDK guards raised on malformed input instead of returning a decision  [medium | med]
- **Category:** type confusion / never-crash. **Location:** `sdk.py` (strict pydantic event build).
- **Trigger:** `guard_request(None)`, `guard_response(123)`, `guard_tool_call("t", ["a"])`.
- **Remediation:** input normalization (`_norm_messages`/`_norm_args`/coerce) + last-resort
  `_fail_safe` (WARN + reason). **Status:** fixed. **Verified:** `test_sdk_guards_never_raise_on_malformed_input`.

### EC-9 — AWS-secret false positives on 40-char hex digests (SHA) near a cue word  [medium | med]
- **Category:** input precision. **Location:** `secret_pattern` 40-char rule.
- **Remediation:** exclude all-hex 40-char runs (`_HEX_40`). **Status:** fixed.
  **Verified:** `test_hex_digest_is_not_an_aws_secret` + `test_real_base64_secret_near_cue_still_matches`.

### EC-10 — Non-positive ledger budget silently disabled the detector  [medium | low-med]
- **Category:** config drift / fail-open. **Location:** `ledger.LeakageLedger.__init__`.
- **Remediation:** clamp `budget <= 0` to 1.0 (fail-safe, still detecting). **Status:** fixed.
  **Verified:** `test_ledger_nonpositive_budget_still_detects`.

### EC-11 — Unbounded per-session ledger state growth  [medium | med]
- **Category:** resource/memory. **Location:** `ledger` `_sessions` never evicted.
- **Remediation:** FIFO cap (`_MAX_SESSIONS=50_000`). **Status:** fixed. **Verified:** logic review
  (cap not load-tested in CI to keep the suite fast).

### EC-12 — Honeytoken registry dropped canaries on identical fmt+seed (collision)  [medium | low]
- **Category:** idempotency/duplicate keys. **Location:** `registry.register` (deterministic seed).
- **Remediation:** per-registration counter mixed into the seed → distinct tokens. **Status:** fixed.
  **Verified:** `test_registry_no_collision_on_same_fmt_and_seed`.

### EC-13 — Short/dictionary honeytoken canary caused benign false matches  [low | low]
- **Remediation:** substring match floored at `_MIN_CANARY_LEN=8`. **Status:** fixed.
  **Verified:** `test_short_canary_does_not_false_match`.

### EC-14 — JWT canary never matched the JWT shape/hygiene pattern  [low | med]
- **Remediation:** generator forces an `eyJ` header segment. **Status:** fixed.
  **Verified:** `test_jwt_canary_matches_shape`.

### EC-15 — redact() raised on non-string scalars  [low | low]
- **Remediation:** non-string input returned unchanged. **Status:** fixed.
  **Verified:** `test_redact_tolerates_non_string`.

### EC-16 — Live ClaudeProvider forwarded system-role messages (Anthropic API 400)  [low | med]
- **Remediation:** `complete()` hoists system messages into the `system=` param. **Status:** fixed.
  **Verified:** code review (live-path only; `anthropic` not installed offline).

## Declined (with reasons)

- **Session-id rotation defeats the cumulative budget** (rated critical by the enumerator):
  inherent to per-session accounting (same assumption as the NIMBUS research). The session id is
  assigned by the host, not attacker-controlled per turn; binding it is out of scope. **Declined —
  documented limitation** (already in README/claim-discipline).
- **Bare 40-char AWS secret with no cue word and no AKIA pairing is not flagged:** intentional
  false-positive/false-negative tradeoff; partially mitigated by the hex-exclusion (EC-9). Tightening
  it further would re-introduce the SHA/nonce FPs. **Declined — accepted tradeoff.**
- **Empty-spans provenance defaults to TRUSTED** (`taint.provenance_of`): cosmetic only — provenance
  affects a confidence value and a reason string, never the BLOCK decision (a credential in an exfil
  sink blocks regardless). The SDK does not yet thread request spans into tool-call events.
  **Declined — documented; safe to revisit when spans are threaded through.**
- **bytes/None argument values are stringified, not natively scanned:** never crashes; the wrapper
  string is still scanned. **Declined — cosmetic.**
- **LeakageLedger shares a mutable dict without a lock:** single-threaded by construction in the SDK
  path; no race reproduced. **Declined — documented concern if run multi-threaded.**
- **runtime_checkable Provider accepts wrong-signature objects:** Python Protocol limitation, not an
  Aegis bug. **Declined.**

## Dropped candidates (false positives)
- ReDoS in secret/bearer/connection-string regexes — all linear; 400k-char inputs < 10 ms.
- Oversized-input hang in `decodings`/`find_secrets` — linear (~0.5 s/MB), nesting bounded.
- Detector raising mid-pipeline — already swallowed (records SKIPPED, still returns a decision).
- Secret leakage in reasons/evidence/gateway body — none; previews only, refusals never echo.
- Broker mode-bypass invariant — correct (raw store secret ESCALATEs in observe AND balanced).
