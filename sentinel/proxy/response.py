"""Graduated response — the proxy's Algorithm 1 (PRD §6.1).

Given the per-layer results, pick the single most-severe action and rewrite the output
accordingly: pass (untouched), warn (annotate), sanitize (redact), block (refusal stub).
Scores are never fused; we only take a max over actions.
"""

from __future__ import annotations

from sentinel.events.schema import Action, LayerResult, most_severe

REFUSAL_STUB = "[BLOCKED by Sentinel: potential credential exfiltration detected.]"
WARN_PREFIX = "[Sentinel warning: elevated leakage signal.]\n"


def decide(layers: list[LayerResult]) -> tuple[Action, str | None]:
    """Return (final_action, caught_by). caught_by names the highest-severity triggering layer."""
    final = most_severe([lr.action for lr in layers])
    caught_by = None
    if final != Action.PASS:
        # The first layer (in pipeline order) that emitted the winning action.
        for lr in layers:
            if lr.action == final:
                caught_by = lr.layer
                break
    return final, caught_by


def apply(action: Action, output: str) -> str:
    """Produce the client-facing output text for the final action.

    ``output`` is already the (possibly sanitized) text after the post-output stages ran.
    """
    if action == Action.BLOCK:
        return REFUSAL_STUB
    if action == Action.WARN:
        return WARN_PREFIX + output
    return output  # PASS or SANITIZE (already redacted upstream)
