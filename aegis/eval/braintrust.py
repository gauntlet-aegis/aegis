"""Optional hosted-trail logging to Braintrust (PDF section 7 — nice-to-have, never required).

This is a strict no-op unless BOTH conditions hold:
  1. ``BRAINTRUST_API_KEY`` is set in the environment, and
  2. the ``braintrust`` package is importable (lazy import — not a dependency of the eval).

The core eval (load → run → score → write_report) is fully local and offline; this module exists
only so a team that *wants* a hosted trail can opt in by setting the key and installing the SDK.
It must never raise into the run and never block an offline run. By default it does nothing.
"""

from __future__ import annotations

import os

from aegis.eval.runner import CaseResult


def maybe_log_braintrust(results: list[CaseResult], *, project: str = "aegis-eval") -> bool:
    """Best-effort hosted log of ``results`` to Braintrust; a no-op unless opted in.

    Returns True if it actually logged, False otherwise (key missing, package absent, or any
    error). Never raises — a failed hosted log must not fail the offline eval.
    """
    if not os.environ.get("BRAINTRUST_API_KEY"):
        return False
    try:
        import braintrust  # lazy: not a hard dependency of the eval.
    except ImportError:
        return False

    try:
        experiment = braintrust.init(project=project)
        for r in results:
            experiment.log(
                input={"scenario_id": r.scenario_id, "category": r.category, "mode": r.mode},
                output={"action": r.observed_action, "allowed": r.allowed},
                expected={"expected": r.expected},
                scores={"risk_score": r.risk_score, "evidence_complete": float(r.evidence_complete)},
                metadata={"reasons": r.reasons, "detector_hits": r.detector_hits,
                          "latency_ms": r.latency_ms},
            )
        experiment.flush()
        return True
    except Exception:
        # A hosted-trail failure must never break a local run.
        return False
