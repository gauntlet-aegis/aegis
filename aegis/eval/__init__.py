"""Aegis evaluation harness (PDF section 7).

An offline, deterministic test bench that drives benign + attack scenarios through the real Aegis
SDK guards and produces metrics plus a baseline-vs-protected comparison (local JSONL + Markdown).
No network, no Braintrust (optional opt-in only), no ML.

Pipeline: :func:`load_scenarios` -> :func:`run_suite` (per posture) -> :func:`score` ->
:func:`write_report`. "Baseline" is observe mode (the vulnerable agent that records but never
blocks); "protected" is balanced mode (enforcement on). The contrast is the deliverable.
"""

from __future__ import annotations

from aegis.eval.braintrust import maybe_log_braintrust
from aegis.eval.report import write_report
from aegis.eval.runner import (
    BENIGN_CATEGORIES,
    CaseResult,
    Scenario,
    load_scenarios,
    run_suite,
)
from aegis.eval.scorers import Metrics, score

__all__ = [
    "load_scenarios",
    "run_suite",
    "score",
    "write_report",
    "maybe_log_braintrust",
    "Scenario",
    "CaseResult",
    "Metrics",
    "BENIGN_CATEGORIES",
]
