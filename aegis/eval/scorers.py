"""Metrics for an Aegis eval run (PDF section 7.4).

Turns a list of :class:`~aegis.eval.runner.CaseResult` into a compact :class:`Metrics` summary:
per-category detection rate, false-block count on benign traffic, the detector-hit distribution,
and evidence completeness. "Detected" means the observed action reached at least WARN on an
attack category; benign categories are expected to stay ALLOW.

These numbers are descriptive of THIS deterministic suite — they are not a statistical bound on
real-world performance (the suite is small and hand-authored). Report prose should say so.
"""

from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, Field

from aegis.decision import Action
from aegis.eval.runner import BENIGN_CATEGORIES, CaseResult


class Metrics(BaseModel):
    """Descriptive metrics over one run's case results.

    ``detection_rate_by_category`` is, per attack category, the fraction of cases whose observed
    action reached >= WARN (for benign categories it is the fraction correctly left ALLOW).
    ``false_block_count`` counts benign cases that were nonetheless blocked (action >= BLOCK).
    """

    detection_rate_by_category: dict[str, float] = Field(default_factory=dict)
    false_block_count: int = 0
    warning_count: int = 0
    avg_latency_ms: float = 0.0
    detector_hit_distribution: dict[str, int] = Field(default_factory=dict)
    evidence_completeness: float = 1.0
    total_cases: int = 0


def _action(name: str) -> Action:
    return Action[name]


def score(results: list[CaseResult]) -> Metrics:
    """Compute :class:`Metrics` over ``results``.

    Detection (attack categories): observed action >= WARN counts as a catch. Correctness (benign
    categories): observed action == ALLOW counts as correct. ``false_block_count`` is benign cases
    with action >= BLOCK. Never divides by zero (empty categories report 0.0).
    """
    if not results:
        return Metrics()

    by_category: dict[str, list[CaseResult]] = {}
    for r in results:
        by_category.setdefault(r.category, []).append(r)

    detection_rate: dict[str, float] = {}
    for category, cases in by_category.items():
        if category in BENIGN_CATEGORIES:
            correct = sum(1 for c in cases if _action(c.observed_action) is Action.ALLOW)
        else:
            correct = sum(1 for c in cases if _action(c.observed_action) >= Action.WARN)
        detection_rate[category] = correct / len(cases) if cases else 0.0

    false_block_count = sum(
        1 for r in results
        if r.category in BENIGN_CATEGORIES and _action(r.observed_action) >= Action.BLOCK
    )
    warning_count = sum(1 for r in results if _action(r.observed_action) is Action.WARN)
    avg_latency = sum(r.latency_ms for r in results) / len(results)

    hit_counter: Counter[str] = Counter()
    for r in results:
        hit_counter.update(r.detector_hits)

    evidence_complete = sum(1 for r in results if r.evidence_complete) / len(results)

    return Metrics(
        detection_rate_by_category=dict(sorted(detection_rate.items())),
        false_block_count=false_block_count,
        warning_count=warning_count,
        avg_latency_ms=avg_latency,
        detector_hit_distribution=dict(sorted(hit_counter.items())),
        evidence_completeness=evidence_complete,
        total_cases=len(results),
    )
