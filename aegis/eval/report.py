"""Local artifact writer for the Aegis eval (PDF section 7.4 — the Demo Metrics Table).

Writes two files into ``out_dir`` (created if needed), purely local, no network:

- ``results.jsonl`` — one JSON line per case across BOTH runs (baseline + protected), for
  downstream inspection or a hosted trail.
- ``report.md``     — the baseline-vs-protected comparison: a per-category table (Baseline Result
  vs Aegis Result vs Evidence) plus a summary metrics block for each posture.

"Baseline" is observe mode (records, never blocks — the vulnerable agent); "protected" is balanced
mode (enforcement on). The contrast is the whole point: same detectors, same rules, only the mode
differs, and only the protected run stops the hard attacks.

HONEST FRAMING: the leakage-budget signal is a learned suspicion heuristic, not a measured bound on
leaked secret bits; the report prose says so rather than overclaiming.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.decision import Action
from aegis.eval.runner import BENIGN_CATEGORIES, CaseResult
from aegis.eval.scorers import Metrics

# A short, honest caveat carried into every report so the numbers are never read as a bound.
_CLAIM_DISCIPLINE = (
    "Metrics are descriptive of this small, deterministic offline suite, not a statistical bound "
    "on real-world performance. The NIMBUS leakage budget is a learned suspicion signal (a "
    "cumulative heuristic), not a measured count of leaked secret bits."
)


def _write_jsonl(path: Path, baseline: list[CaseResult], protected: list[CaseResult]) -> None:
    """One line per case across both runs; each line tags its ``run`` for downstream filtering."""
    with path.open("w", encoding="utf-8") as fh:
        for run_name, results in (("baseline", baseline), ("protected", protected)):
            for r in results:
                row = r.model_dump()
                row["run"] = run_name
                fh.write(json.dumps(row, sort_keys=True) + "\n")


def _category_rows(baseline: list[CaseResult],
                   protected: list[CaseResult]) -> list[tuple[str, str, str, str]]:
    """Build per-category (category, baseline-result, aegis-result, evidence) table rows.

    Aggregates each category to its most-severe observed action under each posture, so the table
    reads as "what did the baseline do vs what did Aegis do" at a glance.
    """
    base_by_cat: dict[str, list[CaseResult]] = {}
    prot_by_cat: dict[str, list[CaseResult]] = {}
    for r in baseline:
        base_by_cat.setdefault(r.category, []).append(r)
    for r in protected:
        prot_by_cat.setdefault(r.category, []).append(r)

    rows: list[tuple[str, str, str, str]] = []
    for category in sorted(set(base_by_cat) | set(prot_by_cat)):
        base_cases = base_by_cat.get(category, [])
        prot_cases = prot_by_cat.get(category, [])
        base_action = max((Action[c.observed_action] for c in base_cases), default=Action.ALLOW)
        prot_action = max((Action[c.observed_action] for c in prot_cases), default=Action.ALLOW)

        # Evidence: a representative reason from the protected run (or "clean" if it allowed).
        evidence = "clean — allowed"
        for c in prot_cases:
            if c.reasons:
                evidence = c.reasons[0]
                break

        base_label = _result_label(category, base_action)
        prot_label = _result_label(category, prot_action)
        rows.append((category, base_label, prot_label, evidence))
    return rows


def _result_label(category: str, action: Action) -> str:
    """Human-readable cell: name the action and editorialize benign vs attack outcome."""
    if category in BENIGN_CATEGORIES:
        ok = "✓ correct" if action is Action.ALLOW else "✗ FALSE POSITIVE"
        return f"{action.name} ({ok})"
    # Attack category: a leak gets through only if it stayed ALLOW.
    if action is Action.ALLOW:
        return "ALLOW (✗ leaked)"
    return f"{action.name} (✓ caught)"


def _metrics_block(title: str, m: Metrics) -> list[str]:
    """Render a Metrics summary as Markdown lines."""
    lines = [f"### {title}", ""]
    lines.append(f"- Total cases: **{m.total_cases}**")
    lines.append(f"- False blocks on benign traffic: **{m.false_block_count}**")
    lines.append(f"- Warnings: **{m.warning_count}**")
    lines.append(f"- Avg latency: **{m.avg_latency_ms:.3f} ms**")
    lines.append(f"- Evidence completeness: **{m.evidence_completeness:.0%}**")
    lines.append("")
    lines.append("Detection rate by category:")
    lines.append("")
    lines.append("| Category | Rate |")
    lines.append("| --- | --- |")
    for cat, rate in m.detection_rate_by_category.items():
        lines.append(f"| {cat} | {rate:.0%} |")
    lines.append("")
    if m.detector_hit_distribution:
        lines.append("Detector hit distribution: " +
                     ", ".join(f"`{k}`×{v}" for k, v in m.detector_hit_distribution.items()))
        lines.append("")
    return lines


def write_report(baseline_results: list[CaseResult], protected_results: list[CaseResult],
                 metrics_baseline: Metrics, metrics_protected: Metrics,
                 out_dir: str | Path) -> dict[str, Path]:
    """Write ``results.jsonl`` + ``report.md`` into ``out_dir`` and return their paths.

    Pure local I/O: creates ``out_dir`` if missing. The Markdown is the PDF 7.4 Demo Metrics
    Table (Baseline vs Aegis, per category) plus a summary metrics block per posture.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "results.jsonl"
    md_path = out_dir / "report.md"

    _write_jsonl(jsonl_path, baseline_results, protected_results)

    lines: list[str] = [
        "# Aegis Evaluation — Baseline vs Protected",
        "",
        "**Baseline** = observe mode (records, never blocks — the vulnerable agent). "
        "**Protected** = balanced mode (enforcement on). Same detectors, same policy rules; "
        "only the deployment posture differs.",
        "",
        f"> {_CLAIM_DISCIPLINE}",
        "",
        "## Demo Metrics Table (per category)",
        "",
        "| Scenario Category | Baseline Result | Aegis Result | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for category, base_label, prot_label, evidence in _category_rows(baseline_results,
                                                                     protected_results):
        # Escape pipes in evidence so the table stays well-formed.
        ev = evidence.replace("|", "\\|")
        lines.append(f"| {category} | {base_label} | {prot_label} | {ev} |")

    lines.append("")
    lines.append("## Summary Metrics")
    lines.append("")
    lines.extend(_metrics_block("Baseline (observe)", metrics_baseline))
    lines.extend(_metrics_block("Protected (balanced)", metrics_protected))

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"jsonl": jsonl_path, "markdown": md_path}
