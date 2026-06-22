#!/usr/bin/env python
"""Run the full evaluation suite and write artifacts (PDF section 7).

Drives every scenario through a baseline (observe) and protected (balanced) agent, scores both,
and writes ``artifacts/eval/results.jsonl`` + ``artifacts/eval/report.md`` (the baseline-vs-protected
demo metrics table). Fully offline; Braintrust is logged only if BRAINTRUST_API_KEY is set.
"""

from __future__ import annotations

from pathlib import Path

from aegis.eval import load_scenarios, run_suite, score, write_report
from aegis.eval.braintrust import maybe_log_braintrust
from aegis.policy.schema import Mode

SCENARIO_DIR = "aegis/eval/scenarios"
OUT_DIR = Path("artifacts/eval")


def main() -> None:
    scenarios = load_scenarios(SCENARIO_DIR)
    baseline = run_suite(scenarios, mode=Mode.OBSERVE)
    protected = run_suite(scenarios, mode=Mode.BALANCED)
    m_base, m_prot = score(baseline), score(protected)

    write_report(baseline, protected, m_base, m_prot, OUT_DIR)
    maybe_log_braintrust(protected)

    print(f"Scenarios: {len(scenarios)}")
    print("Category                    detection(protected)")
    for cat, rate in sorted(m_prot.detection_rate_by_category.items()):
        print(f"  {cat:<26} {rate:.0%}")
    print(f"False blocks   baseline={m_base.false_block_count}  protected={m_prot.false_block_count}")
    print(f"Avg latency    {m_prot.avg_latency_ms:.2f} ms/turn")
    print(f"Evidence complete: {m_prot.evidence_completeness:.0%}")
    print(f"Artifacts: {OUT_DIR}/results.jsonl, {OUT_DIR}/report.md")


if __name__ == "__main__":
    main()
