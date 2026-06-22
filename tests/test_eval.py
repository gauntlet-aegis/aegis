"""Tests for the offline evaluation harness (PDF section 7).

Fully offline + deterministic: load scenarios, drive them through the real Aegis guards in both
postures, score, and write local artifacts. Asserts the core demo claim — Aegis (balanced) stops
the hard attacks while the baseline (observe) only records, with no false blocks on benign traffic.
"""

from __future__ import annotations

from aegis.decision import Action
from aegis.eval import (
    BENIGN_CATEGORIES,
    load_scenarios,
    run_suite,
    score,
    write_report,
)
from aegis.policy import Mode

# Attack categories whose hard cases the protected run must catch (>= WARN).
_ATTACK_CATEGORIES = {
    "encoded_single_turn",
    "multi_turn_drip",
    "tool_call_arg_exfil",
    "canary_touch",
}


def _action(name: str) -> Action:
    return Action[name]


def test_load_scenarios_finds_all_categories() -> None:
    scenarios = load_scenarios()
    assert scenarios, "expected scenarios to load"
    categories = {s.category for s in scenarios}
    # All seven PDF categories present.
    assert categories == (BENIGN_CATEGORIES | _ATTACK_CATEGORIES)
    # ids are unique.
    ids = [s.id for s in scenarios]
    assert len(ids) == len(set(ids))


def test_protected_catches_attacks_and_spares_benign() -> None:
    scenarios = load_scenarios()
    results = run_suite(scenarios, mode=Mode.BALANCED)
    by_id = {r.scenario_id: r for r in results}

    # Every attack case reaches at least WARN.
    for r in results:
        if r.category in _ATTACK_CATEGORIES:
            assert _action(r.observed_action) >= Action.WARN, (
                f"{r.scenario_id} should be detected, got {r.observed_action}"
            )

    # The marquee categories are HARD-stopped (>= BLOCK) on their representative cases.
    assert _action(by_id["tool_exfil_email_body"].observed_action) >= Action.BLOCK
    assert _action(by_id["encoded_base64_openai"].observed_action) >= Action.BLOCK
    assert _action(by_id["canary_in_response"].observed_action) is Action.ESCALATE

    # No benign case is blocked, and none even warns.
    for r in results:
        if r.category in BENIGN_CATEGORIES:
            assert _action(r.observed_action) is Action.ALLOW, (
                f"{r.scenario_id} false-positive: {r.observed_action}"
            )


def test_baseline_records_but_never_blocks() -> None:
    scenarios = load_scenarios()
    baseline = run_suite(scenarios, mode=Mode.OBSERVE)
    # Observe mode clamps everything at/above SANITIZE down to WARN: it can never block.
    for r in baseline:
        assert _action(r.observed_action) <= Action.WARN, (
            f"baseline must not enforce, but {r.scenario_id} -> {r.observed_action}"
        )


def test_baseline_vs_protected_difference() -> None:
    scenarios = load_scenarios()
    baseline = run_suite(scenarios, mode=Mode.OBSERVE)
    protected = run_suite(scenarios, mode=Mode.BALANCED)
    base_by_id = {r.scenario_id: r for r in baseline}
    prot_by_id = {r.scenario_id: r for r in protected}

    # The whole point: a hard attack the vulnerable baseline lets through is blocked when protected.
    for sid in ("tool_exfil_email_body", "encoded_base64_openai", "canary_in_response"):
        assert _action(base_by_id[sid].observed_action) <= Action.WARN
        assert _action(prot_by_id[sid].observed_action) >= Action.BLOCK


def test_score_returns_sane_metrics() -> None:
    scenarios = load_scenarios()
    protected = run_suite(scenarios, mode=Mode.BALANCED)
    m = score(protected)

    assert m.total_cases == len(protected)
    assert m.false_block_count == 0
    assert 0.0 <= m.evidence_completeness <= 1.0
    assert m.evidence_completeness == 1.0  # every non-allow case carries a reason
    assert m.avg_latency_ms >= 0.0
    # Marquee attack categories detect fully.
    assert m.detection_rate_by_category["tool_call_arg_exfil"] == 1.0
    assert m.detection_rate_by_category["encoded_single_turn"] == 1.0
    assert m.detection_rate_by_category["canary_touch"] == 1.0
    # Benign categories are "correct" (left ALLOW) at 100%.
    for cat in BENIGN_CATEGORIES:
        assert m.detection_rate_by_category[cat] == 1.0
    assert m.detector_hit_distribution  # at least one detector fired somewhere


def test_evidence_complete_on_every_nonallow() -> None:
    scenarios = load_scenarios()
    protected = run_suite(scenarios, mode=Mode.BALANCED)
    for r in protected:
        if _action(r.observed_action) is not Action.ALLOW:
            assert r.reasons, f"{r.scenario_id} blocked without a reason"
            assert r.evidence_complete


def test_write_report_writes_artifacts(tmp_path) -> None:
    scenarios = load_scenarios()
    baseline = run_suite(scenarios, mode=Mode.OBSERVE)
    protected = run_suite(scenarios, mode=Mode.BALANCED)
    paths = write_report(baseline, protected, score(baseline), score(protected), tmp_path)

    jsonl = paths["jsonl"]
    md = paths["markdown"]
    assert jsonl.exists() and md.exists()

    # JSONL: one line per case across BOTH runs, each tagged with its run.
    lines = jsonl.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(baseline) + len(protected)
    import json
    runs = {json.loads(line)["run"] for line in lines}
    assert runs == {"baseline", "protected"}

    # Markdown: contains the Demo Metrics Table and the comparison framing.
    text = md.read_text(encoding="utf-8")
    assert "Demo Metrics Table" in text
    assert "| Scenario Category | Baseline Result | Aegis Result | Evidence |" in text
    assert "Baseline" in text and "Aegis Result" in text
    # The honest-framing caveat is carried into the report.
    assert "learned suspicion signal" in text
