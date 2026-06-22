"""Unit tests for the dashboard's pure data layer (:mod:`dashboard.data`).

These exercise ONLY ``dashboard.data`` — never Streamlit / ``dashboard.app`` — so they assert the
view-building logic in isolation: that the protected run blocks attacks and clears benign cases,
the baseline (observe) run never blocks, the action mapping is correct, and the reference loaders
return non-empty data. They drive the real scenarios dir in-process.
"""

from __future__ import annotations

import dashboard.data as data
from aegis.decision import Action
from aegis.eval.runner import BENIGN_CATEGORIES
from aegis.policy import Mode


def test_action_name_maps_all_representations() -> None:
    assert data.action_name(Action.BLOCK) == "BLOCK"
    assert data.action_name(3) == "BLOCK"
    assert data.action_name("BLOCK") == "BLOCK"
    assert data.action_name(0) == "ALLOW"
    assert data.action_name(Action.ESCALATE) == "ESCALATE"


def test_action_meta_has_all_five_actions_with_colors() -> None:
    assert set(data.ACTION_META) == {a.name for a in Action}
    for name, meta in data.ACTION_META.items():
        assert meta["bg"].startswith("#") and len(meta["bg"]) == 7
        assert meta["fg"].startswith("#")
        assert meta["label"] == name
    # Spot-check the contract palette so a silent recolor is caught.
    assert data.ACTION_META["BLOCK"]["bg"] == "#DA3633"
    assert data.ACTION_META["ESCALATE"]["bg"] == "#8957E5"


def test_protected_run_blocks_attacks_and_clears_benign() -> None:
    view = data.run_view(Mode.BALANCED)
    assert view.total > 0
    # At least one attack reached a hard stop (BLOCK or ESCALATE).
    assert view.blocked + view.escalated > 0

    by_attack = {True: [], False: []}
    for r in view.rows:
        by_attack[r.is_attack].append(r)

    # Every attack scenario is caught: protected reaches at least WARN.
    for r in by_attack[True]:
        assert Action[r.action] >= Action.WARN, f"{r.scenario_id} was not caught: {r.action}"
    # No benign scenario is blocked under the protected posture.
    for r in by_attack[False]:
        assert Action[r.action] < Action.BLOCK, f"benign {r.scenario_id} blocked: {r.action}"


def test_baseline_observe_run_never_blocks() -> None:
    view = data.run_view(Mode.OBSERVE)
    assert view.total > 0
    assert view.blocked == 0
    assert view.escalated == 0
    assert view.sanitized == 0
    for r in view.rows:
        assert Action[r.action] <= Action.WARN, f"{r.scenario_id} enforced in observe: {r.action}"


def test_baseline_vs_protected_shows_aegis_stopping_leaks() -> None:
    rows = data.baseline_vs_protected(Mode.BALANCED)
    assert rows
    # The headline: at least one scenario the baseline let through is stopped harder by Aegis.
    assert any(r.protected_stops_more for r in rows)
    # Benign categories must match in both columns (allowed clean both ways).
    for r in rows:
        if not r.is_attack:
            assert Action[r.protected_action] < Action.BLOCK


def test_decision_detail_carries_evidence_for_attack() -> None:
    rows = data.baseline_vs_protected(Mode.BALANCED)
    attack = next(r for r in rows if r.is_attack and r.protected_stops_more)
    det = data.decision_detail(attack.scenario_id, Mode.BALANCED)
    assert det is not None
    assert Action[det.action] >= Action.WARN
    # Non-allow decisions must carry at least one human-readable reason (the audit invariant).
    assert det.reasons
    # At least one detector fired with structured evidence.
    assert any(h.evidence for h in det.detector_hits)
    assert det.trace_id


def test_decision_detail_unknown_scenario_returns_none() -> None:
    assert data.decision_detail("does_not_exist") is None


def test_policy_loader_returns_rules() -> None:
    pv = data.load_policy_rules()
    assert pv.mode
    assert pv.rules, "policy must expose at least one rule"
    assert pv.raw_yaml.strip()
    for r in pv.rules:
        assert r["action"] in data.ACTION_META
        assert r["summary"]


def test_detector_roster_non_empty_with_phases() -> None:
    roster = data.detector_roster()
    assert roster
    names = {d.name for d in roster}
    # The shipping detector stack.
    assert {"secret_pattern", "encoding", "tool_call_args", "honeytoken", "nimbus_lite"} <= names
    for d in roster:
        assert d.phases


def test_registry_loader_returns_honeytokens_and_handles() -> None:
    reg = data.honeytoken_and_broker_registry()
    assert reg.honeytokens, "scenarios plant at least one canary"
    for h in reg.honeytokens:
        # Provenance only — never the live token value.
        assert set(h) == {"canary_id", "service", "fmt", "location"}
        assert "token" not in h
    assert reg.broker_handles, "benign-handle scenarios expose secret:// handles"
    for b in reg.broker_handles:
        assert b["handle"].startswith("secret://")


def test_benign_categories_constant_present() -> None:
    # Guard against a future scenario rename silently breaking the benign/attack split.
    assert BENIGN_CATEGORIES
    cats = {s.category for s in data.get_scenarios()}
    assert BENIGN_CATEGORIES <= cats
