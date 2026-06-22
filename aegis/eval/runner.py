"""Scenario loader + run driver for the Aegis evaluation harness (PDF section 7).

This is the offline test bench: it loads YAML scenarios (benign + attack), drives each through the
*real* Aegis SDK guards under a chosen :class:`~aegis.policy.Mode`, and records one
:class:`CaseResult` per scenario. Nothing here re-implements detection — every verdict comes from
the SDK, so the eval measures the shipping system rather than a parallel mock.

Two postures are compared elsewhere (see :mod:`aegis.eval.report`):
- baseline  = ``Mode.OBSERVE``  — the vulnerable agent: records evidence, never blocks.
- protected = ``Mode.BALANCED`` — enforcement on.

Where it fits: :func:`load_scenarios` reads ``scenarios/*.yaml``; :func:`run_suite` builds one
Aegis per run (default policy with ``mode`` overridden), drives the right guard for each scenario's
phase in its own ``session_id``, and substitutes a freshly-planted canary token for the
``{{CANARY}}`` marker in canary scenarios. Fully offline, deterministic, no network/ML.
"""

from __future__ import annotations

import time
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from aegis.decision import Action
from aegis.policy import Mode, load_policy
from aegis.policy.engine import PolicyEngine
from aegis.sdk import Aegis

# The default (balanced) policy ships alongside the engine; the eval loads it and only overrides
# the mode, so baseline and protected runs share an identical rule set.
DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "policy" / "default.yaml"
SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"

# Marker the runner replaces with a freshly-minted canary token in canary scenarios. Inert text
# until substitution, so the YAML never contains a live token.
CANARY_MARKER = "{{CANARY}}"

# Map the scenario's `expected` string onto the authoritative Action enum.
_EXPECTED_TO_ACTION = {
    "allow": Action.ALLOW,
    "warn": Action.WARN,
    "sanitize": Action.SANITIZE,
    "block": Action.BLOCK,
    "escalate": Action.ESCALATE,
}

# Benign categories must pass clean; everything else is an attack we expect to detect (>= WARN).
BENIGN_CATEGORIES = {"benign_normal", "benign_secret_handle", "false_positive_benign_text"}


class Turn(BaseModel):
    """One turn within a scenario.

    For ``request``/``response`` phases a turn is ``{role, content}``; for ``tool_call`` it is
    ``{tool_name, arguments}``. All fields are optional so one model covers every phase; the runner
    reads the pair that matches the scenario's declared phase.
    """

    role: str | None = None
    content: str | None = None
    tool_name: str | None = None
    arguments: dict | None = None


class CanarySpec(BaseModel):
    """How to plant a honeytoken for a canary scenario (passed straight to ``plant_honeytoken``)."""

    service: str
    fmt: str
    location: str


class Scenario(BaseModel):
    """One loaded scenario: a small, deterministic case across one or more turns.

    ``phase`` selects which guard the runner drives (request / tool_call / response). ``expected``
    is the ground-truth action the protected (balanced) run should reach. ``canary`` (optional)
    declares a honeytoken to plant and substitute into the turn text via :data:`CANARY_MARKER`.
    """

    id: str
    category: str
    description: str = ""
    phase: str
    turns: list[Turn] = Field(default_factory=list)
    expected: str
    canary: CanarySpec | None = None

    @property
    def expected_action(self) -> Action:
        return _EXPECTED_TO_ACTION[self.expected]


class CaseResult(BaseModel):
    """The recorded outcome of running one scenario under one mode.

    ``observed_action`` is what Aegis actually decided on the final guarded turn; ``allowed`` is
    its boolean shorthand. ``evidence_complete`` is True when every non-ALLOW case carries at least
    one human-readable reason (the audit-trail invariant from the SDK contract).
    """

    scenario_id: str
    category: str
    expected: str
    observed_action: str
    allowed: bool
    risk_score: float
    reasons: list[str] = Field(default_factory=list)
    detector_hits: list[str] = Field(default_factory=list)
    latency_ms: float
    evidence_complete: bool
    mode: str


def load_scenarios(directory: str | Path = SCENARIO_DIR) -> list[Scenario]:
    """Load and validate every ``*.yaml`` scenario file under ``directory``.

    Each file holds a YAML list of scenario mappings. Returns them flattened and sorted by id so a
    run is deterministic regardless of filesystem ordering. Empty files are skipped.
    """
    directory = Path(directory)
    scenarios: list[Scenario] = []
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for entry in data:
            scenarios.append(Scenario.model_validate(entry))
    scenarios.sort(key=lambda s: s.id)
    return scenarios


def _build_aegis(mode: Mode) -> Aegis:
    """Construct an Aegis on the default policy with its mode overridden to ``mode``.

    ``local_test_mode`` is OFF: the eval deliberately exercises the real broker/escalation path so
    a planted-canary leak escalates exactly as it would in production.
    """
    policy = load_policy(DEFAULT_POLICY)
    policy.mode = mode
    return Aegis(PolicyEngine(policy))


def _materialize_turn(turn: Turn, canary_token: str | None) -> Turn:
    """Substitute the live canary token for :data:`CANARY_MARKER` in a turn's text/args.

    Returns a copy; the loaded Scenario is never mutated, so re-running a suite is repeatable.
    """
    if canary_token is None:
        return turn
    new = turn.model_copy(deep=True)
    if new.content is not None:
        new.content = new.content.replace(CANARY_MARKER, canary_token)
    if new.arguments is not None:
        new.arguments = _sub_in_obj(new.arguments, canary_token)
    return new


def _sub_in_obj(obj, token: str):
    """Recursively replace the canary marker inside an arguments structure."""
    if isinstance(obj, str):
        return obj.replace(CANARY_MARKER, token)
    if isinstance(obj, dict):
        return {k: _sub_in_obj(v, token) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sub_in_obj(v, token) for v in obj]
    return obj


def _guard_turn(aegis: Aegis, scenario: Scenario, turn: Turn, session_id: str):
    """Drive the guard matching the scenario's phase for a single turn."""
    if scenario.phase == "request":
        return aegis.guard_request([{"role": turn.role or "user", "content": turn.content or ""}],
                                   session_id=session_id)
    if scenario.phase == "response":
        return aegis.guard_response(turn.content or "", session_id=session_id)
    if scenario.phase == "tool_call":
        return aegis.guard_tool_call(turn.tool_name or "", turn.arguments or {},
                                     session_id=session_id)
    raise ValueError(f"unknown phase: {scenario.phase!r}")


def run_suite(scenarios: list[Scenario], *, mode: Mode) -> list[CaseResult]:
    """Run every scenario through a fresh Aegis under ``mode`` and return one result each.

    Each scenario runs in its own ``session_id`` (so a multi-turn drip accumulates in isolation).
    Multi-turn scenarios are driven turn by turn; the FINAL turn's decision is the recorded
    outcome (that is where the expected verdict lands). Canary scenarios plant a honeytoken with a
    fixed seed and substitute the minted token into the turns before guarding.
    """
    results: list[CaseResult] = []
    for scenario in scenarios:
        aegis = _build_aegis(mode)
        session_id = f"eval::{scenario.id}"

        canary_token: str | None = None
        if scenario.canary is not None:
            # Deterministic token (seed) so the suite is repeatable; planted into model-visible
            # context, then its reappearance downstream is the ground-truth leak.
            canary = aegis.registry.register(
                scenario.canary.service, scenario.canary.fmt, scenario.canary.location,
                session_id=session_id, seed=1234,
            )
            canary_token = canary.token

        start = time.perf_counter()
        decision = None
        for turn in scenario.turns:
            decision = _guard_turn(aegis, scenario, _materialize_turn(turn, canary_token),
                                   session_id)
        latency_ms = (time.perf_counter() - start) * 1000.0

        # A scenario with no turns is a config error, but never crash the suite over it.
        if decision is None:
            results.append(CaseResult(
                scenario_id=scenario.id, category=scenario.category, expected=scenario.expected,
                observed_action=Action.ALLOW.name, allowed=True, risk_score=0.0, reasons=[],
                detector_hits=[], latency_ms=latency_ms, evidence_complete=True, mode=mode.value,
            ))
            continue

        # Evidence invariant: every non-ALLOW decision must carry at least one reason.
        evidence_complete = decision.allowed or len(decision.reasons) >= 1
        results.append(CaseResult(
            scenario_id=scenario.id,
            category=scenario.category,
            expected=scenario.expected,
            observed_action=decision.action.name,
            allowed=decision.allowed,
            risk_score=decision.risk_score,
            reasons=list(decision.reasons),
            detector_hits=[h.detector_name for h in decision.detector_hits],
            latency_ms=latency_ms,
            evidence_complete=evidence_complete,
            mode=mode.value,
        ))
    return results
