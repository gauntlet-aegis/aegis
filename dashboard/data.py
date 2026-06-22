"""Pure data layer for the Aegis dashboard (PDF FR-11).

Streamlit-free by design: every function here builds a plain Python data structure by driving the
*real* Aegis SDK / eval harness in-process, so the whole module is unit-testable without a browser
and the dashboard runs fully offline (no network, no live LLM, no trace files required).

Where it fits: :mod:`dashboard.app` is a thin Streamlit shell that calls these functions and
renders the results. The two postures the dashboard contrasts mirror the eval harness exactly —
``Mode.OBSERVE`` is the baseline (the vulnerable agent: records, never blocks) and ``Mode.BALANCED``
(or whatever the header selects) is the protected run.

Key building blocks:
- :data:`ACTION_META` / :func:`action_name` — the single source of action color-coding + naming.
- :func:`run_view` — drives ``run_suite`` for one mode and returns view-ready feed rows + metrics.
- :func:`baseline_vs_protected` — the demo headline (observe vs balanced, aligned per scenario).
- :func:`decision_detail` — re-runs ONE scenario through the SDK to capture the full
  :class:`~aegis.decision.AegisDecision` (per-detector evidence) for the drill-down view.
- :func:`load_policy_rules` / :func:`detector_roster` / :func:`honeytoken_and_broker_registry` —
  the reference data for the Policy & Detectors panel.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from aegis.broker.handles import find_handles, parse_handle
from aegis.decision import Action, AegisDecision
from aegis.eval import CaseResult, Metrics, Scenario, load_scenarios, run_suite, score
from aegis.eval.runner import (
    BENIGN_CATEGORIES,
    CANARY_MARKER,
    DEFAULT_POLICY,
    SCENARIO_DIR,
    _materialize_turn,
)
from aegis.policy import Mode, PolicyEngine, load_policy
from aegis.sdk import Aegis

# ---------------------------------------------------------------------------------------------
# Action color-coding — the ONE place the dashboard's palette lives (matches the approved mocks).
# bg is the badge fill (hex), fg is the badge text color. Used everywhere an action is rendered.
# ---------------------------------------------------------------------------------------------
ACTION_META: dict[str, dict[str, str]] = {
    "ALLOW":    {"bg": "#238636", "fg": "#FFFFFF", "label": "ALLOW"},
    "WARN":     {"bg": "#9E6A03", "fg": "#FFFFFF", "label": "WARN"},
    "SANITIZE": {"bg": "#BD561D", "fg": "#FFFFFF", "label": "SANITIZE"},
    "BLOCK":    {"bg": "#DA3633", "fg": "#FFFFFF", "label": "BLOCK"},
    "ESCALATE": {"bg": "#8957E5", "fg": "#FFFFFF", "label": "ESCALATE"},
}

# Phase glyphs for the feed (kept ASCII-safe so they render in any terminal/headless context).
PHASE_ICON: dict[str, str] = {
    "request": "REQ",
    "tool_call": "TOOL",
    "response": "RESP",
}

# Friendly names for the three deployment postures (the header mode selector).
MODE_LABELS: dict[Mode, str] = {
    Mode.OBSERVE: "observe (baseline)",
    Mode.BALANCED: "balanced (protected)",
    Mode.STRICT: "strict (high-stakes)",
}


def action_name(action: "int | Action | str") -> str:
    """Normalize an Action (enum / int value / name string) to its canonical NAME string.

    The feed/detail data carry actions as names; this is the safe coercion every renderer uses so
    an ``Action`` enum, its int value, or an already-normalized string all map to e.g. ``"BLOCK"``.
    """
    if isinstance(action, str):
        return Action[action].name
    return Action(int(action)).name


def action_meta(action: "int | Action | str") -> dict[str, str]:
    """Color + label metadata for any action representation (see :data:`ACTION_META`)."""
    return ACTION_META[action_name(action)]


# ---------------------------------------------------------------------------------------------
# Feed rows + per-view bundles
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class FeedRow:
    """One guarded boundary as the Live Decision Feed (V1) renders it.

    All fields are redacted/derived — the input summary never contains a raw secret (the SDK's
    detector hits are names only; the raw token only appears, redacted, in the detail re-run).
    """

    scenario_id: str
    category: str
    phase: str
    phase_icon: str
    action: str
    is_attack: bool
    risk_score: float
    latency_ms: float
    detectors: list[str]
    reasons: list[str]
    input_summary: str


@dataclass(frozen=True)
class ViewData:
    """A single mode's run: the feed rows, the scored metrics, and headline counters (V1/V4)."""

    mode: str
    rows: list[FeedRow]
    metrics: Metrics
    total: int
    blocked: int
    escalated: int
    warnings: int
    sanitized: int
    allowed: int


def _redacted_input_summary(scenario: Scenario, max_len: int = 110) -> str:
    """Build a short, redacted one-line preview of a scenario's first turn for the feed.

    Never surfaces a raw credential: the canary marker stays inert text and any ``secret://`` handle
    is kept (a handle is not a secret), while embedded long tokens are left to the SDK's redaction —
    this preview is built from the *authored* scenario text, which by construction holds no live
    secret value (canaries are substituted only inside the SDK run).
    """
    if not scenario.turns:
        return "(no turns)"
    turn = scenario.turns[0]
    if scenario.phase == "tool_call":
        raw = f"{turn.tool_name}({_compact_args(turn.arguments or {})})"
    else:
        raw = (turn.content or "").replace(CANARY_MARKER, "<canary>")
    raw = " ".join(raw.split())
    return raw if len(raw) <= max_len else raw[: max_len - 1] + "…"


def _compact_args(args: dict) -> str:
    """Render tool arguments compactly for a one-line preview (keys + short values)."""
    parts = []
    for k, v in args.items():
        sv = v if isinstance(v, str) else str(v)
        sv = sv if len(sv) <= 40 else sv[:39] + "…"
        parts.append(f"{k}={sv}")
    return ", ".join(parts)


def _scenario_index(scenarios: list[Scenario]) -> dict[str, Scenario]:
    return {s.id: s for s in scenarios}


def _build_rows(results: list[CaseResult], scenarios: dict[str, Scenario]) -> list[FeedRow]:
    """Join scored case results with their scenarios into feed rows (reverse-chronological)."""
    rows: list[FeedRow] = []
    for r in results:
        scenario = scenarios.get(r.scenario_id)
        phase = scenario.phase if scenario else "request"
        rows.append(FeedRow(
            scenario_id=r.scenario_id,
            category=r.category,
            phase=phase,
            phase_icon=PHASE_ICON.get(phase, phase.upper()),
            action=action_name(r.observed_action),
            is_attack=r.category not in BENIGN_CATEGORIES,
            risk_score=r.risk_score,
            latency_ms=r.latency_ms,
            detectors=[d for d in r.detector_hits],
            reasons=list(r.reasons),
            input_summary=_redacted_input_summary(scenario) if scenario else "(unknown)",
        ))
    # Reverse so the most recently-run scenario sits on top, like a live stream.
    rows.reverse()
    return rows


@lru_cache(maxsize=1)
def _scenarios_cached(directory: str) -> tuple[Scenario, ...]:
    """Cache the loaded, validated scenarios (the input is the same dir every call)."""
    return tuple(load_scenarios(directory))


def get_scenarios(directory: "str | Path" = SCENARIO_DIR) -> list[Scenario]:
    """Load (and cache) the scenario suite the dashboard drives."""
    return list(_scenarios_cached(str(directory)))


@lru_cache(maxsize=8)
def _run_view_cached(mode_value: str, directory: str) -> ViewData:
    scenarios = list(_scenarios_cached(directory))
    mode = Mode(mode_value)
    results = run_suite(scenarios, mode=mode)
    metrics = score(results)
    rows = _build_rows(results, _scenario_index(scenarios))
    counts = {a: 0 for a in ACTION_META}
    for r in rows:
        counts[r.action] += 1
    return ViewData(
        mode=mode_value,
        rows=rows,
        metrics=metrics,
        total=len(rows),
        blocked=counts["BLOCK"],
        escalated=counts["ESCALATE"],
        warnings=counts["WARN"],
        sanitized=counts["SANITIZE"],
        allowed=counts["ALLOW"],
    )


def run_view(mode: "Mode | str" = Mode.BALANCED,
             directory: "str | Path" = SCENARIO_DIR) -> ViewData:
    """Drive the whole suite under ``mode`` and return feed rows + metrics + counters.

    Powers V1 (Live Decision Feed) and V4 (Metrics). Cached per (mode, directory) — the suite is
    deterministic, so repeated renders are free.
    """
    mode_value = mode.value if isinstance(mode, Mode) else Mode(mode).value
    return _run_view_cached(mode_value, str(directory))


# ---------------------------------------------------------------------------------------------
# V3 — Baseline vs Protected
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ComparisonRow:
    """One scenario aligned across the baseline (observe) and protected runs (V3)."""

    scenario_id: str
    category: str
    is_attack: bool
    description: str
    baseline_action: str
    protected_action: str
    protected_reasons: list[str]
    protected_risk: float
    # True when the protected run is strictly more conservative than the baseline (the headline:
    # "baseline leaked / warned, Aegis stopped it").
    protected_stops_more: bool


def baseline_vs_protected(protected_mode: "Mode | str" = Mode.BALANCED,
                          directory: "str | Path" = SCENARIO_DIR) -> list[ComparisonRow]:
    """Run the suite in observe (baseline) and ``protected_mode`` and align per scenario.

    This is the demo headline: the same scenarios run by the vulnerable agent (observe never blocks)
    next to the protected agent. Returns rows in scenario-id order.
    """
    scenarios = get_scenarios(directory)
    idx = _scenario_index(scenarios)
    baseline = {r.scenario_id: r for r in run_view(Mode.OBSERVE, directory).rows}
    protected_view = run_view(protected_mode, directory)
    protected = {r.scenario_id: r for r in protected_view.rows}

    rows: list[ComparisonRow] = []
    for sid in sorted(idx):
        b = baseline.get(sid)
        p = protected.get(sid)
        if b is None or p is None:
            continue
        rows.append(ComparisonRow(
            scenario_id=sid,
            category=idx[sid].category,
            is_attack=idx[sid].category not in BENIGN_CATEGORIES,
            description=idx[sid].description,
            baseline_action=b.action,
            protected_action=p.action,
            protected_reasons=p.reasons,
            protected_risk=p.risk_score,
            protected_stops_more=Action[p.action] > Action[b.action],
        ))
    return rows


# ---------------------------------------------------------------------------------------------
# V2 — Decision Detail (re-run ONE scenario to capture full evidence)
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class DetectorHitView:
    """One detector's contribution to a decision, with its structured evidence (V2 table)."""

    detector_name: str
    score: float
    confidence: float
    verdict: str
    recommended_action: str
    latency_ms: float
    evidence: dict


@dataclass(frozen=True)
class DecisionDetail:
    """Everything about one guarded turn — the audit-trail view (V2)."""

    scenario_id: str
    category: str
    is_attack: bool
    description: str
    phase: str
    mode: str
    action: str
    risk_score: float
    trace_id: str
    reasons: list[str]
    detector_hits: list[DetectorHitView]
    input_summary: str
    sanitized_payload: "str | dict | None"
    refusal: "str | None"


def _drive_scenario(aegis: Aegis, scenario: Scenario, *, session_id: str) -> AegisDecision:
    """Drive one scenario through the SDK exactly as the eval runner does, returning the FINAL
    turn's full :class:`AegisDecision` (mirrors ``aegis.eval.runner.run_suite`` for a single case so
    we recover the per-detector evidence the scored ``CaseResult`` discards)."""
    canary_token: str | None = None
    if scenario.canary is not None:
        canary = aegis.registry.register(
            scenario.canary.service, scenario.canary.fmt, scenario.canary.location,
            session_id=session_id, seed=1234,
        )
        canary_token = canary.token

    decision: AegisDecision | None = None
    for turn in scenario.turns:
        t = _materialize_turn(turn, canary_token)
        if scenario.phase == "request":
            decision = aegis.guard_request(
                [{"role": t.role or "user", "content": t.content or ""}], session_id=session_id)
        elif scenario.phase == "response":
            decision = aegis.guard_response(t.content or "", session_id=session_id)
        else:  # tool_call
            decision = aegis.guard_tool_call(t.tool_name or "", t.arguments or {},
                                             session_id=session_id)
    return decision  # type: ignore[return-value]


def decision_detail(scenario_id: str, mode: "Mode | str" = Mode.BALANCED,
                    directory: "str | Path" = SCENARIO_DIR) -> "DecisionDetail | None":
    """Re-run a single scenario through a fresh Aegis under ``mode`` and capture full evidence.

    Returns ``None`` for an unknown scenario id. Builds a fresh SDK + policy each call (cheap,
    deterministic) so the per-detector evidence is exactly what the runtime would produce.
    """
    scenario = _scenario_index(get_scenarios(directory)).get(scenario_id)
    if scenario is None:
        return None
    mode_enum = mode if isinstance(mode, Mode) else Mode(mode)

    policy = load_policy(DEFAULT_POLICY)
    policy.mode = mode_enum
    aegis = Aegis(PolicyEngine(policy))
    decision = _drive_scenario(aegis, scenario, session_id=f"dash::{scenario_id}")

    hits = [DetectorHitView(
        detector_name=h.detector_name,
        score=h.score,
        confidence=h.confidence,
        verdict=h.verdict.value,
        recommended_action=h.recommended_action.name,
        latency_ms=h.latency_ms,
        evidence=dict(h.evidence),
    ) for h in decision.detector_hits]

    action = decision.action
    return DecisionDetail(
        scenario_id=scenario_id,
        category=scenario.category,
        is_attack=scenario.category not in BENIGN_CATEGORIES,
        description=scenario.description,
        phase=scenario.phase,
        mode=mode_enum.value,
        action=action.name,
        risk_score=decision.risk_score,
        trace_id=decision.trace_id,
        reasons=list(decision.reasons),
        detector_hits=hits,
        input_summary=_redacted_input_summary(scenario, max_len=300),
        sanitized_payload=decision.sanitized_payload if action is Action.SANITIZE else None,
        refusal=_refusal_text(action) if action >= Action.BLOCK else None,
    )


def _refusal_text(action: Action) -> str:
    """The user-facing refusal line for a blocked/escalated decision (V2 'returned' panel)."""
    if action is Action.ESCALATE:
        return "Request refused and escalated for out-of-band human review."
    return "Request refused: forwarding would disclose protected credential material."


# ---------------------------------------------------------------------------------------------
# V5 — Policy & Detectors panel
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class PolicyView:
    """The loaded policy rendered readably (V5): mode + one human line per rule, plus the raw YAML."""

    mode: str
    rules: list[dict]
    raw_yaml: str


def load_policy_rules(policy_path: "str | Path" = DEFAULT_POLICY) -> PolicyView:
    """Load the policy and describe each rule as a plain 'if <condition> -> <action>' line.

    Returns the active mode, a normalized rule list (type, a human ``summary``, and the resulting
    ``action`` name), and the raw YAML for the reference panel. Never empty for the default policy.
    """
    policy = load_policy(policy_path)
    raw = Path(policy_path).read_text(encoding="utf-8")
    rules: list[dict] = []
    for r in policy.rules:
        d = r.model_dump()
        rules.append({
            "type": d["type"],
            "action": Action(d["action"]).name,
            "summary": _rule_summary(d),
        })
    return PolicyView(mode=policy.mode.value, rules=rules, raw_yaml=raw)


def _rule_summary(d: dict) -> str:
    """One readable 'if <condition>' clause per rule type (the action is shown separately)."""
    t = d["type"]
    if t == "detector_score_threshold":
        det = "any detector" if d["detector"] == "*" else f'detector "{d["detector"]}"'
        return f"if {det} score ≥ {d['threshold']:.2f}"
    if t == "tool_arg_condition":
        tool = "any tool" if d["tool"] == "*" else d["tool"]
        arg = "any arg" if d["arg"] == "*" else d["arg"]
        secret = "carrying a secret" if d.get("contains_secret") else "matching"
        return f"if {tool} / {arg} argument {secret}"
    if t == "canary_hit":
        return "if a planted canary reappears downstream (ground-truth exfiltration)"
    if t == "leakage_budget_threshold":
        return f"if cumulative session leakage ratio ≥ {d['ratio']:.2f}"
    return t


@dataclass(frozen=True)
class DetectorInfo:
    """A registered detector and the guard phases it applies to (V5 roster)."""

    name: str
    phases: list[str]


def detector_roster(policy_path: "str | Path" = DEFAULT_POLICY) -> list[DetectorInfo]:
    """The detectors wired into the SDK pipeline and the phases each runs on. Never empty."""
    aegis = Aegis.from_config(policy_path)
    roster = [
        DetectorInfo(name=d.name, phases=sorted(p.value for p in d.phases))
        for d in aegis.pipeline.detectors
    ]
    return sorted(roster, key=lambda d: d.name)


@dataclass(frozen=True)
class RegistryView:
    """Honeytoken canaries + broker handles in play for the reference panel (V5).

    Honeytokens list provenance only (canary id / service / format / location), never the live
    token value. Broker handles are opaque ``secret://service/name`` references harvested from the
    scenarios — handles, never secret values (that is the whole point of the broker design).
    """

    honeytokens: list[dict]
    broker_handles: list[dict]


def honeytoken_and_broker_registry(directory: "str | Path" = SCENARIO_DIR) -> RegistryView:
    """Plant every scenario's declared canary into a registry and harvest the broker handles.

    Drives a single Aegis so the canary planting path is the real one; collects canary provenance
    (id/service/format/location, NOT the token) and the distinct ``secret://`` handles that appear
    across the scenario tool-call arguments.
    """
    aegis = Aegis.from_config(DEFAULT_POLICY)
    scenarios = get_scenarios(directory)

    honeytokens: list[dict] = []
    handles: dict[str, dict] = {}
    for s in scenarios:
        if s.canary is not None:
            canary = aegis.registry.register(
                s.canary.service, s.canary.fmt, s.canary.location,
                session_id=f"v5::{s.id}", seed=1234,
            )
            honeytokens.append({
                "canary_id": canary.canary_id,
                "service": canary.service,
                "fmt": canary.fmt,
                "location": canary.location,
            })
        for h in _scenario_handles(s):
            parsed = parse_handle(h)
            if parsed is not None and h not in handles:
                handles[h] = {"handle": h, "service": parsed[0], "name": parsed[1]}

    return RegistryView(
        honeytokens=honeytokens,
        broker_handles=sorted(handles.values(), key=lambda d: d["handle"]),
    )


def _scenario_handles(scenario: Scenario) -> list[str]:
    """Every ``secret://service/name`` handle embedded in a scenario's turns (args + content)."""
    found: list[str] = []
    for turn in scenario.turns:
        if turn.content:
            found.extend(find_handles(turn.content))
        if turn.arguments:
            found.extend(_handles_in_obj(turn.arguments))
    return found


def _handles_in_obj(obj) -> list[str]:
    """Recursively collect handles from an arguments structure (dict / list / str)."""
    if isinstance(obj, str):
        return find_handles(obj)
    if isinstance(obj, dict):
        return [h for v in obj.values() for h in _handles_in_obj(v)]
    if isinstance(obj, list):
        return [h for v in obj for h in _handles_in_obj(v)]
    return []
