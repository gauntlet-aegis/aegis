"""Policy engine — combines detector results into one enforceable Action (PDF sections 6.3/6.4).

This is the only place enforcement is decided. Detectors recommend; rules add policy-specific
triggers; the engine gathers every candidate (recommendation + fired rule), reshapes each through
the active :class:`~aegis.policy.modes.Mode`, and the single most-severe action wins (never fuse
scores — severity is ordinal; see :func:`aegis.decision.most_severe`).

Contract: :meth:`PolicyEngine.decide` never raises (a guard must always return a decision) and
every non-ALLOW outcome carries at least one human-readable reason for the audit trail.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from aegis.decision import Action, Verdict, most_severe
from aegis.detectors.base import DetectorResult
from aegis.policy.modes import apply_mode
from aegis.policy.schema import (
    CanaryHit,
    DetectorScoreThreshold,
    LeakageBudgetThreshold,
    Policy,
    ToolArgCondition,
)


class PolicyOutcome(BaseModel):
    """The engine's verdict for one event: the action to enforce plus why."""

    action: Action = Action.ALLOW
    reasons: list[str] = Field(default_factory=list)
    fired_rules: list[str] = Field(default_factory=list)


# A candidate is one (post-mode action, human-readable reason, source-label) triple. The label
# goes into fired_rules; the reason into reasons (only when the action is >= WARN).
_Candidate = tuple[Action, str, str]

# Detectors governed by a DEDICATED rule type are exempt from the generic wildcard ("*")
# score-threshold rule, so their purpose-built graduated thresholds aren't overridden. The
# ledger's score == its budget ratio (handled by leakage_budget_threshold's 0.6/0.9/1.0 bands);
# the canary hit is handled by canary_hit. An explicit, named score rule still applies to them.
_DEDICATED_DETECTORS = {"nimbus_lite", "honeytoken"}


class PolicyEngine:
    """Evaluates a fixed :class:`Policy` against per-event detector results.

    Stateless across calls: the cumulative state policies care about (leakage budget, canary
    sightings) is already folded into the :class:`DetectorResult` values the detectors emit.
    """

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def decide(self, results: list[DetectorResult]) -> PolicyOutcome:
        """Combine ``results`` into a :class:`PolicyOutcome`. Never raises."""
        try:
            return self._decide(results)
        except Exception as exc:  # pragma: no cover - defensive: a guard must never crash.
            # Fail loud-but-safe: surface the error as a reason, do not enforce on a bug.
            return PolicyOutcome(
                action=Action.ALLOW,
                reasons=[f"policy engine error (fail-open to ALLOW): {exc!r}"],
            )

    def _decide(self, results: list[DetectorResult]) -> PolicyOutcome:
        mode = self.policy.mode
        results = results or []
        candidates: list[_Candidate] = []

        # 1. Every detector's own recommendation is a candidate.
        for r in results:
            if r.recommended_action > Action.ALLOW:
                candidates.append(
                    (
                        r.recommended_action,
                        f"{r.detector_name} recommends {r.recommended_action.name}"
                        f" (score {r.score:.2f})",
                        f"detector:{r.detector_name}",
                    )
                )

        # 2. Every policy rule that matches the results is a candidate.
        for idx, rule in enumerate(self.policy.rules):
            candidates.extend(self._match_rule(rule, idx, results))

        if not candidates:
            return PolicyOutcome(action=Action.ALLOW)

        # 3. Reshape each candidate's action through the mode, then most-severe wins.
        reasons: list[str] = []
        fired_rules: list[str] = []
        actions: list[Action] = []
        for raw_action, reason, label in candidates:
            action = apply_mode(raw_action, mode)
            actions.append(action)
            fired_rules.append(label)
            # Only WARN-and-above is worth a line in the audit trail (post-mode, so observe-mode
            # WARNs still get recorded but enforcing language is never shown for a clamped action).
            if action >= Action.WARN:
                reasons.append(f"{reason} -> {action.name}")

        final = most_severe(actions)
        # Invariant: any non-ALLOW outcome must carry >= 1 reason. The post-mode filter above keeps
        # every action >= WARN, so a non-ALLOW final always produced a reason; assert via fallback.
        if final > Action.ALLOW and not reasons:  # pragma: no cover - defensive
            reasons.append(f"policy enforced {final.name}")
        return PolicyOutcome(action=final, reasons=reasons, fired_rules=fired_rules)

    # --- rule matchers ---------------------------------------------------------------------

    def _match_rule(self, rule, idx: int, results: list[DetectorResult]) -> list[_Candidate]:
        """Dispatch one rule to its matcher; return zero or more candidates."""
        if isinstance(rule, DetectorScoreThreshold):
            return self._match_score(rule, idx, results)
        if isinstance(rule, ToolArgCondition):
            return self._match_tool_arg(rule, idx, results)
        if isinstance(rule, CanaryHit):
            return self._match_canary(rule, idx, results)
        if isinstance(rule, LeakageBudgetThreshold):
            return self._match_leakage(rule, idx, results)
        return []  # unknown rule type can't reach here (validated at load), but stay total.

    @staticmethod
    def _match_score(
        rule: DetectorScoreThreshold, idx: int, results: list[DetectorResult]
    ) -> list[_Candidate]:
        out: list[_Candidate] = []
        for r in results:
            if rule.detector not in ("*", r.detector_name):
                continue
            # Wildcard rule defers to dedicated rules for detectors that have them.
            if rule.detector == "*" and r.detector_name in _DEDICATED_DETECTORS:
                continue
            if r.score >= rule.threshold:
                out.append(
                    (
                        rule.action,
                        f"{r.detector_name} score {r.score:.2f} >= {rule.threshold:.2f}",
                        f"rule[{idx}]:detector_score_threshold",
                    )
                )
        return out

    @staticmethod
    def _match_tool_arg(
        rule: ToolArgCondition, idx: int, results: list[DetectorResult]
    ) -> list[_Candidate]:
        """Match against the ``tool_call_args`` detector's evidence findings.

        Findings are read from ``evidence['findings']`` (a list of dicts with ``tool``, ``arg``
        and a ``contains_secret`` flag). Tolerant of a missing/short shape — no findings => no
        candidates.
        """
        out: list[_Candidate] = []
        for r in results:
            if r.detector_name != "tool_call_args":
                continue
            findings = r.evidence.get("findings") or []
            for f in findings:
                if not isinstance(f, dict):
                    continue
                tool = f.get("tool", "")
                arg = f.get("arg", "")
                has_secret = bool(f.get("contains_secret", False))
                if rule.tool not in ("*", tool):
                    continue
                if rule.arg not in ("*", arg):
                    continue
                if rule.contains_secret is not None and has_secret != rule.contains_secret:
                    continue
                secret_note = "secret" if has_secret else "no-secret"
                out.append(
                    (
                        rule.action,
                        f"tool_call_args {tool}.{arg} ({secret_note})",
                        f"rule[{idx}]:tool_arg_condition",
                    )
                )
        return out

    @staticmethod
    def _match_canary(
        rule: CanaryHit, idx: int, results: list[DetectorResult]
    ) -> list[_Candidate]:
        out: list[_Candidate] = []
        for r in results:
            if r.detector_name == "honeytoken" and r.verdict is Verdict.MALICIOUS:
                out.append(
                    (
                        rule.action,
                        "honeytoken canary hit",
                        f"rule[{idx}]:canary_hit",
                    )
                )
        return out

    @staticmethod
    def _match_leakage(
        rule: LeakageBudgetThreshold, idx: int, results: list[DetectorResult]
    ) -> list[_Candidate]:
        out: list[_Candidate] = []
        for r in results:
            if r.detector_name != "nimbus_lite":
                continue
            ratio = r.evidence.get("ratio")
            try:
                ratio = float(ratio)
            except (TypeError, ValueError):
                continue
            if ratio >= rule.ratio:
                out.append(
                    (
                        rule.action,
                        f"leakage ratio {ratio:.2f} >= {rule.ratio:.2f}",
                        f"rule[{idx}]:leakage_budget_threshold",
                    )
                )
        return out


__all__ = ["PolicyEngine", "PolicyOutcome"]
