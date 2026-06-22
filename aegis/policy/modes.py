"""Policy modes — the deployment posture that reshapes every action (PDF sections 6.3/6.4).

A mode is applied to each candidate action *after* it is produced (by a detector recommendation
or a fired rule) and *before* the most-severe combine. It is a pure, total function on a single
:class:`~aegis.decision.Action` — no rule re-interpretation, no hidden state — so the same set of
detectors and rules can run unchanged in production (balanced), in a high-stakes deployment
(strict), or in a non-enforcing dry run (observe).

Rationale for the three postures:
- ``observe``  — shadow/learning mode. Records evidence and surfaces WARNs, but is incapable of
                 affecting traffic: anything enforcing (SANITIZE/BLOCK/ESCALATE) is clamped to
                 WARN. Lets a team measure precision before turning enforcement on.
- ``balanced`` — the default posture. Actions pass through exactly as detectors/rules intended.
- ``strict``  — high-stakes posture. Every action is bumped one step more conservative: WARN
                becomes SANITIZE and SANITIZE becomes BLOCK (BLOCK/ESCALATE are already terminal).
                ALLOW stays ALLOW — strict tightens *responses to signal*, it does not invent it.
"""

from __future__ import annotations

from enum import StrEnum

from aegis.decision import Action


class Mode(StrEnum):
    """Deployment posture. See :func:`apply_mode` for the per-mode action transform."""

    OBSERVE = "observe"
    BALANCED = "balanced"
    STRICT = "strict"


# strict bumps each non-terminal action one notch toward "more conservative".
_STRICT_BUMP: dict[Action, Action] = {
    Action.WARN: Action.SANITIZE,
    Action.SANITIZE: Action.BLOCK,
}


def apply_mode(action: Action, mode: Mode) -> Action:
    """Reshape a single candidate ``action`` for the active ``mode``.

    Pure and total: every Action maps to an Action for every Mode. Called per candidate in
    :class:`~aegis.policy.engine.PolicyEngine` before the most-severe combine.
    """
    if mode is Mode.OBSERVE:
        # Never enforce: clamp anything at/above SANITIZE down to WARN, leave ALLOW/WARN as-is.
        return Action.WARN if action >= Action.SANITIZE else action
    if mode is Mode.STRICT:
        return _STRICT_BUMP.get(action, action)
    # balanced (and any unforeseen mode): pass through unchanged.
    return action


__all__ = ["Mode", "apply_mode"]
