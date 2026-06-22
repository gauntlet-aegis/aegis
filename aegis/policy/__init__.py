"""Aegis policy engine (PDF sections 6.3/6.4).

A small YAML policy, loaded once at startup, maps detector results + cumulative session state to a
single enforceable :class:`~aegis.decision.Action` under one of three :class:`Mode` postures. The
engine evaluates rules independently and the most-severe action wins.

Public surface:
- :func:`load_policy` — read + validate a YAML file into a :class:`Policy`.
- :class:`Policy`     — the loaded mode + flat rule list.
- :class:`PolicyEngine` / :class:`PolicyOutcome` — combine detector results into a decision.
- :class:`Mode`       — observe / balanced / strict deployment posture.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from aegis.policy.engine import PolicyEngine, PolicyOutcome
from aegis.policy.modes import Mode, apply_mode
from aegis.policy.schema import Policy


def load_policy(path: str | Path) -> Policy:
    """Read a YAML policy file and validate it into a :class:`Policy`.

    Validation (mode, rule types, field ranges) happens here at load time so a malformed policy
    fails fast at startup rather than during a guard call.
    """
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    return Policy.model_validate(data)


__all__ = [
    "load_policy",
    "Policy",
    "PolicyEngine",
    "PolicyOutcome",
    "Mode",
    "apply_mode",
]
