"""Honeytoken registry (PDF section 6.4) — per-session bookkeeping of planted canaries.

A :class:`Canary` records one planted honeytoken: its value (the string injected into
model-visible context), the service it impersonates, where it was planted (``location``), and the
session it belongs to. The registry mints canaries via :func:`aegis.honeytokens.generator.generate`
and lets the detector look a downstream string back up to its planting record.

Where it fits: the SDK plants canaries (system prompt, fake tool outputs) at setup time;
:class:`aegis.detectors.honeytoken.HoneytokenDetector` queries this registry on every tool call
and response. A registered canary reappearing downstream is ground-truth exfiltration.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field

from aegis.honeytokens.generator import generate


class Canary(BaseModel):
    """One planted honeytoken and its provenance."""

    canary_id: str = Field(default_factory=lambda: f"canary_{uuid.uuid4().hex[:12]}")
    token: str
    service: str
    fmt: str
    location: str
    session_id: str


class HoneytokenRegistry:
    """In-memory registry of planted canaries, keyed by token value for O(1) leak lookup.

    Tokens are unique per generation (DP-flavored sampling + random ids), so a token-value index is
    safe. Scope a session's view with :meth:`for_session`."""

    def __init__(self) -> None:
        self._by_token: dict[str, Canary] = {}
        self._canaries: list[Canary] = []
        self._counter = 0

    def register(self, service: str, fmt: str, location: str, *, session_id: str = "default",
                 seed: int | None = None) -> Canary:
        """Mint and plant a canary: generate a format-valid token for ``fmt`` and record where it
        was planted. ``location`` is the planting site (e.g. ``"system_prompt"``,
        ``"tool:query_database"``).

        A per-registration counter is mixed into ``seed`` so two canaries registered with the same
        ``fmt`` AND the same ``seed`` still get distinct tokens (otherwise the deterministic
        generator would collide them and the token index would drop one)."""
        self._counter += 1
        effective_seed = None if seed is None else seed * 1_000_003 + self._counter
        token = generate(fmt, seed=effective_seed)
        canary = Canary(token=token, service=service, fmt=fmt, location=location, session_id=session_id)
        self._by_token[token] = canary
        self._canaries.append(canary)
        return canary

    def tokens(self) -> list[str]:
        """All registered token values — the strings the detector scans downstream content for."""
        return list(self._by_token.keys())

    def lookup(self, token: str) -> Canary | None:
        """Return the :class:`Canary` for an exact token value, or ``None`` if unregistered."""
        return self._by_token.get(token)

    def for_session(self, session_id: str) -> list[Canary]:
        """Canaries planted for a given session."""
        return [c for c in self._canaries if c.session_id == session_id]
