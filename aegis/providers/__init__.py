"""Model providers — the seam between Aegis and whatever actually answers a guarded request.

The gateway forwards guarded messages to a :class:`Provider` and re-guards the response. Use
:func:`make_provider` to pick a backend by name: ``"mock"`` for the deterministic offline demo
and tests, ``"claude"`` for a live Anthropic-backed model.
"""

from __future__ import annotations

from aegis.providers.base import Provider, ProviderResponse, ToolCall
from aegis.providers.claude import ClaudeProvider
from aegis.providers.mock import MockProvider


def make_provider(kind: str, **kwargs) -> Provider:
    """Construct a provider by name. ``kind`` is ``"mock"`` or ``"claude"``; ``kwargs`` are
    forwarded to the chosen provider's constructor."""
    if kind == "mock":
        return MockProvider(**kwargs)
    if kind == "claude":
        return ClaudeProvider(**kwargs)
    raise ValueError(f"unknown provider kind: {kind!r} (expected 'mock' or 'claude')")


__all__ = [
    "Provider",
    "ProviderResponse",
    "ToolCall",
    "MockProvider",
    "ClaudeProvider",
    "make_provider",
]
