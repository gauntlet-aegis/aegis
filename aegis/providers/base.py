"""The provider contract — how the gateway forwards a guarded request to a model.

A provider is the seam between Aegis and "the model that actually answers". The SDK guards a
request, then hands the (already-inspected) messages to a :class:`Provider` and guards whatever
comes back. Keeping this interface tiny means a new backend (a hosted API, a local model, a
canned demo script) can be dropped in without touching policy, detectors, or the SDK.

Two implementations ship: :class:`~aegis.providers.mock.MockProvider` (deterministic, offline,
authoritative for tests and the demo) and :class:`~aegis.providers.claude.ClaudeProvider`
(a thin live adapter). Both return the same normalized :class:`ProviderResponse`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    """One tool invocation the model asked for, normalized across providers.

    The gateway re-guards each of these as a ``TOOL_CALL`` event before any tool runs, so this
    is exactly the shape an exfiltration attempt would surface in (e.g. ``send_email`` with a
    leaked secret in ``arguments``)."""

    tool_name: str
    arguments: dict = Field(default_factory=dict)


class ProviderResponse(BaseModel):
    """Normalized model output: free-text plus any tool calls.

    Every provider maps its native response onto this shape so downstream guards never care
    which backend produced the turn."""

    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)


@runtime_checkable
class Provider(Protocol):
    """The minimal interface the gateway calls to get a model turn.

    ``complete`` takes the guarded conversation (a list of role/content message dicts) plus the
    optional tool schemas the model may call, and returns a :class:`ProviderResponse`."""

    name: str

    def complete(
        self, messages: list[dict], tools: list[dict] | None = None
    ) -> ProviderResponse: ...
