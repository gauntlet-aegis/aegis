"""Live Claude adapter — a thin map from the Anthropic Messages API to a ProviderResponse.

This is the only provider that touches the network. ``anthropic`` is an *optional* dependency:
importing this module must always succeed (so the package, tests, and offline demo never depend
on it), and the missing-package / missing-key errors are deferred until ``complete`` is actually
called. That keeps the demo and the test suite fully offline while still letting a deployment
point Aegis at a real model by installing ``anthropic`` and setting the API key.
"""

from __future__ import annotations

import os

from aegis.providers.base import ProviderResponse, ToolCall


class ClaudeProvider:
    """Anthropic-backed :class:`~aegis.providers.base.Provider`.

    Construction is cheap and side-effect-free. The first ``complete`` call lazily imports the
    ``anthropic`` SDK and reads the API key; either being absent raises a clear ``RuntimeError``
    so the failure is obvious and local to the call that needed the network."""

    def __init__(
        self,
        model: str = "claude-opus-4-8",
        *,
        api_key_env: str = "ANTHROPIC_API_KEY",
        max_tokens: int = 1024,
        name: str = "claude",
    ) -> None:
        self.name = name
        self.model = model
        self.api_key_env = api_key_env
        self.max_tokens = max_tokens
        self._client = None  # built lazily on first complete()

    def _ensure_client(self):
        """Lazily build the Anthropic client, raising a clear error if it can't be."""
        if self._client is not None:
            return self._client
        try:
            import anthropic  # noqa: PLC0415 — deliberately lazy: optional dependency.
        except ImportError as exc:
            raise RuntimeError(
                "ClaudeProvider requires the 'anthropic' package, which is not installed. "
                "Install it (pip install anthropic) or use MockProvider for offline runs."
            ) from exc
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            raise RuntimeError(
                f"ClaudeProvider needs an API key in ${self.api_key_env}, which is unset. "
                "Set it or use MockProvider for offline runs."
            )
        self._client = anthropic.Anthropic(api_key=api_key)
        return self._client

    def complete(
        self, messages: list[dict], tools: list[dict] | None = None
    ) -> ProviderResponse:
        client = self._ensure_client()
        kwargs: dict = {"model": self.model, "max_tokens": self.max_tokens, "messages": messages}
        if tools:
            kwargs["tools"] = tools
        resp = client.messages.create(**kwargs)
        return _to_provider_response(resp)


def _to_provider_response(resp) -> ProviderResponse:
    """Flatten an Anthropic Messages response: text blocks join into ``text``; ``tool_use``
    blocks become :class:`ToolCall` entries."""
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    for block in getattr(resp, "content", []) or []:
        block_type = getattr(block, "type", None)
        if block_type == "text":
            text_parts.append(getattr(block, "text", ""))
        elif block_type == "tool_use":
            tool_calls.append(
                ToolCall(tool_name=getattr(block, "name", ""), arguments=getattr(block, "input", {}) or {})
            )
    return ProviderResponse(text="".join(text_parts), tool_calls=tool_calls)
