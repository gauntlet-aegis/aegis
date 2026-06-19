"""Black-box host: forwards to an OpenAI-compatible chat-completions API.

Exposes no activations, so CIFT is dropped from the pipeline (the registry handles that). This
is the API-only configuration from the PRD — same codebase, one stage absent.
"""

from __future__ import annotations

import time

import httpx

from sentinel.config import Settings
from sentinel.events.schema import Mode
from sentinel.model.host import GenResult, ModelHost


class BlackBoxHost(ModelHost):
    mode = Mode.BLACKBOX

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.bb = settings.blackbox
        self._client = httpx.Client(timeout=60.0)

    def generate(self, messages: list[dict]) -> GenResult:
        t0 = time.perf_counter()
        headers = {"Content-Type": "application/json"}
        if (key := self.settings.api_key()):
            headers["Authorization"] = f"Bearer {key}"
        payload = {
            "model": self.bb.model,
            "messages": messages,
            "max_tokens": self.settings.max_new_tokens,
            "stream": False,
        }
        resp = self._client.post(
            f"{self.bb.base_url}/chat/completions", json=payload, headers=headers
        )
        resp.raise_for_status()
        data = resp.json()
        text = data["choices"][0]["message"]["content"] or ""
        usage = data.get("usage", {})
        return GenResult(
            text=text,
            activations=None,
            token_count=usage.get("completion_tokens", 0),
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
