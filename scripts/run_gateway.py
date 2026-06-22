#!/usr/bin/env python
"""Launch the Aegis FastAPI gateway (PDF FR-2).

By default it wraps the SDK around a deterministic mock provider so the gateway runs fully
offline. Set ``AEGIS_PROVIDER=claude`` (with ``ANTHROPIC_API_KEY``) to forward to a live model.

    python scripts/run_gateway.py            # mock provider, http://127.0.0.1:8000
    AEGIS_PROVIDER=claude python scripts/run_gateway.py
"""

from __future__ import annotations

import os

import uvicorn

from aegis.gateway import create_app
from aegis.providers import make_provider


def build_app():
    kind = os.environ.get("AEGIS_PROVIDER", "mock")
    provider = make_provider(kind) if kind != "mock" else None
    return create_app(provider=provider)


if __name__ == "__main__":
    uvicorn.run(build_app(), host=os.environ.get("AEGIS_HOST", "127.0.0.1"),
                port=int(os.environ.get("AEGIS_PORT", "8000")))
