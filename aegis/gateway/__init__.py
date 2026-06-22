"""The Aegis gateway — a thin HTTP front door that guards every model boundary.

The gateway owns no detection logic. It is a FastAPI app that wraps the :class:`~aegis.sdk.Aegis`
SDK and a :class:`~aegis.providers.base.Provider`, calling ``guard_request`` before the model,
``guard_tool_call`` on each tool the model asks for (so a blocked exfiltration never dispatches),
and ``guard_response`` on the model's text before it returns to the caller.

Use :func:`create_app` to build the application; it constructs offline defaults if no SDK or
provider is supplied, so the app stands up with no network.
"""

from __future__ import annotations

from aegis.gateway.app import create_app

__all__ = ["create_app"]
