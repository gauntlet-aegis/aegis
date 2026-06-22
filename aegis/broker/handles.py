"""Opaque credential handles (PDF section 6.5).

The model only ever sees opaque handles of the form ``secret://<service>/<name>`` — never a real
credential. The :class:`~aegis.broker.CredentialBroker` resolves a handle to its real secret ONLY
at the tool-execution boundary, outside model-visible context. These helpers parse and locate
handles; they hold no secrets themselves.
"""

from __future__ import annotations

import re

# secret://<service>/<name> — service and name are conservative identifier-ish tokens so a handle
# is easy to recognize and impossible to confuse with a real credential value.
HANDLE_RE = re.compile(r"secret://([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)")


def is_handle(s: str) -> bool:
    """True if ``s`` is exactly one opaque ``secret://service/name`` handle (nothing else)."""
    if not isinstance(s, str):
        return False
    m = HANDLE_RE.fullmatch(s.strip())
    return m is not None


def parse_handle(s: str) -> tuple[str, str] | None:
    """Return ``(service, name)`` for a lone handle, else ``None``. Never raises."""
    if not isinstance(s, str):
        return None
    m = HANDLE_RE.fullmatch(s.strip())
    return (m.group(1), m.group(2)) if m else None


def find_handles(text: str) -> list[str]:
    """Return every ``secret://service/name`` substring embedded anywhere in ``text``."""
    if not isinstance(text, str):
        return []
    return [m.group(0) for m in HANDLE_RE.finditer(text)]
