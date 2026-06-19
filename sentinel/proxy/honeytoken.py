"""Honeytoken bookkeeping — a proxy property independent of the detectors (PRD §4.3).

Invariant: real credentials flow through the tool runtime and never enter model-visible
context; only honeytokens are model-visible. The ledger holds the bidirectional
real<->honeytoken map per conversation and substitutes honeytokens into outgoing context.

The honeytoken *generator* is pluggable: a trivial default lives here so the spine works
before DP-HONEY exists; DP-HONEY's DP-bigram generator is injected later.
"""

from __future__ import annotations

import re
import secrets
import string
from collections.abc import Callable
from dataclasses import dataclass, field

# A generator maps a format name to a fresh honeytoken string.
Generator = Callable[[str], str]

# Placeholder convention in incoming context: {{CREDENTIAL:name:fmt}}
# The proxy plants a honeytoken for (name, fmt) and substitutes the fake in. The real value, if
# any, is registered out-of-band and never appears in the placeholder.
_PLACEHOLDER = re.compile(r"\{\{CREDENTIAL:([^:}]+):([^}]+)\}\}")


def _default_generator(fmt: str) -> str:
    """Format-aware-ish placeholder honeytokens. Replaced by DP-HONEY's DP-bigram model."""
    alnum = string.ascii_letters + string.digits
    body = "".join(secrets.choice(alnum) for _ in range(20))
    prefixes = {
        "aws_access_key": "AKIA",
        "aws_secret_key": "",
        "openai_key": "sk-",
        "github_pat": "ghp_",
        "stripe_key": "sk_live_",
        "oauth_token": "ya29.",
    }
    return prefixes.get(fmt, "") + body


@dataclass
class Honeytoken:
    value: str
    fmt: str
    name: str  # the credential slot/name this fake stands in for
    conversation_id: str
    turn_planted: int


@dataclass
class HoneytokenLedger:
    """Conversation-scoped real<->honeytoken map. Real secrets never reach the model."""

    conversation_id: str
    generator: Generator = _default_generator
    _by_name: dict[str, Honeytoken] = field(default_factory=dict)
    _real_by_name: dict[str, str] = field(default_factory=dict)

    def register_real(self, name: str, real_value: str) -> None:
        """Record a real secret out-of-band. It is stored here, never placed in messages."""
        self._real_by_name[name] = real_value

    def plant(self, name: str, fmt: str, turn_index: int) -> Honeytoken:
        """Return the honeytoken standing in for ``name``, minting one on first use."""
        existing = self._by_name.get(name)
        if existing is not None:
            return existing
        token = Honeytoken(
            value=self.generator(fmt),
            fmt=fmt,
            name=name,
            conversation_id=self.conversation_id,
            turn_planted=turn_index,
        )
        self._by_name[name] = token
        return token

    def honeytokens(self) -> list[Honeytoken]:
        return list(self._by_name.values())

    def real_values(self) -> list[str]:
        return list(self._real_by_name.values())

    def substitute(self, text: str) -> str:
        """Defense-in-depth: scrub any registered real secret value from model-visible text,
        replacing it with the matching honeytoken so the model never sees the real value."""
        out = text
        for name, real in self._real_by_name.items():
            if real and real in out:
                token = self._by_name.get(name)
                if token is None:
                    # Mint a generic honeytoken if a slot wasn't explicitly planted.
                    token = self.plant(name, "generic", 0)
                out = out.replace(real, token.value)
        return out

    def leaked_real(self, text: str) -> bool:
        """True if any real secret appears verbatim in ``text`` (a guardrail / test hook)."""
        return any(real and real in text for real in self._real_by_name.values())


def inject_honeytokens(messages: list[dict], ledger: HoneytokenLedger, turn_index: int) -> list[dict]:
    """Replace {{CREDENTIAL:name:fmt}} placeholders with planted honeytokens, in place of a copy.

    This is the architectural property in action (PRD §4.3): only honeytokens become
    model-visible. Returns a new message list; the input is not mutated.
    """
    out: list[dict] = []
    for msg in messages:
        content = msg.get("content", "")

        def _sub(m: re.Match) -> str:
            name, fmt = m.group(1), m.group(2)
            return ledger.plant(name, fmt, turn_index).value

        new_content = _PLACEHOLDER.sub(_sub, content) if isinstance(content, str) else content
        # Safety net: scrub any registered real secret that slipped in verbatim.
        if isinstance(new_content, str):
            new_content = ledger.substitute(new_content)
        out.append({**msg, "content": new_content})
    return out
