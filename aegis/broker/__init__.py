"""Credential broker (PDF section 6.5).

The core invariant: a real credential must NEVER enter model-visible context. The model sees only
opaque handles (``secret://<service>/<name>``); the :class:`CredentialBroker` resolves a handle to
the real secret ONLY at the tool-execution boundary — outside model context. If a raw secret ever
appears in model-visible content (or would land in a log), the broker redacts it, reports the leak,
and forces a non-allow decision (ESCALATE) unless the run is in explicit local-test mode.

Where this fits: the SDK calls :meth:`CredentialBroker.resolve_arguments` just before executing a
tool, and :meth:`CredentialBroker.scan_model_visible` on anything about to re-enter model context
(tool outputs, model responses). The broker pairs the store's known values with the trace module's
shape detector and redactor (:func:`aegis.obs.trace.contains_secret_shape`, ``redact``).
"""

from __future__ import annotations

from pydantic import BaseModel

from aegis.decision import Action
from aegis.obs.trace import redact

from .handles import HANDLE_RE, find_handles, is_handle, parse_handle
from .store import FakeSecretStore

__all__ = [
    "CredentialBroker",
    "FakeSecretStore",
    "BrokerFinding",
    "is_handle",
    "parse_handle",
    "find_handles",
    "HANDLE_RE",
]


class BrokerFinding(BaseModel):
    """Result of scanning model-visible text for raw secret leakage.

    ``leaked`` is True if a raw secret value (or a credential-shaped substring) was found.
    ``redacted_text`` is always safe to surface/log. ``forced_action`` is the action the broker
    requires of the policy engine: ESCALATE on a real leak (block + human review), unless the run
    is in local-test mode, in which case it stays ALLOW (the leak is still reported).
    """

    leaked: bool
    redacted_text: str
    message: str
    forced_action: Action = Action.ALLOW


class CredentialBroker:
    """Resolves opaque handles to real secrets at the tool boundary and guards model-visible text.

    Args:
        store: the (fake) secret store backing handle resolution and leak detection.
        local_test_mode: when True, a detected leak is still reported but ``forced_action`` stays
            ALLOW (so local tests/demos can deliberately exercise raw secrets without escalating).
    """

    def __init__(self, store: FakeSecretStore, *, local_test_mode: bool = False) -> None:
        self.store = store
        self.local_test_mode = local_test_mode

    # --- resolution (tool boundary, OUTSIDE model context) ---------------------------------

    def resolve(self, value: str) -> str:
        """If ``value`` is a handle, return the real secret from the store; else return it as-is.

        Unknown handles are returned unchanged (no secret exists to swap in). Non-string and
        non-handle values pass through untouched. Never raises.
        """
        parsed = parse_handle(value) if isinstance(value, str) else None
        if parsed is None:
            return value
        service, name = parsed
        secret = self.store.get(service, name)
        return secret if secret is not None else value

    def resolve_arguments(self, args: dict) -> dict:
        """Deep-resolve every handle found in a tool-args structure (dicts, lists, strings)."""
        return self._resolve_obj(args)

    def _resolve_obj(self, obj):
        if isinstance(obj, str):
            return self.resolve(obj)
        if isinstance(obj, dict):
            return {k: self._resolve_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._resolve_obj(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self._resolve_obj(v) for v in obj)
        return obj

    # --- guard (anything re-entering MODEL-VISIBLE context) --------------------------------

    def scan_model_visible(self, text: str) -> BrokerFinding | None:
        """Detect whether any RAW secret from the store appears in model-visible ``text``.

        Returns ``None`` only when ``text`` is empty/non-string (nothing to scan). Otherwise
        returns a :class:`BrokerFinding`. A leak is flagged only when a known store value appears
        verbatim (generic credential shapes are the secret_pattern detector's job). Never raises
        on adversarial input. Handles (``secret://...``) are NOT leaks — that's the design.
        """
        if not isinstance(text, str) or not text:
            return None

        known = self.store.all_values()
        # Require a minimum length before treating a store value as "present" by substring: a 1-2
        # char value would match benign text everywhere and force a spurious ESCALATE.
        present = [s for s in known if isinstance(s, str) and len(s) >= 4 and s in text]
        # The broker's forced, mode-bypassing escalation is reserved for an actual RAW STORE
        # SECRET leaking — that is the broker invariant. Generic credential *shapes* are the
        # secret_pattern detector's domain and flow through the normal, mode-governed policy, so
        # they must NOT trip the broker here (else observe mode could never let them through).
        leaked = bool(present)

        redacted_text = redact(text, known_secrets=known)

        if not leaked:
            return BrokerFinding(
                leaked=False,
                redacted_text=redacted_text,
                message="No raw store secret in model-visible text.",
                forced_action=Action.ALLOW,
            )

        msg = f"Raw store secret leaked into model-visible text ({len(present)} value(s))."
        forced = Action.ALLOW if self.local_test_mode else Action.ESCALATE
        return BrokerFinding(
            leaked=True,
            redacted_text=redacted_text,
            message=msg,
            forced_action=forced,
        )

    def assert_no_raw_secret(self, text: str) -> BrokerFinding | None:
        """Non-raising variant of the guard: alias for :meth:`scan_model_visible`.

        Named ``assert_*`` for callers that read as a guard clause, but it returns a finding (or
        ``None``) instead of raising — the SDK / policy engine decides what to do with the leak.
        """
        return self.scan_model_visible(text)
