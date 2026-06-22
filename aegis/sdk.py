"""The Aegis SDK — the single source of truth for security decisions (PDF section 4.1/4.2).

Everything else (the gateway, the eval harness, the dashboard) calls these three guards rather
than re-implementing detection logic:

- :meth:`Aegis.guard_request`  — scan prompt + retrieved context + declared tools before a model call.
- :meth:`Aegis.guard_tool_call` — scan structured tool arguments **before** dispatch (the marquee).
- :meth:`Aegis.guard_response` — scan model output before it returns to the user.

Each returns an :class:`~aegis.decision.AegisDecision`. The SDK owns the detector set, the policy
engine, the credential broker, the honeytoken registry, and the cumulative leakage ledger, and
wires them into one :class:`~aegis.pipeline.Pipeline`.
"""

from __future__ import annotations

from pathlib import Path

import uuid

from aegis.broker import CredentialBroker, FakeSecretStore
from aegis.decision import Action, AegisDecision
from aegis.detectors.encoding import EncodingScanner
from aegis.detectors.honeytoken import HoneytokenDetector
from aegis.detectors.ledger import LeakageLedger, NimbusLiteLedger
from aegis.detectors.secret_pattern import SecretPatternScanner
from aegis.detectors.tool_call_args import ToolCallArgumentScanner
from aegis.events import AegisEvent
from aegis.honeytokens.registry import HoneytokenRegistry
from aegis.pipeline import Pipeline
from aegis.policy import PolicyEngine, load_policy
from aegis.obs.trace import TraceSink


class Aegis:
    """Top-level SDK facade. Construct with :meth:`from_config` for the default detector stack."""

    def __init__(self, policy_engine: PolicyEngine, *, store: FakeSecretStore | None = None,
                 registry: HoneytokenRegistry | None = None, ledger: LeakageLedger | None = None,
                 local_test_mode: bool = False, trace_path: str | Path | None = None) -> None:
        self.store = store or FakeSecretStore()
        self.registry = registry or HoneytokenRegistry()
        self.ledger = ledger or LeakageLedger()
        self.broker = CredentialBroker(self.store, local_test_mode=local_test_mode)
        detectors = [
            SecretPatternScanner(),
            EncodingScanner(),
            ToolCallArgumentScanner(),
            HoneytokenDetector(self.registry),
            NimbusLiteLedger(self.ledger),
        ]
        trace = TraceSink(trace_path, local_test_mode=local_test_mode,
                          known_secrets=self.store.all_values()) if trace_path else None
        self.pipeline = Pipeline(detectors, policy_engine, broker=self.broker,
                                 trace_sink=trace, local_test_mode=local_test_mode)

    @classmethod
    def from_config(cls, policy_path: str | Path, **kwargs) -> "Aegis":
        return cls(PolicyEngine(load_policy(policy_path)), **kwargs)

    # ---- guards -------------------------------------------------------------------------
    # The guards normalize malformed input at the boundary and never raise — a guard must always
    # return a decision (an exception would let an unevaluated request through, or 500 the gateway).
    def guard_request(self, messages, tools=None, *, session_id: str = "default",
                      metadata: dict | None = None) -> AegisDecision:
        try:
            ev = AegisEvent.for_request(_norm_messages(messages),
                                        tools=tools if isinstance(tools, list) else None,
                                        session_id=session_id or "default", metadata=metadata)
            return self.pipeline.run(ev)
        except Exception as exc:  # last-resort: never raise out of a guard
            return _fail_safe(exc)

    def guard_tool_call(self, tool_name, arguments, *, session_id: str = "default",
                        spans=None, metadata: dict | None = None) -> AegisDecision:
        try:
            ev = AegisEvent.for_tool_call(str(tool_name or ""), _norm_args(arguments),
                                          session_id=session_id or "default", spans=spans,
                                          metadata=metadata)
            return self.pipeline.run(ev)
        except Exception as exc:
            return _fail_safe(exc)

    def guard_response(self, output, *, session_id: str = "default", spans=None,
                       metadata: dict | None = None) -> AegisDecision:
        try:
            text = output if isinstance(output, str) else ("" if output is None else str(output))
            ev = AegisEvent.for_response(text, session_id=session_id or "default", spans=spans,
                                         metadata=metadata)
            return self.pipeline.run(ev)
        except Exception as exc:
            return _fail_safe(exc)

    # ---- honeytokens --------------------------------------------------------------------
    def plant_honeytoken(self, service: str, fmt: str, location: str, *, session_id: str = "default"):
        """Register a canary and return it; the caller injects ``canary.token`` into model-visible
        context only. Its later appearance in output/tool args is a ground-truth leak."""
        return self.registry.register(service, fmt, location, session_id=session_id)

    def resolve_tool_arguments(self, arguments: dict) -> dict:
        """Resolve ``secret://`` handles to real values at the tool boundary (outside model context)."""
        return self.broker.resolve_arguments(arguments)


def _norm_messages(messages) -> list[dict]:
    """Coerce ``messages`` into a list of role/content dicts; tolerate None/str/odd shapes."""
    if messages is None:
        return []
    if isinstance(messages, str):
        return [{"role": "user", "content": messages}]
    if not isinstance(messages, (list, tuple)):
        return [{"role": "user", "content": str(messages)}]
    return [m if isinstance(m, dict) else {"role": "user", "content": str(m)} for m in messages]


def _norm_args(arguments) -> dict:
    """Coerce tool ``arguments`` into a dict; a non-dict is wrapped so it is still scanned."""
    if isinstance(arguments, dict):
        return arguments
    if arguments is None:
        return {}
    return {"value": arguments}


def _fail_safe(exc: Exception) -> AegisDecision:
    """Last-resort decision when a guard hits an unexpected internal error: WARN (forward but flag)
    with an explainable reason, rather than raising and letting the input through unevaluated."""
    return AegisDecision(
        action=Action.WARN, risk_score=0.0,
        reasons=[f"aegis guard could not evaluate input safely ({type(exc).__name__}); flagged"],
        trace_id=f"trace_err_{uuid.uuid4().hex[:8]}", event_id=f"evt_err_{uuid.uuid4().hex[:8]}",
    )
