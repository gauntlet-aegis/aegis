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

from aegis.broker import CredentialBroker, FakeSecretStore
from aegis.decision import AegisDecision
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
    def guard_request(self, messages: list[dict], tools: list[dict] | None = None, *,
                      session_id: str = "default", metadata: dict | None = None) -> AegisDecision:
        return self.pipeline.run(AegisEvent.for_request(messages, tools=tools,
                                                        session_id=session_id, metadata=metadata))

    def guard_tool_call(self, tool_name: str, arguments: dict, *, session_id: str = "default",
                        spans=None, metadata: dict | None = None) -> AegisDecision:
        return self.pipeline.run(AegisEvent.for_tool_call(tool_name, arguments,
                                                          session_id=session_id, spans=spans,
                                                          metadata=metadata))

    def guard_response(self, output: str, *, session_id: str = "default", spans=None,
                       metadata: dict | None = None) -> AegisDecision:
        return self.pipeline.run(AegisEvent.for_response(output, session_id=session_id,
                                                         spans=spans, metadata=metadata))

    # ---- honeytokens --------------------------------------------------------------------
    def plant_honeytoken(self, service: str, fmt: str, location: str, *, session_id: str = "default"):
        """Register a canary and return it; the caller injects ``canary.token`` into model-visible
        context only. Its later appearance in output/tool args is a ground-truth leak."""
        return self.registry.register(service, fmt, location, session_id=session_id)

    def resolve_tool_arguments(self, arguments: dict) -> dict:
        """Resolve ``secret://`` handles to real values at the tool boundary (outside model context)."""
        return self.broker.resolve_arguments(arguments)
