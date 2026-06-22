"""The normalized event (PDF section 4.3) — the single object every detector inspects.

One event represents one guarded surface: a request (model-visible messages + declared tools),
a tool call (name + structured arguments), or a response (model output). It carries both the
raw inspectable content (so detectors can work) and a redacted ``input_summary`` (so logs and
the dashboard never spill secrets).
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field

from aegis.decision import Phase, TrustBoundary
from aegis.detectors.base import DetectorResult
from aegis.taint import TaintedSpan, overall_boundary, spans_from_messages


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class AegisEvent(BaseModel):
    """Normalized representation of one guarded turn-surface.

    Construct via the :meth:`for_request` / :meth:`for_tool_call` / :meth:`for_response`
    factories rather than by hand — they wire up ids, taint spans, and the trust boundary.
    """

    event_id: str = Field(default_factory=lambda: _new_id("evt"))
    trace_id: str = Field(default_factory=lambda: _new_id("trace"))
    session_id: str = "default"
    phase: Phase
    trusted_boundary: TrustBoundary = TrustBoundary.MIXED

    # Phase-specific payloads (exactly one cluster is populated per phase).
    messages: list[dict] | None = None          # REQUEST
    declared_tools: list[dict] | None = None     # REQUEST (tool schemas, for schema-aware checks)
    tool_name: str | None = None                 # TOOL_CALL
    tool_arguments: dict | None = None           # TOOL_CALL
    output_text: str | None = None               # RESPONSE

    # Provenance + secret bookkeeping.
    spans: list[TaintedSpan] = Field(default_factory=list)
    secret_handles_seen: list[str] = Field(default_factory=list)

    # Display + audit.
    input_summary: str = ""        # redacted, safe for logs/dashboard
    raw_content_ref: str | None = None
    detector_evidence: list[DetectorResult] = Field(default_factory=list)
    policy_decision: dict | None = None
    metadata: dict = Field(default_factory=dict)

    # ---- content surface for detectors --------------------------------------------------
    def inspectable_text(self) -> str:
        """The flat text a text-oriented detector should scan for this phase."""
        if self.phase is Phase.REQUEST and self.messages:
            return "\n".join(str(m.get("content", "")) for m in self.messages)
        if self.phase is Phase.RESPONSE:
            return self.output_text or ""
        if self.phase is Phase.TOOL_CALL and self.tool_arguments is not None:
            return "\n".join(f"{k}={v}" for k, v in _flatten(self.tool_arguments))
        return ""

    def tool_arg_items(self) -> list[tuple[str, str]]:
        """Flattened (dotted-name, string-value) pairs of tool arguments, for the arg scanner."""
        return [(k, str(v)) for k, v in _flatten(self.tool_arguments or {})]

    # ---- factories ----------------------------------------------------------------------
    @classmethod
    def for_request(cls, messages: list[dict], *, tools: list[dict] | None = None,
                    session_id: str = "default", metadata: dict | None = None) -> "AegisEvent":
        spans = spans_from_messages(messages)
        return cls(phase=Phase.REQUEST, messages=messages, declared_tools=tools,
                   session_id=session_id, spans=spans,
                   trusted_boundary=overall_boundary(spans), metadata=metadata or {})

    @classmethod
    def for_tool_call(cls, tool_name: str, arguments: dict, *, session_id: str = "default",
                      spans: list[TaintedSpan] | None = None, metadata: dict | None = None) -> "AegisEvent":
        spans = spans or []
        return cls(phase=Phase.TOOL_CALL, tool_name=tool_name, tool_arguments=arguments,
                   session_id=session_id, spans=spans,
                   trusted_boundary=overall_boundary(spans) if spans else TrustBoundary.MIXED,
                   metadata=metadata or {})

    @classmethod
    def for_response(cls, output_text: str, *, session_id: str = "default",
                     spans: list[TaintedSpan] | None = None, metadata: dict | None = None) -> "AegisEvent":
        spans = spans or []
        return cls(phase=Phase.RESPONSE, output_text=output_text, session_id=session_id,
                   spans=spans, trusted_boundary=overall_boundary(spans) if spans else TrustBoundary.TRUSTED,
                   metadata=metadata or {})


def _flatten(obj, prefix: str = "") -> list[tuple[str, object]]:
    """Flatten nested dicts/lists into dotted-path leaves, e.g. {'a': {'b': 1}} -> [('a.b', 1)]."""
    out: list[tuple[str, object]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            out.extend(_flatten(v, f"{prefix}[{i}]"))
    else:
        out.append((prefix, obj))
    return out
