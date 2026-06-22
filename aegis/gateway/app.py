"""FastAPI factory wiring the Aegis SDK across one chat-completions boundary.

The gateway's whole value is that it guards at *every* seam of a model turn and never trusts the
model: it scans the inbound request, refuses to call the provider if the request is blocked, scans
each tool call the model emits and **drops** any that is blocked (the marquee exfiltration defense),
and scans the model's text before returning it (sanitizing or refusing as the decision dictates).

This module is deliberately a thin wrapper: it calls :class:`~aegis.sdk.Aegis` guards and serializes
their :class:`~aegis.decision.AegisDecision` results — it never re-implements detection. It fits
between an agent/client and a model provider (see :mod:`aegis.providers`).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel, Field

from aegis.decision import Action, AegisDecision
from aegis.providers import MockProvider, Provider
from aegis.providers.mock import benign_response
from aegis.sdk import Aegis

# Text returned to the caller when a guard refuses to forward content (BLOCK/ESCALATE). The
# gateway never echoes the offending payload back; it returns this fixed, non-disclosing string.
_REFUSAL_TEXT = "This request was blocked by Aegis security policy."


def _serialize_decision(decision: AegisDecision) -> dict:
    """Flatten an :class:`AegisDecision` into the compact dict the endpoint reports per boundary."""
    return {
        "action": decision.action.name,
        "allowed": decision.allowed,
        "risk_score": decision.risk_score,
        "reasons": decision.reasons,
        "trace_id": decision.trace_id,
    }


class ChatRequest(BaseModel):
    """Body for ``POST /v1/chat/completions`` — the conversation plus optional tool schemas."""

    messages: list[dict] = Field(..., description="Role/content message dicts, oldest first.")
    tools: list[dict] | None = Field(default=None, description="Tool schemas the model may call.")
    session_id: str | None = Field(default=None, description="Conversation id for cumulative budgets.")


class ChatResponse(BaseModel):
    """Body returned by ``POST /v1/chat/completions``.

    ``output`` is the final (possibly sanitized or refused) text; ``tool_calls`` contains only the
    tool calls Aegis allowed to dispatch; ``aegis`` reports the decision at each guarded boundary."""

    output: str
    tool_calls: list[dict] = Field(default_factory=list)
    aegis: dict


def create_app(
    aegis: Aegis | None = None,
    provider: Provider | None = None,
    *,
    policy_path: str | Path = "aegis/policy/default.yaml",
) -> FastAPI:
    """Build the gateway app. Falls back to offline defaults (default policy + a benign-scripted
    :class:`MockProvider`) so the app constructs with no network and no external config."""
    aegis = aegis or Aegis.from_config(policy_path)
    provider = provider or MockProvider([benign_response()])

    app = FastAPI(title="Aegis Gateway", version="1.0")

    @app.get("/healthz")
    def healthz() -> dict:
        """Liveness probe."""
        return {"status": "ok"}

    @app.get("/")
    def root() -> dict:
        """Brief description of what this gateway fronts."""
        return {
            "service": "aegis-gateway",
            "description": "Guards model requests, tool calls, and responses via the Aegis SDK.",
            "provider": provider.name,
        }

    @app.post("/v1/chat/completions", response_model=ChatResponse)
    def chat_completions(req: ChatRequest) -> ChatResponse:
        """Guard a model turn end to end. See the module docstring for the boundary-by-boundary flow."""
        session_id = req.session_id or "default"

        # (a) Guard the inbound request. Only a BLOCK/ESCALATE stops the provider call; a WARN
        #     annotates and proceeds (observe mode clamps to WARN and must never block).
        request_decision = aegis.guard_request(req.messages, req.tools, session_id=session_id)
        if request_decision.blocks:
            return ChatResponse(
                output=_REFUSAL_TEXT,
                tool_calls=[],
                aegis={"request": _serialize_decision(request_decision)},
            )

        # (b) Call the provider for the model turn (request already cleared). A provider failure
        #     (network/timeout/upstream 500) returns a graceful refusal, never a bare gateway 500.
        try:
            provider_response = provider.complete(req.messages, req.tools)
        except Exception:
            return ChatResponse(
                output="Upstream model provider error; the request was not completed.",
                tool_calls=[],
                aegis={"request": _serialize_decision(request_decision), "provider_error": True},
            )

        # (c) Guard each tool call. Only allowed calls are forwarded; a blocked call is dropped
        #     before dispatch — the marquee exfiltration defense.
        tool_decisions: list[dict] = []
        allowed_tool_calls: list[dict] = []
        for tc in provider_response.tool_calls:
            decision = aegis.guard_tool_call(tc.tool_name, tc.arguments, session_id=session_id)
            tool_decisions.append(_serialize_decision(decision))
            if decision.blocks:
                continue  # the marquee defense: a blocked tool call is never dispatched
            # SANITIZE forwards redacted arguments; WARN/ALLOW forward the originals.
            args = decision.sanitized_payload if decision.action is Action.SANITIZE else tc.arguments
            allowed_tool_calls.append({"tool_name": tc.tool_name, "arguments": args})

        # (d) Guard the model's text. SANITIZE swaps in the redacted payload; BLOCK/ESCALATE refuse.
        response_decision = aegis.guard_response(provider_response.text, session_id=session_id)
        if response_decision.action is Action.SANITIZE:
            output = str(response_decision.sanitized_payload or "")
        elif response_decision.action in (Action.BLOCK, Action.ESCALATE):
            output = _REFUSAL_TEXT
        else:
            output = provider_response.text

        return ChatResponse(
            output=output,
            tool_calls=allowed_tool_calls,
            aegis={
                "request": _serialize_decision(request_decision),
                "tools": tool_decisions,
                "response": _serialize_decision(response_decision),
            },
        )

    return app
