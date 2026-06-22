"""Tool-call argument scanner (the marquee differentiator — PDF section 6.3).

A request/response text scan catches a secret sitting in prose. The real exfiltration path,
though, is the *tool call*: an agent that has been steered (often by indirect injection in an
untrusted document) emits a structured tool invocation whose arguments smuggle a credential out
of the trust boundary — pasting an API key into an email body, base64-ing a token into a URL
query parameter, or stuffing a connection string into an HTTP header. This detector inspects the
structured arguments of high-risk tools with three independent lenses:

  a) credential check  — is a secret *shape* present in a free-form "exfil sink" field, either
     verbatim or only after decoding (base64/hex/url/reverse/leet)? That is exfiltration.
  b) provenance/taint  — did that credential-shaped value originate in UNTRUSTED content
     (a tool output / retrieved doc / pasted user text)? If so it is attacker-controlled and the
     confidence rises (this is the indirect-prompt-injection signature).
  c) schema validation — do the arguments match the declared shape of the tool? Unknown/extra
     fields, oversized strings, shell-metacharacter (RCE) shapes, or a URL pointing at a raw IP /
     disallowed scheme are *suspicious* (WARN), not outright malicious.

It combines per-lens findings and takes the single most severe one (never fuses scores — see
:func:`aegis.decision.most_severe`). Only the three declared tools are in scope; an unknown tool
or empty arguments returns a benign ALLOW result. The detector never raises on adversarial input
and never places a full secret value in its evidence (previews only).
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from aegis.decision import Action, Phase, TrustBoundary, Verdict
from aegis.detectors.base import DetectorResult
from aegis.detectors.encoding import decodings
from aegis.detectors.secret_pattern import find_secrets
from aegis.events import AegisEvent
from aegis.taint import TaintedSpan, provenance_of

# ---------------------------------------------------------------------------------------------
# Tool schema registry
# ---------------------------------------------------------------------------------------------

FieldKind = Literal["email", "url", "enum", "dict", "list", "short_str", "long_str", "sql"]


class FieldSpec(BaseModel):
    """Declared shape of a single tool argument.

    ``exfil_sink`` marks a free-form field where a credential could plausibly be smuggled out of
    the trust boundary (an email body, a URL/query, an HTTP header, a SQL string). A credential
    shape appearing in an exfil-sink field is treated as exfiltration; the same shape in a
    structured/typed field is far less alarming.
    """

    kind: FieldKind
    max_len: int | None = None
    exfil_sink: bool = False
    enum_values: frozenset[str] | None = None
    # Whether shell metacharacters / backticks in this field are anomalous (RCE shape). Free-form
    # bodies legitimately contain punctuation, so only "plain" fields are checked for this.
    plain: bool = False


class ToolSchema(BaseModel):
    """Declared argument specification for one supported high-risk tool."""

    fields: dict[str, FieldSpec]


# The three supported high-risk tools and their declared argument specs. Only these are in scope;
# any other tool name is out of scope and returns a benign result.
TOOL_SCHEMAS: dict[str, ToolSchema] = {
    "send_email": ToolSchema(
        fields={
            "to": FieldSpec(kind="email", max_len=320, plain=True),
            "subject": FieldSpec(kind="short_str", max_len=256, exfil_sink=True),
            "body": FieldSpec(kind="long_str", max_len=100_000, exfil_sink=True),
            "attachments": FieldSpec(kind="list", max_len=50),
        }
    ),
    "http_request": ToolSchema(
        fields={
            "url": FieldSpec(kind="url", max_len=8_192, exfil_sink=True),
            "method": FieldSpec(kind="enum", enum_values=frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})),
            "headers": FieldSpec(kind="dict", exfil_sink=True),
            "params": FieldSpec(kind="dict", exfil_sink=True),
            "body": FieldSpec(kind="long_str", max_len=1_000_000, exfil_sink=True),
        }
    ),
    "query_database": ToolSchema(
        fields={
            "query": FieldSpec(kind="sql", max_len=100_000, exfil_sink=True),
            "params": FieldSpec(kind="list", max_len=1_000),
        }
    ),
}

# Shell metacharacters / command-substitution shapes that should never appear in a "plain" field.
_RCE_SHAPE = re.compile(r"[;|&$()`]|\$\(|\b(?:rm|curl|wget|nc|bash|sh)\s")
# Schemes we consider safe for outbound HTTP-style requests; anything else (file://, gopher://,
# etc.) is anomalous and worth a WARN.
_ALLOWED_URL_SCHEMES = {"http", "https", ""}


class ArgFinding(BaseModel):
    """One per-argument finding, the structured proof placed in detector evidence.

    Never carries a full secret — ``value_preview`` is the first six characters plus an ellipsis.
    """

    tool: str
    arg: str
    value_preview: str
    risk_reason: str
    matched_credential_pattern: bool = False
    appeared_in_untrusted: bool = False
    encoding: Literal["verbatim", "decoded"] | None = None
    schema_violation: str | None = None
    # Internal severity used to pick the most severe finding (mirrors Action ordering).
    action: Action = Field(default=Action.ALLOW, exclude=True)
    verdict: Verdict = Field(default=Verdict.BENIGN, exclude=True)
    score: float = Field(default=0.0, exclude=True)
    confidence: float = Field(default=1.0, exclude=True)


def _preview(value: str) -> str:
    """First six characters of a value plus an ellipsis — never the full (possibly secret) value."""
    return value[:6] + "…"


class ToolCallArgumentScanner:
    """Detector: inspect the structured arguments of high-risk tool calls for credential
    exfiltration (verbatim or encoded), attacker-controlled (untrusted) provenance, and
    schema anomalies (oversized / RCE-shaped / extra fields / bad URL).

    Sits in the TOOL_CALL phase, alongside :class:`SecretPatternScanner` and
    :class:`EncodingScanner`, but is schema- and provenance-aware: it knows which fields are
    exfil sinks and can trace an argument value back to untrusted content.
    """

    name = "tool_call_args"
    phases = frozenset({Phase.TOOL_CALL})

    def run(self, event: AegisEvent) -> DetectorResult:
        t0 = time.perf_counter()
        tool = event.tool_name or ""
        schema = TOOL_SCHEMAS.get(tool)

        # Out of scope: unknown tool or no arguments -> benign. (Only declared tools are guarded.)
        if schema is None or not event.tool_arguments:
            return self._benign(t0)

        findings: list[ArgFinding] = []
        items = event.tool_arg_items()

        # Map each dotted arg name back to its top-level field spec (e.g. "params.q" -> "params").
        for arg_name, value in items:
            top = arg_name.split(".", 1)[0].split("[", 1)[0]
            spec = schema.fields.get(top)
            f = self._scan_arg(tool, arg_name, value, spec, event.spans)
            if f is not None:
                findings.append(f)

        # Schema-level finding: top-level fields present that the tool does not declare.
        present_top = {a.split(".", 1)[0].split("[", 1)[0] for a, _ in items}
        for extra in sorted(present_top - set(schema.fields)):
            findings.append(
                ArgFinding(
                    tool=tool, arg=extra, value_preview=_preview(str(event.tool_arguments.get(extra, ""))),
                    risk_reason="unexpected field not in tool schema",
                    schema_violation=f"unknown field '{extra}'",
                    action=Action.WARN, verdict=Verdict.SUSPICIOUS, score=0.45, confidence=0.7,
                )
            )

        if not findings:
            return self._benign(t0)

        worst = max(findings, key=lambda f: (int(f.action), f.score))
        latency = (time.perf_counter() - t0) * 1000
        return DetectorResult(
            detector_name=self.name,
            score=worst.score,
            confidence=worst.confidence,
            verdict=worst.verdict,
            recommended_action=worst.action,
            evidence={
                "tool": tool,
                "findings": [f.model_dump() for f in findings[:10]],
                "finding_count": len(findings),
            },
            latency_ms=latency,
        )

    # -- per-argument scanning ----------------------------------------------------------------
    def _scan_arg(self, tool: str, arg_name: str, value: str, spec: FieldSpec | None,
                  spans: list[TaintedSpan]) -> ArgFinding | None:
        """Apply the three lenses to a single argument; return the most severe finding, or None."""
        if not value:
            return None

        decoded_forms = decodings(value)

        # (a) CREDENTIAL CHECK — verbatim, then only-after-decoding.
        verbatim_secret = bool(find_secrets(value))
        decoded_secret = any(find_secrets(d) for d in decoded_forms)
        is_sink = bool(spec and spec.exfil_sink)

        if (verbatim_secret or decoded_secret) and is_sink:
            # (b) PROVENANCE — did this credential value (or an equivalent encoded form) come from
            # untrusted content? Attacker-controlled credential reaching a tool sink == injection.
            origin = provenance_of(value, spans, equivalent_forms=decoded_forms)
            untrusted = origin in (TrustBoundary.UNTRUSTED, TrustBoundary.MIXED)
            encoding: Literal["verbatim", "decoded"] = "verbatim" if verbatim_secret else "decoded"
            reason = "credential shape in exfil-sink tool argument"
            if encoding == "decoded":
                reason = "credential shape revealed only after decoding in exfil-sink argument"
            if untrusted:
                reason += "; value originated in untrusted content (attacker-controlled)"
            return ArgFinding(
                tool=tool, arg=arg_name, value_preview=_preview(value),
                risk_reason=reason,
                matched_credential_pattern=True,
                appeared_in_untrusted=untrusted,
                encoding=encoding,
                action=Action.BLOCK, verdict=Verdict.MALICIOUS,
                score=0.97, confidence=0.95 if untrusted else 0.9,
            )

        # (c) SCHEMA-AWARE VALIDATION — anomalies are suspicious (WARN), not malicious.
        if spec is not None:
            violation = self._schema_violation(spec, value)
            if violation is not None:
                return ArgFinding(
                    tool=tool, arg=arg_name, value_preview=_preview(value),
                    risk_reason=f"schema anomaly: {violation}",
                    schema_violation=violation,
                    action=Action.WARN, verdict=Verdict.SUSPICIOUS, score=0.5, confidence=0.7,
                )

        # A credential shape in a *non-sink* field — note it but treat as low-grade suspicious.
        if verbatim_secret or decoded_secret:
            return ArgFinding(
                tool=tool, arg=arg_name, value_preview=_preview(value),
                risk_reason="credential shape in a structured (non-sink) argument",
                matched_credential_pattern=True,
                encoding="verbatim" if verbatim_secret else "decoded",
                action=Action.WARN, verdict=Verdict.SUSPICIOUS, score=0.5, confidence=0.7,
            )
        return None

    def _schema_violation(self, spec: FieldSpec, value: str) -> str | None:
        """Return a human-readable schema violation for ``value`` under ``spec``, or None."""
        if spec.max_len is not None and len(value) > spec.max_len:
            return f"oversized value ({len(value)} > {spec.max_len} chars)"
        if spec.kind == "enum" and spec.enum_values is not None and value not in spec.enum_values:
            return f"value '{value[:16]}' not in allowed set"
        if spec.kind == "url":
            url_violation = self._url_violation(value)
            if url_violation is not None:
                return url_violation
        if spec.plain and _RCE_SHAPE.search(value):
            return "shell metacharacters / command-substitution shape in a plain field"
        return None

    def _url_violation(self, value: str) -> str | None:
        """Flag URLs with a disallowed scheme or a raw-IP host (SSRF / exfil-to-IP shapes)."""
        try:
            parts = urlsplit(value)
        except ValueError:
            return "unparseable URL"
        if parts.scheme not in _ALLOWED_URL_SCHEMES:
            return f"disallowed URL scheme '{parts.scheme}'"
        host = parts.hostname or ""
        if host:
            try:
                ipaddress.ip_address(host)
                return "URL points at a raw IP address"
            except ValueError:
                pass
        return None

    def _benign(self, t0: float) -> DetectorResult:
        return DetectorResult(
            detector_name=self.name, score=0.0, verdict=Verdict.BENIGN,
            recommended_action=Action.ALLOW, latency_ms=(time.perf_counter() - t0) * 1000,
        )
