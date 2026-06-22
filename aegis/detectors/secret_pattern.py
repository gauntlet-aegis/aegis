"""Secret-pattern scanner (PDF section 6.2).

Detects credential *shapes* — API keys, tokens, private-key blocks, connection strings — by
format. Exposes a pure :func:`find_secrets` matcher (reused by the encoding scanner, the
tool-call argument scanner, and the honeytoken detector) plus a :class:`SecretPatternScanner`
detector. Deliberately avoids well-known documentation/example tokens to keep false positives
rare on benign developer text (PDF risk: "false positives make the demo look brittle").
"""

from __future__ import annotations

import re
import time

from pydantic import BaseModel

from aegis.decision import Action, Phase, Verdict
from aegis.detectors.base import DetectorResult
from aegis.detectors.normalize import nfkc_strip
from aegis.events import AegisEvent

# (kind, compiled pattern). Order matters only for labelling; all are tried.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("stripe_live_key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("oauth_bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("connection_string", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s\"']+:[^\s\"'@]+@[^\s\"']+")),
]

# AWS-style secret access keys are 40-char base64-ish strings — high false-positive risk. Only
# flag them when an explicit credential cue is nearby, or when paired with an access-key id.
_SECRET_KEY_KINDS = {"aws_secret_access_key"}
_CREDENTIAL_CUE = re.compile(r"(?i)(secret|password|passwd|token|api[_-]?key|access[_-]?key|credential)")
# A 40-char run that is ALL hexadecimal is almost certainly a SHA-1 / git sha / hex digest, not an
# AWS secret key (which is base64 with mixed case). Excluding these cuts the common benign FP.
_HEX_40 = re.compile(r"^[0-9a-fA-F]{40}$")

# Known public documentation/example values that must never trip the scanner.
_EXAMPLE_TOKENS = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}


class SecretMatch(BaseModel):
    kind: str
    value: str
    start: int
    end: int


def find_secrets(text: str) -> list[SecretMatch]:
    """Return all credential-shaped matches in ``text`` (never raises; example tokens excluded).

    ``text`` is NFKC-normalized with zero-width characters stripped first, so a key hidden with
    homoglyphs or a spliced-in zero-width space is still matched.
    """
    if not text:
        return []
    text = nfkc_strip(text)
    matches: list[SecretMatch] = []
    has_cue = bool(_CREDENTIAL_CUE.search(text))
    has_access_key = any(_PATTERNS[0][1].search(text) for _ in (0,))
    for kind, pat in _PATTERNS:
        for m in pat.finditer(text):
            val = m.group(0)
            if val in _EXAMPLE_TOKENS:
                continue
            # Gate the noisy 40-char secret-key shape behind an explicit cue or a paired key id,
            # and never treat an all-hex 40-char digest (SHA-1 / git sha) as an AWS secret key.
            if kind in _SECRET_KEY_KINDS:
                if not (has_cue or has_access_key):
                    continue
                if _HEX_40.match(val):
                    continue
            matches.append(SecretMatch(kind=kind, value=val, start=m.start(), end=m.end()))
    return _dedupe(matches)


def _dedupe(matches: list[SecretMatch]) -> list[SecretMatch]:
    """Drop matches fully contained within another (e.g. a 40-char run inside a longer token)."""
    out: list[SecretMatch] = []
    for m in sorted(matches, key=lambda x: (x.start, -(x.end - x.start))):
        if any(o.start <= m.start and m.end <= o.end and o is not m for o in matches if o.kind != m.kind and (o.end - o.start) > (m.end - m.start)):
            continue
        out.append(m)
    return out


class SecretPatternScanner:
    """Detector wrapper around :func:`find_secrets`. Recommends BLOCK when a secret shape appears
    in a tool call or response (a credential leaving the boundary); flags requests as suspicious."""

    name = "secret_pattern"
    phases = frozenset({Phase.REQUEST, Phase.TOOL_CALL, Phase.RESPONSE})

    def run(self, event: AegisEvent) -> DetectorResult:
        t0 = time.perf_counter()
        text = event.inspectable_text()
        matches = find_secrets(text)
        latency = (time.perf_counter() - t0) * 1000
        if not matches:
            return DetectorResult(detector_name=self.name, score=0.0, verdict=Verdict.BENIGN,
                                  recommended_action=Action.ALLOW, latency_ms=latency)
        # A secret shape leaving via tool-call/response is a leak; in the request it's suspicious.
        leaving = event.phase in (Phase.TOOL_CALL, Phase.RESPONSE)
        return DetectorResult(
            detector_name=self.name,
            score=0.95 if leaving else 0.6,
            confidence=0.9,
            verdict=Verdict.MALICIOUS if leaving else Verdict.SUSPICIOUS,
            recommended_action=Action.BLOCK if leaving else Action.WARN,
            evidence={"kinds": sorted({m.kind for m in matches}),
                      "count": len(matches),
                      "preview": [{"kind": m.kind, "value_preview": m.value[:4] + "…"} for m in matches[:5]]},
            latency_ms=latency,
        )
