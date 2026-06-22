"""Encoding scanner (PDF section 6.2).

Attackers hide credentials from text-only filters by transforming them: base64, hex, URL-encoding,
reversal, leetspeak, or splitting a token across separators. This module decodes the common forms
*before* the secret/canary scans run, so an encoded credential is still caught.

It exposes a pure :func:`decodings` helper (the set of plausible decoded forms of a string, reused
by the tool-call argument scanner and honeytoken detector) plus an :class:`EncodingScanner`
detector that flags secrets which appear only after decoding.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
import urllib.parse

from aegis.decision import Action, Phase, Verdict
from aegis.detectors.base import DetectorResult
from aegis.detectors.normalize import nfkc_strip
from aegis.detectors.secret_pattern import find_secrets
from aegis.events import AegisEvent

_MAX_DECODE_DEPTH = 2  # follow base64-of-base64(-of-base64) nesting; bounded by the [:8] fan-out

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})


def _printable(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if s and all(31 < ord(c) < 127 or c in "\t\n\r" for c in s) else None


def decodings(text: str, *, _depth: int = 0) -> set[str]:
    """Plausible decoded forms of ``text`` (one level, plus one nested level for base64-of-hex etc.).

    Always includes transforms that are reversible regardless of content (reverse, leet, despaced);
    includes base64/hex/URL decodings only when they yield printable output. Never raises.
    """
    out: set[str] = set()
    if not text:
        return out

    # Unicode canonicalization: undo homoglyph / zero-width splicing so a decoded secret matches.
    normalized = nfkc_strip(text)
    if normalized != text:
        out.add(normalized)

    # Whole-string reversible transforms.
    out.add(text[::-1])
    out.add(text.translate(_LEET))
    despaced = re.sub(r"[\s._\-|:]+", "", text)
    if despaced != text:
        out.add(despaced)

    # URL-decode.
    try:
        u = urllib.parse.unquote(text)
        if u != text:
            out.add(u)
    except Exception:
        pass

    # Base64 substrings.
    for m in _B64_RUN.finditer(text):
        chunk = m.group(0)
        pad = chunk + "=" * (-len(chunk) % 4)
        try:
            dec = _printable(base64.b64decode(pad, validate=False))
            if dec:
                out.add(dec)
        except (binascii.Error, ValueError):
            pass

    # Hex substrings.
    for m in _HEX_RUN.finditer(text):
        chunk = m.group(0)
        if len(chunk) % 2 == 0:
            try:
                dec = _printable(bytes.fromhex(chunk))
                if dec:
                    out.add(dec)
            except ValueError:
                pass

    out.discard(text)

    # Follow nested encodings (e.g. base64 of base64, or base64 of a hex string) up to
    # _MAX_DECODE_DEPTH levels — bounded by the [:8] fan-out at each level to avoid blowup.
    if _depth < _MAX_DECODE_DEPTH:
        nested: set[str] = set()
        for d in list(out)[:8]:
            nested |= decodings(d, _depth=_depth + 1)
        out |= nested
        out.discard(text)
    return out


class EncodingScanner:
    """Detector: decode common encodings, then look for secret shapes that emerge only after
    decoding (a strong exfiltration signal — the raw text passed a naive filter)."""

    name = "encoding"
    phases = frozenset({Phase.TOOL_CALL, Phase.RESPONSE})

    def run(self, event: AegisEvent) -> DetectorResult:
        t0 = time.perf_counter()
        text = event.inspectable_text()
        raw_hits = {m.value for m in find_secrets(text)}
        found: list[dict] = []
        for decoded in decodings(text):
            for m in find_secrets(decoded):
                if m.value not in raw_hits:
                    found.append({"kind": m.kind, "decoded_preview": m.value[:4] + "…"})
        latency = (time.perf_counter() - t0) * 1000
        if not found:
            return DetectorResult(detector_name=self.name, score=0.0, verdict=Verdict.BENIGN,
                                  recommended_action=Action.ALLOW, latency_ms=latency)
        return DetectorResult(
            detector_name=self.name,
            score=0.97,
            confidence=0.9,
            verdict=Verdict.MALICIOUS,
            recommended_action=Action.BLOCK,
            evidence={"encoded_secrets": found[:5], "count": len(found)},
            latency_ms=latency,
        )
