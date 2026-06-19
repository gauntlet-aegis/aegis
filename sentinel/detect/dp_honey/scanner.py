"""Cross-encoding honeytoken scanner.

Detection = did the *planted value* appear in the output in any form? Because the target is
known and finite, encoding does not help the attacker. We (a) encode the token in each scheme
and search the output, (b) decode encoded-looking substrings of the output and search for the
token, and (c) normalize away separators to catch within-output fragmentation. Exact hits are
ground truth (-> block); the best partial overlap feeds the conformal fuzzy channel.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from sentinel.redteam.taxonomy import Encoding, encode

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
_HEX_RUN = re.compile(r"[0-9a-fA-F]{16,}")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")

# Encodings we proactively apply to the token and search for in the output.
_FORWARD = [Encoding.VERBATIM, Encoding.REVERSE, Encoding.ROT13, Encoding.LEET,
            Encoding.BASE64, Encoding.HEX]


@dataclass
class CanaryHit:
    token: str
    encoding: str
    exact: bool
    fragment_ratio: float

    def as_dict(self) -> dict:
        return {
            "token_tail": self.token[-6:],
            "encoding": self.encoding,
            "exact": self.exact,
            "fragment_ratio": round(self.fragment_ratio, 3),
        }


def _alnum(s: str) -> str:
    return _NON_ALNUM.sub("", s)


def _longest_overlap_ratio(token: str, text: str) -> float:
    """Longest contiguous shared run / len(token), on alphanumeric-normalized strings."""
    t, o = _alnum(token), _alnum(text)
    if not t:
        return 0.0
    m = SequenceMatcher(None, t, o).find_longest_match(0, len(t), 0, len(o))
    return m.size / len(t)


def _decoded_substrings(text: str) -> list[str]:
    out: list[str] = []
    for m in _B64_RUN.finditer(text):
        run = m.group()
        try:
            out.append(base64.b64decode(run + "=" * (-len(run) % 4)).decode("utf-8", "ignore"))
        except Exception:
            pass
    for m in _HEX_RUN.finditer(text):
        try:
            out.append(bytes.fromhex(m.group()).decode("utf-8", "ignore"))
        except Exception:
            pass
    return out


class CrossEncodingScanner:
    def scan(self, output_text: str, tokens: list[str]) -> list[CanaryHit]:
        hits: list[CanaryHit] = []
        for token in tokens:
            if not token:
                continue
            hit = self._match(output_text, token)
            if hit is not None:
                hits.append(hit)
        return hits

    def _match(self, output: str, token: str) -> CanaryHit | None:
        # (a) Encode the token each way and search the raw output.
        for enc in _FORWARD:
            needle = encode(token, enc)
            if needle and needle in output:
                return CanaryHit(token, enc.value, exact=True, fragment_ratio=1.0)

        # (b) Decode encoded-looking substrings and search for the verbatim token.
        for dec in _decoded_substrings(output):
            if token in dec:
                return CanaryHit(token, "decoded_blob", exact=True, fragment_ratio=1.0)

        # (c) Fragmentation: separators stripped, exact containment.
        if _alnum(token) and _alnum(token) in _alnum(output):
            return CanaryHit(token, "fragmentation", exact=True, fragment_ratio=1.0)

        # (d) Partial overlap -> fuzzy channel (conformal-calibrated downstream).
        ratio = _longest_overlap_ratio(token, output)
        if ratio > 0.0:
            return CanaryHit(token, "partial", exact=False, fragment_ratio=ratio)
        return None
