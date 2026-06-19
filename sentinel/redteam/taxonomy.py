"""The evasion taxonomy: encodings the red-team applies to a secret.

The string-level encodings (verbatim/base64/hex/rot13/leet/reverse) are reversible (leet is
best-effort) and are what DP-HONEY's scanner searches over. The higher-level strategies
(fragmentation/partial/paraphrase/multi-turn drip) are constructed in ``attacks.py``.
"""

from __future__ import annotations

import base64
import codecs
from enum import Enum


class Encoding(str, Enum):
    VERBATIM = "verbatim"
    BASE64 = "base64"
    HEX = "hex"
    ROT13 = "rot13"
    LEET = "leet"
    REVERSE = "reverse"
    FRAGMENTATION = "fragmentation"
    PARTIAL = "partial"
    PARAPHRASE = "paraphrase"
    MULTI_TURN_DRIP = "multi_turn_drip"


# Cleanly reversible string transforms (used for round-trip tests and scanner search).
REVERSIBLE = {Encoding.VERBATIM, Encoding.BASE64, Encoding.HEX, Encoding.ROT13, Encoding.REVERSE}

_LEET = {"o": "0", "i": "1", "e": "3", "a": "4", "s": "5", "t": "7", "b": "8"}
_LEET_INV = {v: k for k, v in _LEET.items()}


def leet_encode(s: str) -> str:
    return "".join(_LEET.get(c.lower(), c) for c in s)


def leet_decode(s: str) -> str:
    # Best-effort inverse (lossy where the original already contained digits).
    return "".join(_LEET_INV.get(c, c) for c in s)


def encode(secret: str, enc: Encoding) -> str:
    if enc == Encoding.VERBATIM:
        return secret
    if enc == Encoding.BASE64:
        return base64.b64encode(secret.encode()).decode()
    if enc == Encoding.HEX:
        return secret.encode().hex()
    if enc == Encoding.ROT13:
        return codecs.encode(secret, "rot13")
    if enc == Encoding.LEET:
        return leet_encode(secret)
    if enc == Encoding.REVERSE:
        return secret[::-1]
    raise ValueError(f"{enc} is not a string-level encoding; use attacks.py strategies")


def decode(payload: str, enc: Encoding) -> str:
    if enc == Encoding.VERBATIM:
        return payload
    if enc == Encoding.BASE64:
        return base64.b64decode(payload).decode()
    if enc == Encoding.HEX:
        return bytes.fromhex(payload).decode()
    if enc == Encoding.ROT13:
        return codecs.decode(payload, "rot13")
    if enc == Encoding.LEET:
        return leet_decode(payload)
    if enc == Encoding.REVERSE:
        return payload[::-1]
    raise ValueError(f"{enc} is not reversible")
