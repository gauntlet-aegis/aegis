"""Text normalization shared by the shape detectors (edge-case hardening).

Attackers hide a credential from shape-based scanners with Unicode tricks: a zero-width space
spliced into a key, fullwidth/homoglyph characters, soft hyphens. Normalizing to NFKC and
stripping zero-width/invisible characters before scanning collapses those variants back to their
canonical ASCII form so the secret/canary patterns still match. Used by
:func:`aegis.detectors.secret_pattern.find_secrets` and :func:`aegis.detectors.encoding.decodings`.
"""

from __future__ import annotations

import re
import unicodedata

# Zero-width / invisible formatting characters used to splice inside a token without being seen:
# ZWSP, ZWNJ, ZWJ, word joiner, BOM/ZWNBSP, soft hyphen, LRM/RLM, and the LRO/RLO/PDF overrides.
_INVISIBLE = re.compile(
    "[​‌‍⁠﻿­‎‏‪‫‬‭‮]"
)


def nfkc_strip(text: str) -> str:
    """NFKC-normalize ``text`` and remove zero-width/invisible characters. Never raises."""
    if not text:
        return text
    try:
        return unicodedata.normalize("NFKC", _INVISIBLE.sub("", text))
    except (TypeError, ValueError):
        return text
