"""Honeytokens (PDF section 6.4) — plant unique, format-matched canary credentials into
model-visible context and treat any downstream reappearance as ground-truth exfiltration.

Three pieces fit together: :mod:`generator` builds DP-flavored, format-valid canary strings
(trained only on synthetic examples); :mod:`registry` tracks which canary was planted where for
a session; and :class:`aegis.detectors.honeytoken.HoneytokenDetector` scans tool calls and
responses for any registered canary (verbatim or decoded) and reports a leak.
"""
