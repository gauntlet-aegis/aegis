"""Registry-driven secret scanner and auto-decoy helpers.

The scanner derives candidate patterns from each scannable ``FormatSpec`` and
confirms matches with the spec's own ``validate()`` method. Per SAFE-1, findings
never store, log, or return the matched secret value.
"""

from __future__ import annotations

import re
from functools import lru_cache

from .bigram import generate_honeytokens
from .formats import get_format, list_formats
from .grammar import Checksum, FormatSpec, Literal, Variable

_BOUNDARY_BEFORE = r"(?<![A-Za-z0-9_./+-])"
_BOUNDARY_AFTER = r"(?![A-Za-z0-9_/+-])"
_CHECKSUM_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}


def _segment_pattern(spec: FormatSpec) -> str:
    parts: list[str] = []
    for segment in spec.segments:
        if isinstance(segment, Literal):
            parts.append(re.escape(segment.text))
        elif isinstance(segment, Variable):
            parts.append(f"[{re.escape(segment.alphabet)}]{{{segment.length}}}")
        elif isinstance(segment, Checksum):
            parts.append(f"[{_CHECKSUM_ALPHABET}]{{{segment.length}}}")
    return "".join(parts)


@lru_cache(maxsize=None)
def detection_pattern(slug: str) -> re.Pattern[str]:
    """Return the compiled detection regex for a registered format slug."""
    spec = get_format(slug)
    return re.compile(_BOUNDARY_BEFORE + _segment_pattern(spec) + _BOUNDARY_AFTER)


def scan(text: str) -> list[dict[str, int | str]]:
    """Return ``{format, start, end, confidence}`` findings for *text*.

    SAFE-1: matched values are used only as local validation candidates and are
    never included in returned findings.
    """
    raw: list[dict[str, int | str]] = []
    for spec in _scannable_specs():
        checksummed = _has_checksum(spec)
        for match in detection_pattern(spec.slug).finditer(text):
            candidate = match.group(0)
            if not spec.validate(candidate):
                continue
            raw.append(
                {
                    "format": spec.slug,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": "high" if checksummed else "medium",
                }
            )
    return _dedupe(raw)


def auto_decoy(text: str, *, seed: int = 0) -> dict[str, object]:
    """Scan *text*, generate one matching decoy per finding, and swap spans."""
    findings = scan(text)
    decoys: list[str] = []
    for index, finding in enumerate(findings):
        original = text[int(finding["start"]) : int(finding["end"])]
        decoy = original
        attempt = 0
        while decoy == original and attempt < 1000:
            sample_seed = seed + (index * 1000) + attempt
            decoy = generate_honeytokens(str(finding["format"]), count=1, sample_seed=sample_seed)[0]
            attempt += 1
        decoys.append(decoy)

    swapped = text
    replacements = zip(findings, decoys)
    for finding, decoy in sorted(replacements, key=lambda pair: int(pair[0]["start"]), reverse=True):
        start = int(finding["start"])
        end = int(finding["end"])
        swapped = swapped[:start] + decoy + swapped[end:]

    return {"findings": findings, "decoys": decoys, "swapped_text": swapped}


def _scannable_specs() -> list[FormatSpec]:
    return [spec for spec in list_formats() if spec.scannable]


def _has_checksum(spec: FormatSpec) -> bool:
    return any(isinstance(segment, Checksum) for segment in spec.segments)


def _dedupe(findings: list[dict[str, int | str]]) -> list[dict[str, int | str]]:
    ordered = sorted(
        findings,
        key=lambda finding: (
            -_CONFIDENCE_RANK[str(finding["confidence"])],
            -(int(finding["end"]) - int(finding["start"])),
            int(finding["start"]),
        ),
    )
    kept: list[dict[str, int | str]] = []
    for finding in ordered:
        start = int(finding["start"])
        end = int(finding["end"])
        if any(start < int(kept_finding["end"]) and int(kept_finding["start"]) < end for kept_finding in kept):
            continue
        kept.append(finding)
    return sorted(kept, key=lambda finding: int(finding["start"]))
