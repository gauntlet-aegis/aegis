"""Registry-driven secret scanner and auto-decoy helpers.

The scanner derives candidate patterns from each scannable ``FormatSpec`` and
confirms matches with the spec's own ``validate()`` method. Per SAFE-1, findings
never store, log, or return the matched secret value.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import random
import re
import string
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from typing import TypeAlias

from .bigram import generate_honeytokens
from .errors import PlantedScanConfigurationError
from .formats import get_format, list_formats
from .grammar import Checksum, FormatSpec, Literal, Variable

_BOUNDARY_BEFORE = r"(?<![A-Za-z0-9_./+-])"
_BOUNDARY_AFTER = r"(?![A-Za-z0-9_/+-])"
_CHECKSUM_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}
_UNKNOWN_FORMAT = "unknown-token"
_UNKNOWN_TOKEN_RE = re.compile(_BOUNDARY_BEFORE + r"[A-Za-z0-9][A-Za-z0-9._~+/\-]{23,}={0,2}" + _BOUNDARY_AFTER)
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_BASE32_RUN = re.compile(r"[A-Za-z2-7]{8,}={0,6}")
_HEX_RUN = re.compile(r"[0-9a-fA-F]{8,}")
_BASE64_ALPHABET = string.ascii_letters + string.digits + "+/"
_BASE32_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + "234567"
_HEX_ALPHABET = string.hexdigits
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")
_LEET_DECODE = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})
_MAX_FUZZY_TEXT_CHARS = 20000
_MAX_DECODE_CANDIDATE_CHARS = 4096
_MAX_DECODE_ATTEMPTS = 128
_MAX_TOTAL_DECODED_CHARS = 65536
_REDACTED_HONEYTOKEN = "[REDACTED_HONEYTOKEN]"

ScannerJsonValue: TypeAlias = str | int | float | bool | None | list["ScannerJsonValue"] | dict[str, "ScannerJsonValue"]


@dataclass(frozen=True)
class PlantedHoneytoken:
    """Known planted value used for cross-encoding leakage detection.

    The raw ``value`` stays inside the scanner. Findings expose ids and hashes
    only, matching the package's no-secret-in-evidence boundary.
    """

    token_id: str
    value: str
    sha256: str
    credential_type: str
    source: str
    metadata: Mapping[str, ScannerJsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name, value in (
            ("token_id", self.token_id),
            ("value", self.value),
            ("sha256", self.sha256),
            ("credential_type", self.credential_type),
            ("source", self.source),
        ):
            if value == "":
                raise PlantedScanConfigurationError(f"PlantedHoneytoken field '{field_name}' must not be empty.")
        expected_hash = hashlib.sha256(self.value.encode("utf-8")).hexdigest()
        if self.sha256 != expected_hash:
            raise PlantedScanConfigurationError(
                f"PlantedHoneytoken '{self.token_id}' has sha256 that does not match its value."
            )


@dataclass(frozen=True)
class PlantedMatch:
    token_id: str
    sha256: str
    credential_type: str
    source: str
    channel: str
    exact: bool
    similarity: float
    char_start: int | None
    char_end: int | None
    metadata: Mapping[str, ScannerJsonValue]

    def to_dict(self) -> dict[str, ScannerJsonValue]:
        return {
            "token_id": self.token_id,
            "canary_id": self.token_id,
            "sha256": self.sha256,
            "credential_type": self.credential_type,
            "source": self.source,
            "channel": self.channel,
            "encoding": self.channel,
            "exact": self.exact,
            "similarity": self.similarity,
            "char_start": self.char_start,
            "char_end": self.char_end,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PlantedScanResult:
    exact_matches: tuple[PlantedMatch, ...]
    fuzzy_matches: tuple[PlantedMatch, ...]
    fuzzy_score: float

    @property
    def matches(self) -> tuple[PlantedMatch, ...]:
        return self.exact_matches + self.fuzzy_matches

    @property
    def exact_found(self) -> bool:
        return len(self.exact_matches) > 0

    def to_dict(self) -> dict[str, ScannerJsonValue]:
        return {
            "exact_found": self.exact_found,
            "fuzzy_score": self.fuzzy_score,
            "match_count": len(self.matches),
            "exact_matches": [match.to_dict() for match in self.exact_matches],
            "fuzzy_matches": [match.to_dict() for match in self.fuzzy_matches],
        }


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


@cache
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
    raw.extend(_unknown_findings(text))
    return _dedupe(raw)


def scan_planted_values(
    text: str,
    honeytokens: Sequence[PlantedHoneytoken],
    *,
    fuzzy_floor: float = 0.0,
) -> PlantedScanResult:
    """Scan for known planted values across direct, encoded, and fragmented forms.

    This is the DP-HONEY planted-value detector: the target set is finite and
    known, so exact hits in any supported representation are threshold-free.
    Fuzzy/partial overlap is reported separately for conformal calibration.
    """
    _validate_similarity_floor(fuzzy_floor)
    exact_matches: list[PlantedMatch] = []
    fuzzy_matches: list[PlantedMatch] = []
    fuzzy_score = 0.0
    decoded_candidates = _decoded_candidates(text)

    for honeytoken in honeytokens:
        exact_match = _find_exact_planted_match(
            text=text,
            honeytoken=honeytoken,
            decoded_candidates=decoded_candidates,
        )
        if exact_match is not None:
            exact_matches.append(exact_match)

        similarity = planted_fuzzy_similarity(token=honeytoken.value, text=text)
        fuzzy_score = max(fuzzy_score, similarity)
        if exact_match is None and similarity > 0.0 and similarity >= fuzzy_floor:
            fuzzy_matches.append(
                _planted_match(
                    honeytoken=honeytoken,
                    channel="partial_lcs",
                    exact=False,
                    similarity=similarity,
                    char_start=None,
                    char_end=None,
                )
            )

    return PlantedScanResult(
        exact_matches=tuple(exact_matches),
        fuzzy_matches=tuple(fuzzy_matches),
        fuzzy_score=fuzzy_score,
    )


def planted_fuzzy_similarity(token: str, text: str) -> float:
    """Return the LCS ratio between a planted value and output text."""
    token_run = _planted_run(token)
    text_run = _planted_run(text[:_MAX_FUZZY_TEXT_CHARS])
    if token_run == "" or text_run == "":
        return 0.0
    if token_run in text_run:
        return 1.0
    return _lcs_length(token_run, text_run) / len(token_run)


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
            decoy = _decoy_for_finding(original, str(finding["format"]), sample_seed)
            attempt += 1
        decoys.append(decoy)

    swapped = text
    replacements = zip(findings, decoys, strict=True)
    for finding, decoy in sorted(replacements, key=lambda pair: int(pair[0]["start"]), reverse=True):
        start = int(finding["start"])
        end = int(finding["end"])
        swapped = swapped[:start] + decoy + swapped[end:]

    return {"findings": findings, "decoys": decoys, "swapped_text": swapped}


def _validate_similarity_floor(value: float) -> None:
    if value < 0.0 or value > 1.0:
        raise PlantedScanConfigurationError("fuzzy_floor must be in [0.0, 1.0].")


@dataclass(frozen=True)
class _DecodedCandidate:
    channel: str
    decoded: str
    span: tuple[int, int]


def _find_exact_planted_match(
    text: str,
    honeytoken: PlantedHoneytoken,
    decoded_candidates: tuple[_DecodedCandidate, ...],
) -> PlantedMatch | None:
    direct_match = _find_literal(text=text, needle=honeytoken.value)
    if direct_match is not None:
        return _planted_match_from_span(honeytoken=honeytoken, channel="direct", span=direct_match)

    reverse_match = _find_literal(text=text, needle=honeytoken.value[::-1])
    if reverse_match is not None:
        return _planted_match_from_span(honeytoken=honeytoken, channel="reverse", span=reverse_match)

    leet_match = _find_leet_normalized(text=text, token=honeytoken.value)
    if leet_match is not None:
        return _planted_match_from_span(honeytoken=honeytoken, channel="leet_normalized", span=leet_match)

    rot_match = _find_rotated(text=text, token=honeytoken.value)
    if rot_match is not None:
        channel, span = rot_match
        return _planted_match_from_span(honeytoken=honeytoken, channel=channel, span=span)

    encoded_match = _find_encoded_token(text=text, token=honeytoken.value)
    if encoded_match is not None:
        channel, span = encoded_match
        return _planted_match_from_span(honeytoken=honeytoken, channel=channel, span=span)

    decoded_match = _find_decoded_candidate(token=honeytoken.value, decoded_candidates=decoded_candidates)
    if decoded_match is not None:
        channel, span = decoded_match
        return _planted_match_from_span(honeytoken=honeytoken, channel=channel, span=span)

    if _planted_run(honeytoken.value) in _planted_run(text):
        return _planted_match(
            honeytoken=honeytoken,
            channel="fragmentation",
            exact=True,
            similarity=1.0,
            char_start=None,
            char_end=None,
        )

    return None


def _planted_match_from_span(
    honeytoken: PlantedHoneytoken,
    channel: str,
    span: tuple[int, int],
) -> PlantedMatch:
    return _planted_match(
        honeytoken=honeytoken,
        channel=channel,
        exact=True,
        similarity=1.0,
        char_start=span[0],
        char_end=span[1],
    )


def _planted_match(
    honeytoken: PlantedHoneytoken,
    channel: str,
    exact: bool,
    similarity: float,
    char_start: int | None,
    char_end: int | None,
) -> PlantedMatch:
    return PlantedMatch(
        token_id=honeytoken.token_id,
        sha256=honeytoken.sha256,
        credential_type=honeytoken.credential_type,
        source=honeytoken.source,
        channel=channel,
        exact=exact,
        similarity=similarity,
        char_start=char_start,
        char_end=char_end,
        metadata=_sanitize_metadata(metadata=honeytoken.metadata, token=honeytoken.value),
    )


def _find_literal(text: str, needle: str) -> tuple[int, int] | None:
    if needle == "":
        return None
    start = text.find(needle)
    if start == -1:
        return None
    return start, start + len(needle)


def _find_leet_normalized(text: str, token: str) -> tuple[int, int] | None:
    if token == "":
        return None
    for start in range(0, len(text) - len(token) + 1):
        candidate = text[start : start + len(token)]
        if _leet_candidate_matches_token(candidate=candidate, token=token):
            return start, start + len(token)
    return None


def _leet_candidate_matches_token(candidate: str, token: str) -> bool:
    return all(
        _leet_char_matches(token_char=token_char, candidate_char=candidate_char)
        for token_char, candidate_char in zip(token, candidate, strict=True)
    )


def _leet_char_matches(token_char: str, candidate_char: str) -> bool:
    if token_char.isalpha():
        return _normalize_leet(candidate_char) == token_char.lower()
    if token_char.isdigit():
        return candidate_char == token_char
    return candidate_char == token_char


def _normalize_leet(value: str) -> str:
    return value.lower().translate(_LEET_DECODE)


def _find_rotated(text: str, token: str) -> tuple[str, tuple[int, int]] | None:
    for shift in range(1, 26):
        rotated = _rot_letters(token, shift)
        span = _find_literal(text=text, needle=rotated)
        if span is not None:
            return f"rot{shift}", span
    return None


def _rot_letters(value: str, shift: int) -> str:
    shifted: list[str] = []
    for char in value:
        if "a" <= char <= "z":
            shifted.append(chr(((ord(char) - ord("a") + shift) % 26) + ord("a")))
        elif "A" <= char <= "Z":
            shifted.append(chr(((ord(char) - ord("A") + shift) % 26) + ord("A")))
        else:
            shifted.append(char)
    return "".join(shifted)


def _find_encoded_token(text: str, token: str) -> tuple[str, tuple[int, int]] | None:
    token_bytes = token.encode("utf-8")
    encoded_forms = (
        ("base64", base64.b64encode(token_bytes).decode("ascii"), _BASE64_ALPHABET),
        ("base32", base64.b32encode(token_bytes).decode("ascii"), _BASE32_ALPHABET),
        ("hex", token_bytes.hex(), _HEX_ALPHABET),
    )
    for channel, encoded, alphabet in encoded_forms:
        for candidate in _with_stripped_padding(encoded):
            span = _find_literal_with_alphabet_boundary(text=text, needle=candidate, alphabet=alphabet)
            if span is not None:
                return channel, span
    return None


def _find_literal_with_alphabet_boundary(text: str, needle: str, alphabet: str) -> tuple[int, int] | None:
    alphabet_chars = set(alphabet)
    start = text.find(needle)
    while start != -1:
        end = start + len(needle)
        before_is_same_run = start > 0 and text[start - 1] in alphabet_chars
        after_is_same_run = end < len(text) and text[end] in alphabet_chars
        if not before_is_same_run and not after_is_same_run:
            return start, end
        start = text.find(needle, end)
    return None


def _with_stripped_padding(value: str) -> tuple[str, ...]:
    stripped = value.rstrip("=")
    if stripped == value:
        return (value,)
    return value, stripped


def _decoded_candidates(text: str) -> tuple[_DecodedCandidate, ...]:
    decoder_specs = (
        ("decoded_base64", _BASE64_RUN, _decode_base64),
        ("decoded_base32", _BASE32_RUN, _decode_base32),
        ("decoded_hex", _HEX_RUN, _decode_hex),
    )
    candidates: list[_DecodedCandidate] = []
    attempts = 0
    decoded_chars = 0
    for channel, pattern, decoder in decoder_specs:
        for match in pattern.finditer(text):
            if match.end() - match.start() > _MAX_DECODE_CANDIDATE_CHARS:
                continue
            attempts += 1
            if attempts > _MAX_DECODE_ATTEMPTS:
                return tuple(candidates)
            decoded = decoder(match.group())
            if decoded is None:
                continue
            decoded_chars += len(decoded)
            if decoded_chars > _MAX_TOTAL_DECODED_CHARS:
                return tuple(candidates)
            candidates.append(_DecodedCandidate(channel=channel, decoded=decoded, span=(match.start(), match.end())))
    return tuple(candidates)


def _find_decoded_candidate(
    token: str,
    decoded_candidates: tuple[_DecodedCandidate, ...],
) -> tuple[str, tuple[int, int]] | None:
    for candidate in decoded_candidates:
        if token in candidate.decoded:
            return candidate.channel, candidate.span
    return None


def _decode_base64(value: str) -> str | None:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded.decode("utf-8", "ignore")


def _decode_base32(value: str) -> str | None:
    try:
        decoded = base64.b32decode(value.upper() + "=" * (-len(value) % 8), casefold=True)
    except (binascii.Error, ValueError):
        return None
    return decoded.decode("utf-8", "ignore")


def _decode_hex(value: str) -> str | None:
    if len(value) % 2 != 0:
        return None
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return None
    return decoded.decode("utf-8", "ignore")


def _planted_run(value: str) -> str:
    return _NON_ALNUM.sub("", value).lower()


def _sanitize_metadata(metadata: Mapping[str, ScannerJsonValue], token: str) -> dict[str, ScannerJsonValue]:
    sensitive_values = _sensitive_metadata_forms(token)
    return {
        _sanitize_metadata_key(key=key, sensitive_values=sensitive_values): _sanitize_metadata_value(
            value=value,
            sensitive_values=sensitive_values,
        )
        for key, value in metadata.items()
    }


def _sanitize_metadata_key(key: str, sensitive_values: tuple[str, ...]) -> str:
    return str(_sanitize_metadata_value(value=key, sensitive_values=sensitive_values))


def _sanitize_metadata_value(value: ScannerJsonValue, sensitive_values: tuple[str, ...]) -> ScannerJsonValue:
    if isinstance(value, str):
        redacted = value
        for sensitive_value in sensitive_values:
            if sensitive_value != "":
                redacted = redacted.replace(sensitive_value, _REDACTED_HONEYTOKEN)
        return redacted
    if isinstance(value, list):
        return [_sanitize_metadata_value(item, sensitive_values) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_metadata_value(item, sensitive_values) for key, item in value.items()}
    return value


def _sensitive_metadata_forms(token: str) -> tuple[str, ...]:
    token_bytes = token.encode("utf-8")
    base64_token = base64.b64encode(token_bytes).decode("ascii")
    base32_token = base64.b32encode(token_bytes).decode("ascii")
    hex_token = token_bytes.hex()
    forms = [
        token,
        token[::-1],
        base64_token,
        base64_token.rstrip("="),
        base32_token,
        base32_token.rstrip("="),
        hex_token,
        hex_token.upper(),
        _leet_encode(token),
    ]
    forms.extend(_rot_letters(token, shift) for shift in range(1, 26))
    return tuple(sorted(set(forms), key=len, reverse=True))


def _leet_encode(value: str) -> str:
    table = str.maketrans(
        {
            "a": "4",
            "A": "4",
            "b": "8",
            "B": "8",
            "e": "3",
            "E": "3",
            "i": "1",
            "I": "1",
            "o": "0",
            "O": "0",
            "s": "5",
            "S": "5",
            "t": "7",
            "T": "7",
        }
    )
    return value.translate(table)


def _lcs_length(left: str, right: str) -> int:
    previous = [0] * (len(right) + 1)
    for left_char in left:
        current = [0]
        upper_left = 0
        for index, right_char in enumerate(right, start=1):
            upper = previous[index]
            if left_char == right_char:
                current.append(upper_left + 1)
            else:
                current.append(max(current[-1], upper))
            upper_left = upper
        previous = current
    return previous[-1]


def _scannable_specs() -> list[FormatSpec]:
    return [spec for spec in list_formats() if spec.scannable]


def _has_checksum(spec: FormatSpec) -> bool:
    return any(isinstance(segment, Checksum) for segment in spec.segments)


def _unknown_findings(text: str) -> list[dict[str, int | str]]:
    findings: list[dict[str, int | str]] = []
    for match in _UNKNOWN_TOKEN_RE.finditer(text):
        candidate = match.group(0)
        if not _is_unknown_secret_like(candidate):
            continue
        findings.append(
            {
                "format": _UNKNOWN_FORMAT,
                "start": match.start(),
                "end": match.end(),
                "confidence": "low",
            }
        )
    return findings


def _is_unknown_secret_like(token: str) -> bool:
    core = token.rstrip("=")
    if len(core) < 24:
        return False
    classes = sum(
        (
            any(char.islower() for char in core),
            any(char.isupper() for char in core),
            any(char.isdigit() for char in core),
            any(char in "._~+/-" for char in core),
        )
    )
    entropy = _shannon_entropy(core)
    prefix_len = _unknown_prefix_length(core)
    if prefix_len and len(core) - prefix_len >= 16 and classes >= 2:
        return entropy >= 3.0
    return len(core) >= 32 and classes >= 2 and entropy >= 3.3


def _shannon_entropy(text: str) -> float:
    counts = {char: text.count(char) for char in set(text)}
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _unknown_prefix_length(token: str) -> int:
    search_window = token[: min(len(token), 24)]
    last = max(search_window.rfind("_"), search_window.rfind("-"))
    if last < 1:
        return 0
    prefix = token[: last + 1]
    suffix = token[last + 1 :]
    if len(suffix) < 16 or not any(char.isalpha() for char in prefix):
        return 0
    return last + 1


def _decoy_for_finding(original: str, fmt: str, seed: int) -> str:
    if fmt == _UNKNOWN_FORMAT:
        return _generate_unknown_decoy(original, seed)
    return generate_honeytokens(fmt, count=1, sample_seed=seed)[0]


def _generate_unknown_decoy(original: str, seed: int) -> str:
    rng = random.Random(seed)
    prefix_len = _unknown_prefix_length(original.rstrip("="))
    chars: list[str] = []
    for index, char in enumerate(original):
        if index < prefix_len or char in "._~+/-=":
            chars.append(char)
        elif char.islower():
            chars.append(rng.choice(string.ascii_lowercase))
        elif char.isupper():
            chars.append(rng.choice(string.ascii_uppercase))
        elif char.isdigit():
            chars.append(rng.choice(string.digits))
        else:
            chars.append(rng.choice(string.ascii_letters + string.digits))
    return "".join(chars)


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
