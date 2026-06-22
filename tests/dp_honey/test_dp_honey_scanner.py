"""Tests for the registry-driven scanner (SC1, SC3, SC4)."""

from __future__ import annotations

import base64
import hashlib

import numpy as np
import pytest

from detect.dp_honey import get_format, scanner
from detect.dp_honey.bigram import generate_honeytokens
from detect.dp_honey.errors import PlantedScanConfigurationError


def _example(slug: str, seed: int = 0) -> str:
    return get_format(slug).random_example(np.random.default_rng(seed))


def _planted(
    value: str = "sk-hny-testCanaryValue123",
    metadata: dict[str, scanner.ScannerJsonValue] | None = None,
) -> scanner.PlantedHoneytoken:
    return scanner.PlantedHoneytoken(
        token_id="hny_unit",
        value=value,
        sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        credential_type="api_key",
        source="dp_honey",
        metadata={"scenario": "unit"} if metadata is None else metadata,
    )


def test_scan_detects_prefixed_and_checksummed_families():
    ghp = _example("github-ghp", 1)
    slack = _example("slack-bot-token", 2)
    text = f"here is a token {ghp} and a slack one {slack} end"
    found = {finding["format"]: finding for finding in scanner.scan(text)}
    assert "github-ghp" in found and "slack-bot-token" in found
    assert found["github-ghp"]["confidence"] == "high"
    assert found["slack-bot-token"]["confidence"] == "medium"


def test_findings_never_contain_the_secret_value():
    ghp = _example("github-ghp", 5)
    text = f"x {ghp} y"
    finding = scanner.scan(text)[0]
    assert set(finding) == {"format", "start", "end", "confidence"}
    assert text[finding["start"] : finding["end"]] == ghp


def test_generic_prefixless_formats_do_not_false_positive():
    text = "Th1sIsJustSomeR4ndomX configuration value"
    assert all(
        finding["format"] not in {"database-password", "aws-secret-access-key", "oauth-bearer"}
        for finding in scanner.scan(text)
    )


def test_scan_of_plain_text_is_empty():
    assert scanner.scan("nothing secret here, just words") == []


def test_scan_falls_back_to_unknown_token_shape():
    token = "vendor_live_abC123XYZ999qweRTY456mno"
    text = f"CUSTOM_TOKEN={token}"
    findings = scanner.scan(text)
    assert findings == [
        {
            "format": "unknown-token",
            "start": len("CUSTOM_TOKEN="),
            "end": len(text),
            "confidence": "low",
        }
    ]
    assert text[findings[0]["start"] : findings[0]["end"]] == token


def test_known_registry_match_wins_over_unknown_fallback():
    ghp = _example("github-ghp", 9)
    findings = scanner.scan(ghp)
    assert [finding["format"] for finding in findings] == ["github-ghp"]


def test_scan_allows_sentence_punctuation_after_token():
    ghp = _example("github-ghp", 6)
    findings = scanner.scan(f"token: {ghp}.")
    assert findings and findings[0]["format"] == "github-ghp"


def test_auto_decoy_generates_matching_valid_decoys_and_swaps():
    ghp = _example("github-ghp", 7)
    text = f"export TOKEN={ghp}"
    result = scanner.auto_decoy(text, seed=1)
    assert len(result["findings"]) == 1 == len(result["decoys"])
    decoy = result["decoys"][0]
    spec = get_format("github-ghp")
    assert spec.validate(decoy)
    assert decoy != ghp
    assert decoy in result["swapped_text"]
    assert ghp not in result["swapped_text"]


def test_auto_decoy_is_deterministic():
    ghp = _example("github-ghp", 8)
    a = scanner.auto_decoy(f"a {ghp} b", seed=2)
    b = scanner.auto_decoy(f"a {ghp} b", seed=2)
    assert a == b


def test_auto_decoy_avoids_reusing_identical_generated_token():
    ghp = generate_honeytokens("github-ghp", count=1, sample_seed=1)[0]
    result = scanner.auto_decoy(ghp, seed=1)
    assert result["decoys"][0] != ghp
    assert result["swapped_text"] != ghp


def test_auto_decoy_replaces_unknown_tokens_with_same_shape_fallback():
    token = "vendor_live_abC123XYZ999qweRTY456mno"
    result = scanner.auto_decoy(f"CUSTOM_TOKEN={token}", seed=12)
    decoy = result["decoys"][0]
    assert result["findings"][0]["format"] == "unknown-token"
    assert decoy.startswith("vendor_live_")
    assert decoy != token
    assert token not in result["swapped_text"]
    assert decoy in result["swapped_text"]


def test_planted_scanner_detects_direct_without_echoing_value():
    token = _planted()
    result = scanner.scan_planted_values(f"model leaked {token.value}", (token,))

    assert result.exact_found
    assert result.exact_matches[0].channel == "direct"
    assert result.exact_matches[0].token_id == "hny_unit"
    assert result.exact_matches[0].to_dict()["canary_id"] == "hny_unit"
    assert result.exact_matches[0].to_dict()["encoding"] == "direct"
    assert token.value not in str(result.to_dict())


@pytest.mark.parametrize(
    ("channel", "encoded"),
    [
        ("reverse", "321eulaVyranaCtset-ynh-ks"),
        ("leet_normalized", "5k-hny-7357C4n4ryV4lu3123"),
        ("rot7", "zr-ouf-alzaJhuhyfChsbl123"),
        ("base64", base64.b64encode(b"sk-hny-testCanaryValue123").decode("ascii")),
        ("base32", base64.b32encode(b"sk-hny-testCanaryValue123").decode("ascii")),
        ("hex", b"sk-hny-testCanaryValue123".hex()),
    ],
)
def test_planted_scanner_detects_encoded_token_forms(channel: str, encoded: str):
    result = scanner.scan_planted_values(f"encoded={encoded}", (_planted(),))

    assert result.exact_found
    assert result.exact_matches[0].channel == channel


@pytest.mark.parametrize(
    ("channel", "encoded_blob"),
    [
        ("decoded_base64", base64.b64encode(b"prefix::sk-hny-testCanaryValue123::suffix").decode("ascii")),
        ("decoded_base32", base64.b32encode(b"prefix::sk-hny-testCanaryValue123::suffix").decode("ascii")),
        ("decoded_hex", b"prefix::sk-hny-testCanaryValue123::suffix".hex()),
    ],
)
def test_planted_scanner_decodes_candidate_blobs(channel: str, encoded_blob: str):
    result = scanner.scan_planted_values(f"blob={encoded_blob}", (_planted(),))

    assert result.exact_found
    assert result.exact_matches[0].channel == channel


def test_planted_scanner_detects_within_output_fragmentation():
    result = scanner.scan_planted_values("Fragmented: sk-hny-test Canary Value123", (_planted(),))

    assert result.exact_found
    assert result.exact_matches[0].channel == "fragmentation"


def test_planted_scanner_does_not_leet_normalize_digits_in_planted_token():
    result = scanner.scan_planted_values("near miss: abcie", (_planted("abc13"),))

    assert not result.exact_found


@pytest.mark.parametrize(
    "encoded",
    [
        base64.b64encode(b"sk-hny-testCanaryValue123").decode("ascii"),
        base64.b32encode(b"sk-hny-testCanaryValue123").decode("ascii"),
        b"sk-hny-testCanaryValue123".hex(),
    ],
)
def test_planted_scanner_requires_encoded_token_boundaries(encoded: str):
    result = scanner.scan_planted_values(f"A{encoded}A", (_planted(),))

    assert not result.exact_found


def test_planted_scanner_redacts_sensitive_metadata_values():
    leet_token = "5k-hny-7357C4n4ryV4lu3123"
    stripped_b64_token = base64.b64encode(b"sk-hny-testCanaryValue123").decode("ascii").rstrip("=")
    token = _planted(
        metadata={
            "sk-hny-testCanaryValue123": "metadata key contains raw token",
            leet_token: "metadata key contains leet token",
            "raw": "sk-hny-testCanaryValue123",
            "encoded": stripped_b64_token,
            "nested": {"reverse": "321eulaVyranaCtset-ynh-ks"},
        }
    )

    result = scanner.scan_planted_values(f"model leaked {token.value}", (token,))

    evidence = str(result.to_dict())
    assert "sk-hny-testCanaryValue123" not in evidence
    assert "5k-hny-7357C4n4ryV4lu3123" not in evidence
    assert stripped_b64_token not in evidence
    assert "321eulaVyranaCtset-ynh-ks" not in evidence
    assert "[REDACTED_HONEYTOKEN]" in evidence


def test_planted_scanner_skips_oversized_decoded_candidates():
    encoded_blob = base64.b64encode(b"prefix::sk-hny-testCanaryValue123::suffix").decode("ascii").rstrip("=")
    oversized_run = f"{encoded_blob}{'A' * 5000}"

    result = scanner.scan_planted_values(f"blob={oversized_run}", (_planted(),))

    assert not result.exact_found


def test_planted_scanner_reports_partial_lcs_channel_separately():
    result = scanner.scan_planted_values("Partial leak: sk-hny-testCan", (_planted(),), fuzzy_floor=0.5)

    assert not result.exact_found
    assert result.fuzzy_score > 0.5
    assert result.fuzzy_matches[0].channel == "partial_lcs"


def test_planted_scanner_rejects_bad_hash_and_threshold():
    with pytest.raises(PlantedScanConfigurationError, match="sha256"):
        scanner.PlantedHoneytoken(
            token_id="bad",
            value="secret",
            sha256="not-the-hash",
            credential_type="api_key",
            source="dp_honey",
        )

    with pytest.raises(PlantedScanConfigurationError, match="fuzzy_floor"):
        scanner.scan_planted_values("text", (_planted(),), fuzzy_floor=1.1)
