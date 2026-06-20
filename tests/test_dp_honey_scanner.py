"""Tests for the registry-driven scanner (SC1, SC3, SC4)."""

from __future__ import annotations

import numpy as np

from detect.dp_honey import get_format
from detect.dp_honey import scanner
from detect.dp_honey.bigram import generate_honeytokens


def _example(slug: str, seed: int = 0) -> str:
    return get_format(slug).random_example(np.random.default_rng(seed))


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
