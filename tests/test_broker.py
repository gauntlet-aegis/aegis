"""Tests for the credential broker (PDF section 6.5).

The headline test is the leak invariant: a raw secret value must never pass through
model-visible text un-redacted, and doing so must force ESCALATE (unless local-test mode).
"""

from __future__ import annotations

from aegis.broker import (
    BrokerFinding,
    CredentialBroker,
    FakeSecretStore,
    find_handles,
    is_handle,
    parse_handle,
)
from aegis.decision import Action

REAL_SECRET = "ghp_REALSECRETVALUE0123456789ABCDEFabcd"  # fake, ghp_ + 36 chars


# --- handles ---------------------------------------------------------------------------------

def test_is_handle():
    assert is_handle("secret://github/token") is True
    assert is_handle("  secret://github/token  ") is True
    assert is_handle("not a handle") is False
    assert is_handle(REAL_SECRET) is False
    assert is_handle(None) is False  # adversarial / wrong type


def test_parse_handle():
    assert parse_handle("secret://github/token") == ("github", "token")
    assert parse_handle("secret://aws/access_key_id") == ("aws", "access_key_id")
    assert parse_handle("nope") is None
    assert parse_handle(123) is None


def test_find_handles_embedded():
    text = "call the api with secret://github/token then secret://aws/key please"
    assert find_handles(text) == ["secret://github/token", "secret://aws/key"]
    assert find_handles("no handles here") == []


# --- resolution ------------------------------------------------------------------------------

def test_resolve_swaps_handle_for_real_value():
    store = FakeSecretStore({"github/token": REAL_SECRET})
    broker = CredentialBroker(store)
    assert broker.resolve("secret://github/token") == REAL_SECRET
    assert broker.resolve("plain string") == "plain string"
    # unknown handle: no secret to swap, returned unchanged
    assert broker.resolve("secret://github/missing") == "secret://github/missing"


def test_resolve_arguments_deep():
    store = FakeSecretStore({"github/token": REAL_SECRET})
    broker = CredentialBroker(store)
    args = {
        "headers": {"Authorization": "secret://github/token"},
        "items": ["secret://github/token", "literal"],
        "count": 3,
    }
    resolved = broker.resolve_arguments(args)
    assert resolved["headers"]["Authorization"] == REAL_SECRET
    assert resolved["items"] == [REAL_SECRET, "literal"]
    assert resolved["count"] == 3


# --- THE KEY INVARIANT -----------------------------------------------------------------------

def test_raw_secret_in_model_visible_text_escalates():
    store = FakeSecretStore({"github/token": REAL_SECRET})
    broker = CredentialBroker(store)
    text = f"Here is the token you asked for: {REAL_SECRET}"
    finding = broker.scan_model_visible(text)
    assert isinstance(finding, BrokerFinding)
    assert finding.leaked is True
    assert REAL_SECRET not in finding.redacted_text
    assert finding.forced_action == Action.ESCALATE


def test_local_test_mode_reports_leak_but_allows():
    store = FakeSecretStore({"github/token": REAL_SECRET})
    broker = CredentialBroker(store, local_test_mode=True)
    finding = broker.scan_model_visible(f"token: {REAL_SECRET}")
    assert finding.leaked is True
    assert REAL_SECRET not in finding.redacted_text
    assert finding.forced_action == Action.ALLOW


def test_handle_only_is_not_a_leak():
    store = FakeSecretStore({"github/token": REAL_SECRET})
    broker = CredentialBroker(store)
    finding = broker.scan_model_visible("Use secret://github/token to authenticate.")
    assert finding.leaked is False
    assert finding.forced_action == Action.ALLOW
    # the handle itself is fine to keep in model-visible text
    assert "secret://github/token" in finding.redacted_text


def test_scan_handles_empty_and_nonstring():
    broker = CredentialBroker(FakeSecretStore({"github/token": REAL_SECRET}))
    assert broker.scan_model_visible("") is None
    assert broker.scan_model_visible(None) is None  # adversarial / wrong type
    assert broker.assert_no_raw_secret(f"x {REAL_SECRET}").forced_action == Action.ESCALATE
