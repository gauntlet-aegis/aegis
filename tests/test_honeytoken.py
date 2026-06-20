from sentinel.proxy.honeytoken import HoneytokenLedger, inject_honeytokens

REAL = "sk-REAL-SECRET-do-not-leak-123456"


def test_real_secret_never_model_visible():
    ledger = HoneytokenLedger("c1")
    ledger.register_real("api_key", REAL)
    messages = [
        {"role": "system", "content": "Key: {{CREDENTIAL:api_key:openai_key}}"},
        {"role": "user", "content": f"the real one is {REAL}"},  # simulate a leak into context
    ]
    out = inject_honeytokens(messages, ledger, turn_index=0)
    joined = " ".join(m["content"] for m in out)
    assert REAL not in joined  # real value scrubbed everywhere
    assert ledger.honeytokens(), "a honeytoken should have been planted"
    assert ledger.honeytokens()[0].value in out[0]["content"]


def test_placeholder_substituted_with_planted_token():
    ledger = HoneytokenLedger("c2")
    messages = [{"role": "system", "content": "k={{CREDENTIAL:api_key:openai_key}}"}]
    out = inject_honeytokens(messages, ledger, turn_index=0)
    token = ledger.honeytokens()[0]
    assert "{{CREDENTIAL" not in out[0]["content"]
    assert token.value in out[0]["content"]
    assert token.value.startswith("sk-")
