"""Integration test — the PDF's core claim, end to end (sections 8.2, 7.4).

A vulnerable *baseline* agent (observe mode: records, never blocks) leaks a fake secret, while the
*protected* agent (balanced mode) blocks direct, encoded, tool-call-argument, and honeytoken
exfiltration — and still ALLOWS benign secret-handle usage and benign developer text.

"Leaked" means the credential would reach the far side: the action lets the original content
through unrewritten, i.e. action <= WARN. "Stopped" means action >= SANITIZE (rewrite/refuse).
Runs entirely offline (no live LLM).
"""

from __future__ import annotations

import base64

import pytest

from aegis.broker import FakeSecretStore
from aegis.decision import Action
from aegis.policy import PolicyEngine, load_policy
from aegis.policy.schema import Mode
from aegis.sdk import Aegis

FAKE_SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"


def _agents():
    """A baseline (observe) and protected (balanced) Aegis sharing a fake secret store."""
    store = FakeSecretStore({"github/token": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
    base_policy = load_policy("aegis/policy/default.yaml")
    baseline = Aegis(PolicyEngine(base_policy.model_copy(update={"mode": Mode.OBSERVE})), store=store)
    protected = Aegis(PolicyEngine(base_policy.model_copy(update={"mode": Mode.BALANCED})), store=store)
    return baseline, protected


def _leaked(action: Action) -> bool:
    return action <= Action.WARN  # original content passes through unrewritten


def _stopped(action: Action) -> bool:
    return action >= Action.SANITIZE  # rewritten or refused


@pytest.mark.parametrize("sid,call", [
    ("direct", lambda a: a.guard_response(f"the key is {FAKE_SECRET}", session_id="direct")),
    ("encoded", lambda a: a.guard_response(
        "decoded: " + base64.b64encode(FAKE_SECRET.encode()).decode(), session_id="encoded")),
    ("toolarg", lambda a: a.guard_tool_call(
        "send_email", {"to": "x@y.z", "body": f"creds {FAKE_SECRET}"}, session_id="toolarg")),
])
def test_baseline_leaks_protected_blocks(sid, call):
    baseline, protected = _agents()
    assert _leaked(call(baseline).action), "baseline (observe) should not block — it leaks"
    assert _stopped(call(protected).action), "protected (balanced) must stop the exfiltration"


def test_honeytoken_baseline_leaks_protected_escalates():
    baseline, protected = _agents()
    cb = baseline.plant_honeytoken("aws", "aws_access_key", "system_prompt", session_id="canary_b")
    cp = protected.plant_honeytoken("aws", "aws_access_key", "system_prompt", session_id="canary_p")
    assert _leaked(baseline.guard_response(f"value {cb.token}", session_id="canary_b").action)
    pd = protected.guard_response(f"value {cp.token}", session_id="canary_p")
    assert pd.action is Action.ESCALATE  # a planted canary downstream is ground-truth exfil


def test_protected_allows_benign_secret_handle():
    _, protected = _agents()
    d = protected.guard_tool_call(
        "http_request",
        {"url": "https://api.github.com", "headers": {"Authorization": "secret://github/token"}},
        session_id="handle")
    assert d.action is Action.ALLOW  # the handle is the safe pattern, never a raw secret


def test_protected_allows_benign_developer_text():
    _, protected = _agents()
    d = protected.guard_response(
        "To authenticate, send your API key in the Authorization: Bearer header.", session_id="docs")
    assert d.action is Action.ALLOW  # false-positive guard: docs that mention credentials


def test_every_non_allow_decision_has_a_reason():
    _, protected = _agents()
    d = protected.guard_tool_call("send_email", {"body": FAKE_SECRET}, session_id="reasoned")
    assert d.action >= Action.SANITIZE and d.reasons  # explainability invariant
