"""Tests for the Cameron/Spine red-team beta adapter seam."""

from __future__ import annotations

import hashlib
import sys

import pytest

from detect.dp_honey.cameron_spine import (
    CAMERON_SPINE_REQUEST_SCHEMA_VERSION,
    build_cameron_spine_request,
    parse_cameron_spine_beta_report,
    run_cameron_spine_red_team,
)
from detect.dp_honey.errors import CameronSpineAdapterError
from detect.dp_honey.scanner import PlantedHoneytoken


def _planted(value: str = "sk_live_TestCanaryValue123", token_id: str = "hny_eval_unit") -> PlantedHoneytoken:
    return PlantedHoneytoken(
        token_id=token_id,
        value=value,
        sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        credential_type="stripe-sk-live",
        source="unit",
        metadata={"synthetic_only": True},
    )


def test_build_cameron_spine_request_has_stable_schema_and_candidates():
    token = _planted(token_id="candidate-1")

    request = build_cameron_spine_request((token,))

    assert request["schema_version"] == CAMERON_SPINE_REQUEST_SCHEMA_VERSION
    assert request["task"] == "dp_honey_beta_distinguishability"
    assert request["honeytokens"] == [
        {
            "token_id": "candidate-1",
            "value": token.value,
            "sha256": token.sha256,
            "credential_type": token.credential_type,
        }
    ]
    assert request["preferred_response_schema"]["schema_version"] == "cameron_spine_beta_v1"


def test_parse_cameron_spine_beta_report_accepts_numeric_beta_fallback():
    tokens = (_planted(token_id="a"), _planted("sk_live_realisticValue123", token_id="b"))
    payload = {
        "schema_version": "cameron_spine_beta_v1",
        "run_id": "numeric-beta",
        "beta": 0.25,
        "token_count": 4,
        "distinguished_count": 1,
    }

    report = parse_cameron_spine_beta_report(payload, honeytokens=tokens, command_name="fixture")

    assert report.beta == 0.25
    assert report.token_count == 4
    assert report.distinguished_count == 1
    assert report.label == "cameron_spine_red_team_call"
    assert report.summary["run_id"] == "numeric-beta"


def test_run_cameron_spine_red_team_sends_request_to_command():
    tokens = (
        _planted("sk_live_hny_canary_0000", token_id="a"),
        _planted("sk_live_realisticValue123", token_id="b"),
    )
    code = (
        "import json, sys; "
        "request = json.load(sys.stdin); "
        "assert request['schema_version'] == 'dp_honey_cameron_spine_request_v1'; "
        "predictions = ["
        "{'token_id': item['token_id'], 'distinguished': item['value'].find('hny') >= 0} "
        "for item in request['honeytokens']"
        "]; "
        "print(json.dumps({'schema_version': 'cameron_spine_beta_v1', 'predictions': predictions}))"
    )

    report = run_cameron_spine_red_team([sys.executable, "-c", code], tokens)

    assert report.beta == 0.5
    assert report.token_count == 2
    assert report.distinguished_count == 1


def test_run_cameron_spine_red_team_fails_closed_on_bad_json():
    token = _planted()

    with pytest.raises(CameronSpineAdapterError, match="valid JSON"):
        run_cameron_spine_red_team([sys.executable, "-c", "print('not json')"], (token,))


def test_parse_cameron_spine_beta_report_rejects_unknown_prediction_token():
    token = _planted(token_id="known")

    with pytest.raises(CameronSpineAdapterError, match="unknown token_id"):
        parse_cameron_spine_beta_report(
            {"predictions": [{"token_id": "unknown", "distinguished": True}]},
            honeytokens=(token,),
        )
