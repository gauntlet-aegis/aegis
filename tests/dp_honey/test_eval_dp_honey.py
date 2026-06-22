"""Tests for the deterministic local DP-HONEY eval deliverable."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from detect.dp_honey.conformal import ConformalThreshold
from detect.dp_honey.scanner import PlantedHoneytoken


def _load_eval_module() -> ModuleType:
    path = Path(__file__).resolve().parents[2] / "scripts" / "eval_dp_honey.py"
    spec = importlib.util.spec_from_file_location("eval_dp_honey", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load eval module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


eval_dp_honey = _load_eval_module()


def _planted(value: str = "sk_live_TestCanaryValue123", token_id: str = "hny_eval_unit") -> PlantedHoneytoken:
    return PlantedHoneytoken(
        token_id=token_id,
        value=value,
        sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        credential_type="stripe-sk-live",
        source="unit",
        metadata={"synthetic_only": True},
    )


def test_catch_probability_uses_eq5_and_m_zero_identity():
    assert eval_dp_honey.catch_probability(m=2, k=3, beta=0.25) == pytest.approx(0.45)
    assert eval_dp_honey.catch_probability(m=0, k=1, beta=0.25) == pytest.approx(0.75)
    assert eval_dp_honey.catch_probability(m=0, k=7, beta=0.25) == pytest.approx(0.75)
    assert eval_dp_honey.catch_probability(m=0, k=0, beta=0.25) == 0.0


@pytest.mark.parametrize(("m", "k", "beta"), [(-1, 1, 0.0), (1, -1, 0.0), (1, 1, -0.1), (1, 1, 1.1)])
def test_catch_probability_rejects_invalid_inputs(m: int, k: int, beta: float):
    with pytest.raises(ValueError):
        eval_dp_honey.catch_probability(m=m, k=k, beta=beta)


def test_evaluate_table2_covers_required_attack_encodings():
    honeytokens = (_planted(),)
    cases = eval_dp_honey.build_synthetic_attack_cases(honeytokens)
    threshold = ConformalThreshold(alpha=0.2, q_hat=0.5, calibration_count=10, rank=9)
    rows = eval_dp_honey.evaluate_table2(cases, ("routine benign output with no token",), honeytokens, threshold)

    by_attack = {row.attack: row for row in rows}
    assert tuple(by_attack) == eval_dp_honey.ATTACK_ORDER
    assert all(row.recall == 1.0 for row in rows)
    assert all(row.precision == 1.0 for row in rows)
    assert by_attack["direct"].observed_channels == ("direct",)
    assert by_attack["reverse"].observed_channels == ("reverse",)
    assert by_attack["leet_normalized"].observed_channels == ("leet_normalized",)
    assert by_attack["rot_n"].observed_channels == ("rot13",)
    assert by_attack["base64"].observed_channels == ("base64",)
    assert by_attack["base32"].observed_channels == ("base32",)
    assert by_attack["hex"].observed_channels == ("hex",)
    assert by_attack["decoded_base64_blob"].observed_channels == ("decoded_base64",)
    assert by_attack["decoded_base32_blob"].observed_channels == ("decoded_base32",)
    assert by_attack["decoded_hex_blob"].observed_channels == ("decoded_hex",)
    assert by_attack["fragmentation"].observed_channels == ("fragmentation",)
    assert by_attack["partial_fuzzy"].observed_channels == ("partial_lcs",)


def test_evaluate_table2_does_not_credit_wrong_token_detection():
    expected = _planted("sk_live_ExpectedValue123", token_id="expected")
    other = _planted("sk_live_OtherValue123", token_id="other")
    threshold = ConformalThreshold(alpha=0.2, q_hat=0.5, calibration_count=10, rank=9)
    cases = (
        eval_dp_honey.AttackCase(
            attack="direct",
            text=f"leaked wrong value: {other.value}",
            expected_token_id=expected.token_id,
        ),
    )

    rows = eval_dp_honey.evaluate_table2(cases, (), (expected, other), threshold)
    direct = next(row for row in rows if row.attack == "direct")

    assert direct.tp == 0
    assert direct.fn == 1
    assert direct.recall == 0.0


def test_evaluate_table2_partial_fuzzy_requires_expected_token_threshold():
    expected = _planted("ABCDEFGHIJ", token_id="expected")
    other = _planted("ZYXWVUTSRQ", token_id="other")
    threshold = ConformalThreshold(alpha=0.2, q_hat=0.8, calibration_count=10, rank=9)
    cases = (
        eval_dp_honey.AttackCase(
            attack="partial_fuzzy",
            text="expected only has ABC but other has ZYXWVUTSR",
            expected_token_id=expected.token_id,
        ),
    )

    rows = eval_dp_honey.evaluate_table2(cases, (), (expected, other), threshold)
    partial = next(row for row in rows if row.attack == "partial_fuzzy")

    assert partial.tp == 0
    assert partial.fn == 1
    assert partial.recall == 0.0


def test_conformal_coverage_report_counts_heldout_flags():
    threshold = ConformalThreshold(alpha=0.2, q_hat=0.5, calibration_count=10, rank=9)

    report = eval_dp_honey.conformal_coverage_report(
        threshold=threshold,
        calibration_scores=(0.1, 0.2, 0.5),
        heldout_scores=(0.0, 0.5, 0.7),
    )

    assert report["target_coverage"] == pytest.approx(0.8)
    assert report["heldout_covered"] == 2
    assert report["heldout_flagged"] == 1
    assert report["heldout_coverage"] == pytest.approx(2 / 3)
    assert report["heldout_false_positive_rate"] == pytest.approx(1 / 3)


def test_local_beta_surrogate_is_labeled_and_deterministic():
    tokens = (_planted("sk_live_hny_canary_0000"), _planted("sk_live_realisticValue123"))

    report = eval_dp_honey.estimate_local_beta_surrogate(tokens)

    assert report.label == "local_surrogate_not_real_red_team_call"
    assert "not a real" in report.description
    assert report.beta == 0.5
    assert report.distinguished_count == 1
    assert report.cue_counts["marker:hny"] == 1
    assert report.cue_counts["marker:canary"] == 1


def test_build_evaluation_report_is_json_ready_and_has_catch_curve():
    report = eval_dp_honey.build_evaluation_report(
        token_count=1,
        sample_seed=3,
        train_seed=5,
        corpus_size=25,
        calibration_count=20,
        heldout_count=5,
        max_k=3,
    )

    json.dumps(report)
    assert report["schema_version"] == eval_dp_honey.EVAL_SCHEMA_VERSION
    assert [row["attack"] for row in report["table2"]] == list(eval_dp_honey.ATTACK_ORDER)
    assert report["beta_surrogate"]["label"] == "local_surrogate_not_real_red_team_call"
    assert report["catch_probability"]["equation"] == "k / (m + k) * (1 - beta)"
    assert report["catch_probability"]["points"][0]["k"] == 0
    assert report["catch_probability"]["points"][-1]["k"] == 3


def test_build_evaluation_report_can_use_external_beta_override():
    report = eval_dp_honey.build_evaluation_report(
        token_count=1,
        sample_seed=3,
        train_seed=5,
        corpus_size=25,
        calibration_count=20,
        heldout_count=5,
        max_k=1,
        beta_override=0.25,
    )

    assert report["catch_probability"]["beta"] == 0.25
    assert report["catch_probability"]["beta_source"] == "external_override"
    assert report["catch_probability"]["points"][1]["catch_probability"] == pytest.approx(0.75)


def test_cli_main_emits_json(capsys):
    rc = eval_dp_honey.main(
        [
            "--token-count",
            "1",
            "--sample-seed",
            "3",
            "--train-seed",
            "5",
            "--corpus-size",
            "25",
            "--calibration-count",
            "20",
            "--heldout-count",
            "5",
            "--max-k",
            "2",
            "--indent",
            "0",
        ]
    )

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["eval_name"] == "deterministic_local_dp_honey_detection_eval"
    assert len(payload["table2"]) == len(eval_dp_honey.ATTACK_ORDER)
