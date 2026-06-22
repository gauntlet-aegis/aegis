"""Cameron/Spine red-team adapter for DP-HONEY beta accounting.

The adapter is intentionally transport-small: it can invoke any command that
accepts a JSON request on stdin and emits a JSON report on stdout. That keeps the
eval script independent from the concrete Cameron/Spine runner while still
making the measured beta path real and testable.
"""

from __future__ import annotations

import json
import math
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TypeAlias, cast

from .errors import CameronSpineAdapterError
from .scanner import PlantedHoneytoken

DEFAULT_CAMERON_SPINE_TIMEOUT_SECONDS = 300.0
CAMERON_SPINE_REQUEST_SCHEMA_VERSION = "dp_honey_cameron_spine_request_v1"
CAMERON_SPINE_RESPONSE_SCHEMA_VERSION = "cameron_spine_beta_v1"

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


@dataclass(frozen=True, slots=True)
class RedTeamBetaReport:
    """Measured beta from a Cameron/Spine-compatible distinguisher run."""

    beta: float
    token_count: int
    distinguished_count: int
    label: str
    description: str
    command_name: str
    summary: Mapping[str, JsonValue]

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "beta": self.beta,
            "token_count": self.token_count,
            "distinguished_count": self.distinguished_count,
            "label": self.label,
            "description": self.description,
            "command_name": self.command_name,
            "summary": dict(self.summary),
        }


def build_cameron_spine_request(honeytokens: Sequence[PlantedHoneytoken]) -> dict[str, JsonValue]:
    """Build the stdin request for a Cameron/Spine-compatible distinguisher."""

    _require_non_empty(honeytokens, "honeytokens")
    return {
        "schema_version": CAMERON_SPINE_REQUEST_SCHEMA_VERSION,
        "task": "dp_honey_beta_distinguishability",
        "candidate_semantics": (
            "Each candidate value is a planted DP-HONEY token. Return distinguished=true when the "
            "red-team distinguisher identifies it as planted/honeytoken rather than real."
        ),
        "honeytokens": [
            {
                "token_id": token.token_id,
                "value": token.value,
                "sha256": token.sha256,
                "credential_type": token.credential_type,
            }
            for token in honeytokens
        ],
        "preferred_response_schema": {
            "schema_version": CAMERON_SPINE_RESPONSE_SCHEMA_VERSION,
            "predictions": [{"token_id": "string", "distinguished": True, "score": 1.0}],
        },
    }


def run_cameron_spine_red_team(
    command: Sequence[str],
    honeytokens: Sequence[PlantedHoneytoken],
    *,
    timeout_seconds: float = DEFAULT_CAMERON_SPINE_TIMEOUT_SECONDS,
) -> RedTeamBetaReport:
    """Run a Cameron/Spine-compatible red-team distinguisher command.

    The command receives a JSON request on stdin and must write a JSON object to
    stdout. The preferred response shape is:

    ``{"predictions": [{"token_id": "...", "distinguished": true}]}``

    where ``distinguished=true`` means the red team identified the candidate as
    a honeytoken rather than a real credential. A top-level ``beta`` may be
    supplied instead, but per-token predictions are preferred because they make
    the accounting auditable.
    """

    _require_non_empty(command, "command")
    _require_non_empty(honeytokens, "honeytokens")
    if timeout_seconds <= 0 or not math.isfinite(timeout_seconds):
        raise CameronSpineAdapterError(f"timeout_seconds must be positive and finite, got {timeout_seconds!r}")

    request = build_cameron_spine_request(honeytokens)
    try:
        completed = subprocess.run(
            list(command),
            input=json.dumps(request, sort_keys=True),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except OSError as exc:
        raise CameronSpineAdapterError(f"Cameron/Spine red-team command could not be started: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CameronSpineAdapterError(f"Cameron/Spine red-team command timed out after {timeout_seconds:g}s.") from exc

    if completed.returncode != 0:
        raise CameronSpineAdapterError(f"Cameron/Spine red-team command failed with exit code {completed.returncode}.")

    try:
        payload_obj = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CameronSpineAdapterError("Cameron/Spine red-team command did not emit valid JSON.") from exc
    if not isinstance(payload_obj, dict):
        raise CameronSpineAdapterError("Cameron/Spine red-team command must emit a JSON object.")

    return parse_cameron_spine_beta_report(
        cast(Mapping[str, object], payload_obj),
        honeytokens=honeytokens,
        command_name=str(command[0]),
    )


def parse_cameron_spine_beta_report(
    payload: Mapping[str, object],
    *,
    honeytokens: Sequence[PlantedHoneytoken],
    command_name: str = "cameron-spine",
) -> RedTeamBetaReport:
    """Parse a Cameron/Spine distinguisher report into Eq.5 beta accounting."""

    _require_non_empty(honeytokens, "honeytokens")
    token_ids = {token.token_id for token in honeytokens}
    predictions = payload.get("predictions")
    if isinstance(predictions, list):
        distinguished_count = _count_distinguished_predictions(predictions, token_ids=token_ids)
        token_count = len(token_ids)
        beta = distinguished_count / token_count
        summary = _red_team_summary(
            payload=payload,
            token_count=token_count,
            distinguished_count=distinguished_count,
            prediction_count=len(predictions),
        )
    else:
        beta = _coerce_float(payload.get("beta"), "beta")
        token_count = _coerce_int(payload.get("token_count", len(token_ids)), "token_count")
        distinguished_count = _coerce_int(
            payload.get("distinguished_count", round(beta * token_count)),
            "distinguished_count",
        )
        if token_count <= 0:
            raise CameronSpineAdapterError(f"token_count must be positive, got {token_count}")
        if distinguished_count < 0 or distinguished_count > token_count:
            raise CameronSpineAdapterError(
                f"distinguished_count must be in [0, token_count], got {distinguished_count} for {token_count}"
            )
        beta = _validate_beta(beta)
        summary = _red_team_summary(
            payload=payload,
            token_count=token_count,
            distinguished_count=distinguished_count,
            prediction_count=None,
        )

    return RedTeamBetaReport(
        beta=beta,
        token_count=token_count,
        distinguished_count=distinguished_count,
        label="cameron_spine_red_team_call",
        description=(
            "Measured by executing a Cameron/Spine-compatible red-team distinguisher. "
            "Beta is the fraction of candidate honeytokens the red team identified as planted."
        ),
        command_name=command_name,
        summary=summary,
    )


def _count_distinguished_predictions(predictions: Sequence[object], *, token_ids: set[str]) -> int:
    seen: set[str] = set()
    distinguished_count = 0
    for index, prediction in enumerate(predictions):
        if not isinstance(prediction, Mapping):
            raise CameronSpineAdapterError(f"prediction[{index}] must be an object.")
        token_id_obj = prediction.get("token_id")
        if not isinstance(token_id_obj, str):
            raise CameronSpineAdapterError(f"prediction[{index}].token_id must be a string.")
        if token_id_obj not in token_ids:
            raise CameronSpineAdapterError(f"prediction[{index}] references unknown token_id {token_id_obj!r}.")
        if token_id_obj in seen:
            raise CameronSpineAdapterError(f"prediction[{index}] duplicates token_id {token_id_obj!r}.")
        seen.add(token_id_obj)
        if _prediction_is_distinguished(prediction):
            distinguished_count += 1
    missing = token_ids - seen
    if missing:
        raise CameronSpineAdapterError(
            f"Cameron/Spine report is missing predictions for token_ids: {sorted(missing)!r}."
        )
    return distinguished_count


def _prediction_is_distinguished(prediction: Mapping[str, object]) -> bool:
    for key in ("distinguished", "is_honeytoken", "predicted_honeytoken", "marked_honeytoken"):
        value = prediction.get(key)
        if isinstance(value, bool):
            return value

    for key in ("prediction", "label", "class"):
        value = prediction.get(key)
        if isinstance(value, str):
            normalized = value.strip().lower().replace("-", "_")
            if normalized in {"honeytoken", "decoy", "planted", "planted_honeytoken", "canary", "synthetic"}:
                return True
            if normalized in {"real", "benign", "credential", "production", "real_secret"}:
                return False

    raise CameronSpineAdapterError(
        "each Cameron/Spine prediction must include a boolean distinguished field "
        "or a recognized prediction/label/class string."
    )


def _red_team_summary(
    *,
    payload: Mapping[str, object],
    token_count: int,
    distinguished_count: int,
    prediction_count: int | None,
) -> dict[str, JsonValue]:
    summary: dict[str, JsonValue] = {
        "schema_version": _optional_string(payload.get("schema_version")),
        "run_id": _optional_string(payload.get("run_id")),
        "token_count": token_count,
        "distinguished_count": distinguished_count,
    }
    if prediction_count is not None:
        summary["prediction_count"] = prediction_count
    return summary


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _coerce_float(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CameronSpineAdapterError(f"{name} must be numeric.")
    coerced = float(value)
    if not math.isfinite(coerced):
        raise CameronSpineAdapterError(f"{name} must be finite.")
    return coerced


def _coerce_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CameronSpineAdapterError(f"{name} must be an integer.")
    return value


def _validate_beta(beta: float) -> float:
    if not math.isfinite(beta) or beta < 0.0 or beta > 1.0:
        raise CameronSpineAdapterError(f"beta must be finite and in [0, 1], got {beta!r}")
    return beta


def _require_non_empty(values: Sequence[object], name: str) -> None:
    if not values:
        raise CameronSpineAdapterError(f"{name} must not be empty")
