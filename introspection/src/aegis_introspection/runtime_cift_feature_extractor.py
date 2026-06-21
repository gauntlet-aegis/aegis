from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, TypeAlias, cast

from aegis_introspection.activations import HiddenStateForwardPass, run_hidden_state_forward
from aegis_introspection.features import PoolingMethod, build_feature_key, extract_activation_features
from aegis_introspection.model_loader import LoadedCausalLM
from aegis_introspection.probe import JsonValue

_FEATURE_KEY_PATTERN = re.compile(r"^(final_token|mean_pool|readout_window)_layer_(\d+)$")


class RuntimeCiftFeatureExtractorError(ValueError):
    """Raised when a runtime turn cannot be converted into a CIFT feature vector."""


class RuntimeMessageLike(Protocol):
    role: str
    content: str


class RuntimeTurnLike(Protocol):
    messages: tuple[RuntimeMessageLike, ...]
    metadata: Mapping[str, JsonValue]


class HiddenStateForwardRunner(Protocol):
    def run(self, prompt: str) -> HiddenStateForwardPass:
        """Run a prompt and return hidden states."""


FeatureVector: TypeAlias = tuple[float, ...]


@dataclass(frozen=True)
class ParsedFeatureKey:
    pooling_method: PoolingMethod
    layer_index: int


@dataclass(frozen=True)
class LoadedModelHiddenStateForwardRunner:
    loaded_model: LoadedCausalLM

    def run(self, prompt: str) -> HiddenStateForwardPass:
        return run_hidden_state_forward(loaded_model=self.loaded_model, prompt=prompt)


@dataclass(frozen=True)
class RuntimeCiftFeatureExtractor:
    forward_runner: HiddenStateForwardRunner

    def extract_feature_vector(self, turn: RuntimeTurnLike, feature_key: str) -> FeatureVector | None:
        parsed_key = parse_runtime_cift_feature_key(feature_key)
        prompt = rendered_prompt_from_turn(turn)
        readout_token_indices = readout_indices_from_turn(turn)
        if parsed_key.pooling_method == "readout_window" and readout_token_indices is None:
            return None
        forward_pass = self.forward_runner.run(prompt)
        features = extract_activation_features(
            forward_pass=forward_pass,
            layer_indices=(parsed_key.layer_index,),
            pooling_methods=(parsed_key.pooling_method,),
            readout_token_indices=readout_token_indices,
        )
        if len(features) != 1:
            raise RuntimeCiftFeatureExtractorError(f"Expected one extracted feature for '{feature_key}'.")
        feature = features[0]
        if feature.key != feature_key:
            raise RuntimeCiftFeatureExtractorError(f"Expected extracted feature '{feature_key}', got '{feature.key}'.")
        values = feature.values.squeeze(0).detach().cpu().tolist()
        if not isinstance(values, list):
            raise RuntimeCiftFeatureExtractorError(f"Feature '{feature_key}' did not convert to a list.")
        return tuple(
            _float_value(value=value, field_name=f"{feature_key}[{index}]") for index, value in enumerate(values)
        )


def parse_runtime_cift_feature_key(feature_key: str) -> ParsedFeatureKey:
    match = _FEATURE_KEY_PATTERN.fullmatch(feature_key)
    if match is None:
        raise RuntimeCiftFeatureExtractorError(
            f"Unsupported CIFT feature key '{feature_key}'. Expected '<pooling>_layer_<index>'."
        )
    pooling_method = cast(PoolingMethod, match.group(1))
    layer_index = int(match.group(2))
    canonical_feature_key = build_feature_key(pooling_method=pooling_method, layer_index=layer_index)
    if feature_key != canonical_feature_key:
        raise RuntimeCiftFeatureExtractorError(
            f"Unsupported CIFT feature key '{feature_key}'. Expected canonical key '{canonical_feature_key}'."
        )
    return ParsedFeatureKey(pooling_method=pooling_method, layer_index=layer_index)


def rendered_prompt_from_turn(turn: RuntimeTurnLike) -> str:
    if len(turn.messages) != 1:
        raise RuntimeCiftFeatureExtractorError(
            "Runtime CIFT extraction currently requires a single rendered-prompt message."
        )
    message = turn.messages[0]
    if message.role != "user":
        raise RuntimeCiftFeatureExtractorError("Runtime CIFT extraction expects the rendered prompt in a user message.")
    if message.content == "":
        raise RuntimeCiftFeatureExtractorError("Runtime CIFT extraction requires a non-empty rendered prompt.")
    return message.content


def readout_indices_from_turn(turn: RuntimeTurnLike) -> tuple[int, ...] | None:
    cift_metadata = turn.metadata.get("cift")
    if cift_metadata is None:
        return None
    if not isinstance(cift_metadata, dict):
        raise RuntimeCiftFeatureExtractorError("Runtime turn metadata.cift must be an object when present.")
    raw_indices = cift_metadata.get("readout_token_indices")
    if raw_indices is None:
        return None
    if not isinstance(raw_indices, list):
        raise RuntimeCiftFeatureExtractorError("Runtime turn metadata.cift.readout_token_indices must be a list.")
    indices: list[int] = []
    for index, value in enumerate(raw_indices):
        if isinstance(value, bool) or not isinstance(value, int):
            raise RuntimeCiftFeatureExtractorError(f"readout_token_indices item {index} must be an integer.")
        if value < 0:
            raise RuntimeCiftFeatureExtractorError(f"readout_token_indices item {index} must be non-negative.")
        indices.append(value)
    if len(indices) == 0:
        return None
    if indices != sorted(indices):
        raise RuntimeCiftFeatureExtractorError("readout_token_indices must be sorted.")
    if len(set(indices)) != len(indices):
        raise RuntimeCiftFeatureExtractorError("readout_token_indices must contain unique values.")
    return tuple(indices)


def _float_value(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise RuntimeCiftFeatureExtractorError(f"Feature value '{field_name}' must be numeric.")
    return float(value)
