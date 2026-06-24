from __future__ import annotations

import unittest

import torch
from aegis_introspection.activations import HiddenStateForwardPass
from aegis_introspection.runtime_cift_feature_extractor import (
    ParsedFeatureKey,
    RuntimeCiftFeatureExtractor,
    RuntimeCiftFeatureExtractorError,
    parse_runtime_cift_feature_key,
    readout_indices_from_turn,
    rendered_prompt_from_turn,
)

from aegis.core.contracts import CapabilityMode, Message, ModelInfo, NormalizedTurn
from aegis.detectors.cift_runtime import CiftFeatureVectorAnnotator, cift_feature_vector_from_turn


class RuntimeCiftFeatureExtractorTest(unittest.TestCase):
    def test_extract_feature_vector_pools_readout_window_for_requested_layer(self) -> None:
        runner = RecordingForwardRunner()
        extractor = RuntimeCiftFeatureExtractor(forward_runner=runner)
        turn = _turn(metadata={"cift": {"readout_token_indices": [1, 3]}})

        feature_vector = extractor.extract_feature_vector(turn=turn, feature_key="readout_window_layer_02")

        self.assertEqual(("rendered prompt",), tuple(runner.prompts))
        self.assertEqual((10.0, 11.0, 12.0), feature_vector)

    def test_feature_extractor_satisfies_runtime_annotator_protocol(self) -> None:
        extractor = RuntimeCiftFeatureExtractor(forward_runner=RecordingForwardRunner())
        annotator = CiftFeatureVectorAnnotator(
            feature_key="readout_window_layer_02",
            extractor=extractor,
            source="aegis_introspection.runtime_cift_feature_extractor",
        )

        annotated = annotator.annotate(_turn(metadata={"cift": {"readout_token_indices": [1, 3]}}))

        self.assertEqual((10.0, 11.0, 12.0), cift_feature_vector_from_turn(annotated, "readout_window_layer_02"))
        self.assertEqual("aegis_introspection.runtime_cift_feature_extractor", _feature_source(annotated))

    def test_readout_feature_returns_none_when_runtime_turn_lacks_readout_indices(self) -> None:
        runner = RecordingForwardRunner()
        extractor = RuntimeCiftFeatureExtractor(forward_runner=runner)

        feature_vector = extractor.extract_feature_vector(
            turn=_turn(metadata={}),
            feature_key="readout_window_layer_02",
        )

        self.assertIsNone(feature_vector)
        self.assertEqual([], runner.prompts)

    def test_mean_pool_feature_does_not_require_readout_indices(self) -> None:
        extractor = RuntimeCiftFeatureExtractor(forward_runner=RecordingForwardRunner())

        feature_vector = extractor.extract_feature_vector(turn=_turn(metadata={}), feature_key="mean_pool_layer_02")

        self.assertEqual((10.0, 11.0, 12.0), feature_vector)

    def test_final_token_feature_uses_final_prompt_token(self) -> None:
        extractor = RuntimeCiftFeatureExtractor(forward_runner=RecordingForwardRunner())

        feature_vector = extractor.extract_feature_vector(turn=_turn(metadata={}), feature_key="final_token_layer_02")

        self.assertEqual((13.0, 14.0, 15.0), feature_vector)

    def test_parse_runtime_cift_feature_key_accepts_zero_padded_layers(self) -> None:
        parsed = parse_runtime_cift_feature_key("readout_window_layer_02")

        self.assertEqual(ParsedFeatureKey(pooling_method="readout_window", layer_index=2), parsed)

    def test_parse_runtime_cift_feature_key_rejects_noncanonical_layer_padding(self) -> None:
        with self.assertRaises(RuntimeCiftFeatureExtractorError):
            parse_runtime_cift_feature_key("readout_window_layer_2")

    def test_parse_runtime_cift_feature_key_rejects_unknown_shape(self) -> None:
        with self.assertRaises(RuntimeCiftFeatureExtractorError):
            parse_runtime_cift_feature_key("concat(readout_window_layer_02)")

    def test_rendered_prompt_requires_single_user_message(self) -> None:
        with self.assertRaises(RuntimeCiftFeatureExtractorError):
            rendered_prompt_from_turn(_turn(messages=(Message(role="system", content="bad"),), metadata={}))
        with self.assertRaises(RuntimeCiftFeatureExtractorError):
            rendered_prompt_from_turn(
                _turn(
                    messages=(
                        Message(role="user", content="first"),
                        Message(role="user", content="second"),
                    ),
                    metadata={},
                )
            )

    def test_readout_indices_validate_shape(self) -> None:
        self.assertEqual((1, 3), readout_indices_from_turn(_turn(metadata={"cift": {"readout_token_indices": [1, 3]}})))

        bad_values = (
            {"cift": "bad"},
            {"cift": {"readout_token_indices": "bad"}},
            {"cift": {"readout_token_indices": [3, 1]}},
            {"cift": {"readout_token_indices": [1, 1]}},
            {"cift": {"readout_token_indices": [-1]}},
            {"cift": {"readout_token_indices": [False]}},
        )
        for metadata in bad_values:
            with self.subTest(metadata=metadata), self.assertRaises(RuntimeCiftFeatureExtractorError):
                readout_indices_from_turn(_turn(metadata=metadata))


class RecordingForwardRunner:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    def run(self, prompt: str) -> HiddenStateForwardPass:
        self.prompts.append(prompt)
        hidden_states = (
            torch.zeros((1, 4, 3), dtype=torch.float32),
            torch.ones((1, 4, 3), dtype=torch.float32),
            torch.tensor(
                [
                    [
                        [1.0, 2.0, 3.0],
                        [7.0, 8.0, 9.0],
                        [19.0, 20.0, 21.0],
                        [13.0, 14.0, 15.0],
                    ]
                ],
                dtype=torch.float32,
            ),
        )
        return HiddenStateForwardPass(
            prompt=prompt,
            input_ids=torch.tensor([[1, 2, 3, 4]], dtype=torch.long),
            attention_mask=torch.tensor([[1, 1, 1, 1]], dtype=torch.long),
            hidden_states=hidden_states,
        )


def _turn(
    metadata: dict[str, object],
    messages: tuple[Message, ...] = (Message(role="user", content="rendered prompt"),),
) -> NormalizedTurn:
    return NormalizedTurn(
        trace_id="trace-runtime-cift",
        session_id="session-runtime-cift",
        turn_index=1,
        capability_mode=CapabilityMode.SELF_HOSTED_INTROSPECTION,
        model=ModelInfo(provider="huggingface", model_id="Qwen/Qwen3-0.6B", revision="main", selected_device="cpu"),
        messages=messages,
        tool_calls=(),
        sensitive_spans=(),
        metadata=metadata,
    )


def _feature_source(turn: NormalizedTurn) -> object:
    cift_metadata = turn.metadata["cift"]
    if not isinstance(cift_metadata, dict):
        raise AssertionError("metadata.cift must be an object.")
    feature_sources = cift_metadata["feature_sources"]
    if not isinstance(feature_sources, dict):
        raise AssertionError("metadata.cift.feature_sources must be an object.")
    readout_source = feature_sources["readout_window_layer_02"]
    if not isinstance(readout_source, dict):
        raise AssertionError("feature source must be an object.")
    return readout_source["source"]


if __name__ == "__main__":
    unittest.main()
