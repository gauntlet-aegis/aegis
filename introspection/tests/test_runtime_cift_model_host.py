from __future__ import annotations

import threading
import time
import unittest
from dataclasses import dataclass
from typing import cast

import torch
from aegis_introspection.model_loader import DeviceSelection, LoadedCausalLM, ModelLoadConfig
from aegis_introspection.runtime_cift_model_host import (
    RuntimeCiftModelHost,
    RuntimeCiftModelHostConfig,
    RuntimeCiftModelHostError,
    RuntimePromptRenderConfig,
    messages_to_chat_template_input,
    render_runtime_prompt,
)
from transformers import BatchEncoding, PreTrainedModel, PreTrainedTokenizerBase

from aegis.core.contracts import CapabilityMode, Message, ModelInfo, NormalizedTurn


class RuntimeCiftModelHostTest(unittest.TestCase):
    def test_model_host_lazily_loads_once_and_extracts_single_rendered_prompt_feature(self) -> None:
        tokenizer = FakeTokenizer()
        model = FakeModel(sleep_seconds=0.0)
        loader = FakeLoader(tokenizer=tokenizer, model=model)
        host = RuntimeCiftModelHost(
            config=_host_config(RuntimePromptRenderConfig(mode="single_rendered_prompt", add_generation_prompt=False)),
            loader=loader,
        )

        first_vector = host.extract_feature_vector(
            turn=_turn(messages=_rendered_messages(), metadata={}),
            feature_key="final_token_layer_02",
        )
        second_vector = host.extract_feature_vector(
            turn=_turn(messages=_rendered_messages(), metadata={}),
            feature_key="final_token_layer_02",
        )

        self.assertEqual((13.0, 14.0, 15.0), first_vector)
        self.assertEqual((13.0, 14.0, 15.0), second_vector)
        self.assertEqual(1, loader.load_calls)
        self.assertEqual(("rendered prompt", "rendered prompt"), tuple(tokenizer.encoded_prompts))

    def test_model_host_does_not_load_model_for_missing_readout_geometry(self) -> None:
        tokenizer = FakeTokenizer()
        model = FakeModel(sleep_seconds=0.0)
        loader = FakeLoader(tokenizer=tokenizer, model=model)
        host = RuntimeCiftModelHost(
            config=_host_config(RuntimePromptRenderConfig(mode="single_rendered_prompt", add_generation_prompt=False)),
            loader=loader,
        )

        feature_vector = host.extract_feature_vector(
            turn=_turn(messages=_rendered_messages(), metadata={}),
            feature_key="readout_window_layer_02",
        )

        self.assertIsNone(feature_vector)
        self.assertEqual(0, loader.load_calls)
        self.assertEqual((), tuple(tokenizer.encoded_prompts))

    def test_model_host_renders_chat_template_messages(self) -> None:
        tokenizer = FakeTokenizer()
        model = FakeModel(sleep_seconds=0.0)
        loader = FakeLoader(tokenizer=tokenizer, model=model)
        host = RuntimeCiftModelHost(
            config=_host_config(RuntimePromptRenderConfig(mode="chat_template", add_generation_prompt=True)),
            loader=loader,
        )

        feature_vector = host.extract_feature_vector(
            turn=_turn(
                messages=(
                    Message(role="system", content="follow policy"),
                    Message(role="user", content="inspect this"),
                ),
                metadata={},
            ),
            feature_key="mean_pool_layer_02",
        )

        self.assertEqual((10.0, 11.0, 12.0), feature_vector)
        self.assertEqual("system=follow policy|user=inspect this|generation=True", tokenizer.encoded_prompts[0])
        self.assertEqual(
            (
                ChatTemplateCall(
                    messages=(
                        ("system", "follow policy"),
                        ("user", "inspect this"),
                    ),
                    tokenize=False,
                    add_generation_prompt=True,
                ),
            ),
            tuple(tokenizer.chat_template_calls),
        )

    def test_model_host_serializes_concurrent_forward_passes(self) -> None:
        tokenizer = FakeTokenizer()
        model = FakeModel(sleep_seconds=0.01)
        loader = FakeLoader(tokenizer=tokenizer, model=model)
        host = RuntimeCiftModelHost(
            config=_host_config(RuntimePromptRenderConfig(mode="single_rendered_prompt", add_generation_prompt=False)),
            loader=loader,
        )
        start_barrier = threading.Barrier(6)
        results: list[tuple[float, ...] | None] = []
        errors: list[BaseException] = []

        def extract() -> None:
            try:
                start_barrier.wait()
                results.append(
                    host.extract_feature_vector(
                        turn=_turn(messages=_rendered_messages(), metadata={}),
                        feature_key="final_token_layer_02",
                    )
                )
            except BaseException as exc:
                errors.append(exc)

        threads = tuple(threading.Thread(target=extract) for _ in range(5))
        for thread in threads:
            thread.start()
        start_barrier.wait()
        for thread in threads:
            thread.join()

        self.assertEqual([], errors)
        self.assertEqual(((13.0, 14.0, 15.0),) * 5, tuple(results))
        self.assertEqual(1, loader.load_calls)
        self.assertEqual(1, model.max_active_forward_calls)

    def test_render_runtime_prompt_requires_chat_template_support(self) -> None:
        with self.assertRaises(RuntimeCiftModelHostError):
            render_runtime_prompt(
                turn=_turn(messages=_rendered_messages(), metadata={}),
                tokenizer=cast(PreTrainedTokenizerBase, TokenizerWithoutChatTemplate()),
                config=RuntimePromptRenderConfig(mode="chat_template", add_generation_prompt=False),
            )

    def test_chat_template_input_rejects_empty_messages(self) -> None:
        with self.assertRaises(RuntimeCiftModelHostError):
            messages_to_chat_template_input(
                _turn(
                    messages=(),
                    metadata={},
                )
            )


@dataclass(frozen=True)
class ChatTemplateCall:
    messages: tuple[tuple[str, str], ...]
    tokenize: bool
    add_generation_prompt: bool


@dataclass(frozen=True)
class FakeOutputs:
    hidden_states: tuple[torch.Tensor, ...] | None


class FakeTokenizer:
    def __init__(self) -> None:
        self.encoded_prompts: list[str] = []
        self.chat_template_calls: list[ChatTemplateCall] = []

    def __call__(self, prompt: str, return_tensors: str) -> BatchEncoding:
        if return_tensors != "pt":
            raise AssertionError("FakeTokenizer only supports return_tensors='pt'.")
        self.encoded_prompts.append(prompt)
        return BatchEncoding(
            {
                "input_ids": torch.tensor([[1, 2, 3, 4]], dtype=torch.long),
                "attention_mask": torch.tensor([[1, 1, 1, 1]], dtype=torch.long),
            }
        )

    def apply_chat_template(
        self,
        conversation: list[dict[str, str]],
        tokenize: bool,
        add_generation_prompt: bool,
    ) -> str:
        self.chat_template_calls.append(
            ChatTemplateCall(
                messages=tuple((message["role"], message["content"]) for message in conversation),
                tokenize=tokenize,
                add_generation_prompt=add_generation_prompt,
            )
        )
        rendered_messages = "|".join(f"{message['role']}={message['content']}" for message in conversation)
        return f"{rendered_messages}|generation={add_generation_prompt}"


class TokenizerWithoutChatTemplate:
    def __call__(self, prompt: str, return_tensors: str) -> BatchEncoding:
        if prompt == "" or return_tensors != "pt":
            raise AssertionError("Unexpected tokenizer invocation.")
        return BatchEncoding({"input_ids": torch.tensor([[1]], dtype=torch.long)})


class FakeModel:
    def __init__(self, sleep_seconds: float) -> None:
        self._sleep_seconds = sleep_seconds
        self._lock = threading.Lock()
        self._active_forward_calls = 0
        self.max_active_forward_calls = 0

    def __call__(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor | None,
        output_hidden_states: bool,
        use_cache: bool,
    ) -> FakeOutputs:
        if tuple(input_ids.shape) != (1, 4):
            raise AssertionError("Unexpected fake input_ids shape.")
        if attention_mask is None:
            raise AssertionError("Fake model expects an attention mask.")
        if not output_hidden_states:
            raise AssertionError("CIFT host must request hidden states.")
        if use_cache:
            raise AssertionError("CIFT host must disable cache during hidden-state extraction.")

        with self._lock:
            self._active_forward_calls += 1
            self.max_active_forward_calls = max(self.max_active_forward_calls, self._active_forward_calls)
        try:
            time.sleep(self._sleep_seconds)
            return FakeOutputs(
                hidden_states=(
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
            )
        finally:
            with self._lock:
                self._active_forward_calls -= 1


class FakeLoader:
    def __init__(self, tokenizer: FakeTokenizer, model: FakeModel) -> None:
        self._tokenizer = tokenizer
        self._model = model
        self.load_calls = 0

    def load(self, config: ModelLoadConfig) -> LoadedCausalLM:
        self.load_calls += 1
        return LoadedCausalLM(
            model_id=config.model_id,
            revision=config.revision,
            device=DeviceSelection(name="cpu", torch_device=torch.device("cpu"), torch_dtype=torch.float32),
            tokenizer=cast(PreTrainedTokenizerBase, self._tokenizer),
            model=cast(PreTrainedModel, self._model),
        )


def _host_config(prompt_rendering: RuntimePromptRenderConfig) -> RuntimeCiftModelHostConfig:
    return RuntimeCiftModelHostConfig(
        model=ModelLoadConfig(
            model_id="Qwen/Qwen3-0.6B",
            revision="main",
            requested_device="cpu",
            local_files_only=True,
        ),
        prompt_rendering=prompt_rendering,
    )


def _rendered_messages() -> tuple[Message, ...]:
    return (Message(role="user", content="rendered prompt"),)


def _turn(messages: tuple[Message, ...], metadata: dict[str, object]) -> NormalizedTurn:
    return NormalizedTurn(
        trace_id="trace-runtime-cift-host",
        session_id="session-runtime-cift-host",
        turn_index=1,
        capability_mode=CapabilityMode.SELF_HOSTED_INTROSPECTION,
        model=ModelInfo(provider="huggingface", model_id="Qwen/Qwen3-0.6B", revision="main", selected_device="cpu"),
        messages=messages,
        tool_calls=(),
        sensitive_spans=(),
        metadata=metadata,
    )


if __name__ == "__main__":
    unittest.main()
