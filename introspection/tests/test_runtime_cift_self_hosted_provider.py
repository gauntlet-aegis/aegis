from __future__ import annotations

import threading
import time
import unittest
from typing import cast

import torch
from aegis_introspection.model_loader import DeviceSelection, LoadedCausalLM, ModelLoadConfig
from aegis_introspection.runtime_cift_model_host import (
    PromptRenderMode,
    RuntimeCiftModelHost,
    RuntimeCiftModelHostConfig,
    RuntimePromptRenderConfig,
)
from aegis_introspection.runtime_cift_self_hosted_provider import (
    GeneratedText,
    RuntimeCiftGenerationConfig,
    RuntimeCiftGenerationTimeoutError,
    RuntimeCiftSelfHostedProvider,
    RuntimeCiftSelfHostedProviderConfig,
)
from transformers import PreTrainedModel, PreTrainedTokenizerBase

from aegis.audit.memory import InMemoryAuditSink
from aegis.core.contracts import CapabilityMode, Message, ModelInfo, NormalizedTurn
from aegis.core.orchestrator import AegisRuntime, RuntimeRequest
from aegis.policy.engine import SeverityPolicyEngine


class RuntimeCiftSelfHostedProviderTest(unittest.TestCase):
    def test_provider_generates_from_single_rendered_prompt_inside_runtime(self) -> None:
        loader = FakeLoader(tokenizer=FakeTokenizer())
        runner = RecordingGenerationRunner(sleep_seconds=0.0)
        provider = RuntimeCiftSelfHostedProvider(
            model_host=_model_host(loader=loader, mode="single_rendered_prompt", add_generation_prompt=False),
            generation_runner=runner,
            generation_config=RuntimeCiftGenerationConfig(max_new_tokens=8, timeout_seconds=1.0),
            provider_name="cift_self_hosted",
        )
        audit_sink = InMemoryAuditSink()
        runtime = AegisRuntime(
            turn_annotators=(),
            pre_generation_detectors=(),
            post_generation_detectors=(),
            session_detectors=(),
            policy_engine=SeverityPolicyEngine(),
            audit_sink=audit_sink,
            model_provider=provider,
        )

        response = runtime.evaluate_turn(_request(messages=(Message(role="user", content="rendered prompt"),)))

        self.assertEqual("generated:rendered prompt", response.output_text)
        self.assertEqual(1, loader.load_calls)
        self.assertEqual(("rendered prompt",), tuple(runner.prompts))
        self.assertEqual("allow", response.policy_decision.final_action.value)
        self.assertEqual("cift_self_hosted", response.audit_event.normalized_turn.model.provider)
        self.assertEqual(1, len(audit_sink.recent(limit=10)))

    def test_provider_renders_chat_template_prompt(self) -> None:
        tokenizer = FakeTokenizer()
        loader = FakeLoader(tokenizer=tokenizer)
        runner = RecordingGenerationRunner(sleep_seconds=0.0)
        provider = RuntimeCiftSelfHostedProvider(
            model_host=_model_host(loader=loader, mode="chat_template", add_generation_prompt=True),
            generation_runner=runner,
            generation_config=RuntimeCiftGenerationConfig(max_new_tokens=8, timeout_seconds=1.0),
            provider_name="cift_self_hosted",
        )

        response = provider.generate(
            _turn(
                messages=(
                    Message(role="system", content="follow policy"),
                    Message(role="user", content="inspect this"),
                )
            )
        )

        self.assertEqual("generated:system=follow policy|user=inspect this|generation=True", response.output_text)
        self.assertEqual(("system=follow policy|user=inspect this|generation=True",), tuple(runner.prompts))
        self.assertEqual((True,), tuple(tokenizer.add_generation_prompt_values))

    def test_provider_reuses_loaded_model(self) -> None:
        loader = FakeLoader(tokenizer=FakeTokenizer())
        runner = RecordingGenerationRunner(sleep_seconds=0.0)
        provider = RuntimeCiftSelfHostedProvider(
            model_host=_model_host(loader=loader, mode="single_rendered_prompt", add_generation_prompt=False),
            generation_runner=runner,
            generation_config=RuntimeCiftGenerationConfig(max_new_tokens=8, timeout_seconds=1.0),
            provider_name="cift_self_hosted",
        )

        provider.generate(_turn(messages=(Message(role="user", content="first"),)))
        provider.generate(_turn(messages=(Message(role="user", content="second"),)))

        self.assertEqual(1, loader.load_calls)
        self.assertEqual(("first", "second"), tuple(runner.prompts))

    def test_provider_serializes_concurrent_generation(self) -> None:
        loader = FakeLoader(tokenizer=FakeTokenizer())
        runner = RecordingGenerationRunner(sleep_seconds=0.01)
        provider = RuntimeCiftSelfHostedProvider(
            model_host=_model_host(loader=loader, mode="single_rendered_prompt", add_generation_prompt=False),
            generation_runner=runner,
            generation_config=RuntimeCiftGenerationConfig(max_new_tokens=8, timeout_seconds=1.0),
            provider_name="cift_self_hosted",
        )
        start_barrier = threading.Barrier(6)
        results: list[str] = []
        errors: list[BaseException] = []

        def generate() -> None:
            try:
                start_barrier.wait()
                response = provider.generate(_turn(messages=(Message(role="user", content="rendered prompt"),)))
                results.append(response.output_text)
            except BaseException as exc:
                errors.append(exc)

        threads = tuple(threading.Thread(target=generate) for _ in range(5))
        for thread in threads:
            thread.start()
        start_barrier.wait()
        for thread in threads:
            thread.join()

        self.assertEqual([], errors)
        self.assertEqual(("generated:rendered prompt",) * 5, tuple(results))
        self.assertEqual(1, loader.load_calls)
        self.assertEqual(1, runner.max_active_calls)

    def test_provider_times_out_slow_generation(self) -> None:
        loader = FakeLoader(tokenizer=FakeTokenizer())
        runner = RecordingGenerationRunner(sleep_seconds=0.05)
        provider = RuntimeCiftSelfHostedProvider(
            model_host=_model_host(loader=loader, mode="single_rendered_prompt", add_generation_prompt=False),
            generation_runner=runner,
            generation_config=RuntimeCiftGenerationConfig(max_new_tokens=8, timeout_seconds=0.001),
            provider_name="cift_self_hosted",
        )

        with self.assertRaises(RuntimeCiftGenerationTimeoutError):
            provider.generate(_turn(messages=(Message(role="user", content="rendered prompt"),)))

    def test_provider_config_rejects_invalid_values(self) -> None:
        with self.assertRaises(RuntimeError):
            RuntimeCiftGenerationConfig(max_new_tokens=0, timeout_seconds=1.0)
        with self.assertRaises(RuntimeError):
            RuntimeCiftGenerationConfig(max_new_tokens=1, timeout_seconds=0.0)
        with self.assertRaises(RuntimeError):
            RuntimeCiftSelfHostedProviderConfig(
                model_host=_model_host_config(mode="single_rendered_prompt", add_generation_prompt=False),
                generation=RuntimeCiftGenerationConfig(max_new_tokens=1, timeout_seconds=1.0),
                provider_name="",
            )


class FakeTokenizer:
    def __init__(self) -> None:
        self.add_generation_prompt_values: list[bool] = []

    def apply_chat_template(
        self,
        conversation: list[dict[str, str]],
        tokenize: bool,
        add_generation_prompt: bool,
    ) -> str:
        if tokenize:
            raise AssertionError("FakeTokenizer renders text only.")
        self.add_generation_prompt_values.append(add_generation_prompt)
        rendered_messages = "|".join(f"{message['role']}={message['content']}" for message in conversation)
        return f"{rendered_messages}|generation={add_generation_prompt}"


class FakeModel:
    pass


class FakeLoader:
    def __init__(self, tokenizer: FakeTokenizer) -> None:
        self._tokenizer = tokenizer
        self.load_calls = 0

    def load(self, config: ModelLoadConfig) -> LoadedCausalLM:
        self.load_calls += 1
        return LoadedCausalLM(
            model_id=config.model_id,
            revision=config.revision,
            device=DeviceSelection(name="cpu", torch_device=torch.device("cpu"), torch_dtype=torch.float32),
            tokenizer=cast(PreTrainedTokenizerBase, self._tokenizer),
            model=cast(PreTrainedModel, FakeModel()),
        )


class RecordingGenerationRunner:
    def __init__(self, sleep_seconds: float) -> None:
        self._sleep_seconds = sleep_seconds
        self._lock = threading.Lock()
        self._active_calls = 0
        self.max_active_calls = 0
        self.prompts: list[str] = []

    def generate(
        self,
        loaded_model: LoadedCausalLM,
        prompt: str,
        config: RuntimeCiftGenerationConfig,
    ) -> GeneratedText:
        if loaded_model.model_id != "Qwen/Qwen3-0.6B":
            raise AssertionError("Unexpected model id.")
        if config.max_new_tokens != 8:
            raise AssertionError("Unexpected generation config.")
        with self._lock:
            self._active_calls += 1
            self.max_active_calls = max(self.max_active_calls, self._active_calls)
        try:
            self.prompts.append(prompt)
            time.sleep(self._sleep_seconds)
            return GeneratedText(
                text=f"generated:{prompt}",
                metadata={
                    "generation_runner": "recording",
                    "generated_token_count": 3,
                },
            )
        finally:
            with self._lock:
                self._active_calls -= 1


def _model_host(
    loader: FakeLoader,
    mode: str,
    add_generation_prompt: bool,
) -> RuntimeCiftModelHost:
    return RuntimeCiftModelHost(
        config=_model_host_config(mode=mode, add_generation_prompt=add_generation_prompt),
        loader=loader,
    )


def _model_host_config(mode: str, add_generation_prompt: bool) -> RuntimeCiftModelHostConfig:
    if mode not in ("single_rendered_prompt", "chat_template"):
        raise AssertionError("Unexpected prompt render mode.")
    return RuntimeCiftModelHostConfig(
        model=ModelLoadConfig(
            model_id="Qwen/Qwen3-0.6B",
            revision="main",
            requested_device="cpu",
            local_files_only=True,
        ),
        prompt_rendering=RuntimePromptRenderConfig(
            mode=cast(PromptRenderMode, mode),
            add_generation_prompt=add_generation_prompt,
        ),
    )


def _request(messages: tuple[Message, ...]) -> RuntimeRequest:
    return RuntimeRequest(
        trace_id="trace-cift-self-hosted-provider",
        session_id="session-cift-self-hosted-provider",
        turn_index=1,
        capability_mode=CapabilityMode.SELF_HOSTED_INTROSPECTION,
        model=ModelInfo(
            provider="cift_self_hosted",
            model_id="Qwen/Qwen3-0.6B",
            revision="main",
            selected_device="cpu",
        ),
        messages=messages,
        tool_calls=(),
        sensitive_spans=(),
        metadata={},
    )


def _turn(messages: tuple[Message, ...]) -> NormalizedTurn:
    request = _request(messages=messages)
    return NormalizedTurn(
        trace_id=request.trace_id,
        session_id=request.session_id,
        turn_index=request.turn_index,
        capability_mode=request.capability_mode,
        model=request.model,
        messages=request.messages,
        tool_calls=request.tool_calls,
        sensitive_spans=request.sensitive_spans,
        metadata=request.metadata,
    )


if __name__ == "__main__":
    unittest.main()
