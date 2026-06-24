from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Protocol

import torch
from transformers import BatchEncoding

from aegis.core.contracts import JsonValue, NormalizedTurn
from aegis.core.orchestrator import ModelResponse
from aegis_introspection.model_loader import LoadedCausalLM
from aegis_introspection.runtime_cift_model_host import (
    RuntimeCiftModelHost,
    RuntimeCiftModelHostConfig,
    build_runtime_cift_model_host,
    render_runtime_prompt,
)


class RuntimeCiftSelfHostedProviderError(RuntimeError):
    """Raised when the self-hosted CIFT provider cannot generate a response."""


class RuntimeCiftGenerationTimeoutError(RuntimeCiftSelfHostedProviderError):
    """Raised when self-hosted generation exceeds its configured deadline."""


class TextGenerationRunner(Protocol):
    def generate(
        self,
        loaded_model: LoadedCausalLM,
        prompt: str,
        config: RuntimeCiftGenerationConfig,
    ) -> GeneratedText:
        """Generate text from a hosted causal language model."""


@dataclass(frozen=True)
class RuntimeCiftGenerationConfig:
    max_new_tokens: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        if self.max_new_tokens < 1:
            raise RuntimeCiftSelfHostedProviderError("max_new_tokens must be positive.")
        if self.timeout_seconds <= 0:
            raise RuntimeCiftSelfHostedProviderError("timeout_seconds must be positive.")


@dataclass(frozen=True)
class RuntimeCiftSelfHostedProviderConfig:
    model_host: RuntimeCiftModelHostConfig
    generation: RuntimeCiftGenerationConfig
    provider_name: str

    def __post_init__(self) -> None:
        if self.provider_name == "":
            raise RuntimeCiftSelfHostedProviderError("provider_name must not be empty.")


@dataclass(frozen=True)
class GeneratedText:
    text: str
    metadata: dict[str, JsonValue]


@dataclass(frozen=True)
class TransformersTextGenerationRunner:
    def generate(
        self,
        loaded_model: LoadedCausalLM,
        prompt: str,
        config: RuntimeCiftGenerationConfig,
    ) -> GeneratedText:
        encoded = loaded_model.tokenizer(prompt, return_tensors="pt")
        if not isinstance(encoded, BatchEncoding):
            raise RuntimeCiftSelfHostedProviderError("Expected tokenizer output to be a transformers.BatchEncoding.")
        encoded = encoded.to(loaded_model.device.torch_device)
        input_ids = _tensor_field(encoded=encoded, field_name="input_ids")
        attention_mask = _optional_tensor_field(encoded=encoded, field_name="attention_mask")
        input_length = int(input_ids.shape[-1])

        with torch.no_grad():
            generated_ids = loaded_model.model.generate(
                input_ids=input_ids,
                attention_mask=attention_mask,
                max_new_tokens=config.max_new_tokens,
                do_sample=False,
                use_cache=True,
            )

        if not isinstance(generated_ids, torch.Tensor):
            raise RuntimeCiftSelfHostedProviderError("Model generation did not return a tensor.")
        if len(generated_ids.shape) != 2 or int(generated_ids.shape[0]) != 1:
            raise RuntimeCiftSelfHostedProviderError("Model generation must return a single batch of token ids.")

        generated_token_ids = generated_ids[0, input_length:].detach().cpu()
        decoded = loaded_model.tokenizer.decode(generated_token_ids.tolist(), skip_special_tokens=True)
        if not isinstance(decoded, str):
            raise RuntimeCiftSelfHostedProviderError("Tokenizer decode returned a non-string value.")
        return GeneratedText(
            text=decoded,
            metadata={
                "generated_token_count": int(generated_token_ids.numel()),
                "generation_runner": "transformers.generate",
            },
        )


class RuntimeCiftSelfHostedProvider:
    def __init__(
        self,
        model_host: RuntimeCiftModelHost,
        generation_runner: TextGenerationRunner,
        generation_config: RuntimeCiftGenerationConfig,
        provider_name: str,
    ) -> None:
        if provider_name == "":
            raise RuntimeCiftSelfHostedProviderError("provider_name must not be empty.")
        self._model_host = model_host
        self._generation_runner = generation_runner
        self._generation_config = generation_config
        self._provider_name = provider_name

    def generate(self, turn: NormalizedTurn) -> ModelResponse:
        started_at = time.perf_counter()
        generated = _run_with_timeout(
            operation=lambda: self._model_host.run_exclusive(
                _GenerateOperation(
                    turn=turn,
                    model_host=self._model_host,
                    generation_runner=self._generation_runner,
                    generation_config=self._generation_config,
                )
            ),
            timeout_seconds=self._generation_config.timeout_seconds,
        )
        latency_ms = (time.perf_counter() - started_at) * 1000.0
        metadata: dict[str, JsonValue] = {
            "provider": self._provider_name,
            "source": "aegis_introspection.runtime_cift_self_hosted_provider",
            "model_id": turn.model.model_id,
            "revision": turn.model.revision,
            "selected_device": turn.model.selected_device,
            "prompt_render_mode": self._model_host.config.prompt_rendering.mode,
            "max_new_tokens": self._generation_config.max_new_tokens,
            "timeout_seconds": self._generation_config.timeout_seconds,
            "latency_ms": latency_ms,
        }
        metadata.update(generated.metadata)
        return ModelResponse(output_text=generated.text, metadata=metadata)


@dataclass(frozen=True)
class _GenerateOperation:
    turn: NormalizedTurn
    model_host: RuntimeCiftModelHost
    generation_runner: TextGenerationRunner
    generation_config: RuntimeCiftGenerationConfig

    def __call__(self, loaded_model: LoadedCausalLM) -> GeneratedText:
        prompt = render_runtime_prompt(
            turn=self.turn,
            tokenizer=loaded_model.tokenizer,
            config=self.model_host.config.prompt_rendering,
        )
        return self.generation_runner.generate(
            loaded_model=loaded_model,
            prompt=prompt,
            config=self.generation_config,
        )


def build_runtime_cift_self_hosted_provider(
    config: RuntimeCiftSelfHostedProviderConfig,
) -> RuntimeCiftSelfHostedProvider:
    return RuntimeCiftSelfHostedProvider(
        model_host=build_runtime_cift_model_host(config=config.model_host),
        generation_runner=TransformersTextGenerationRunner(),
        generation_config=config.generation,
        provider_name=config.provider_name,
    )


def _run_with_timeout(operation: Callable[[], GeneratedText], timeout_seconds: float) -> GeneratedText:
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="aegis-cift-generation")
    future = executor.submit(operation)
    try:
        result = future.result(timeout=timeout_seconds)
    except FutureTimeoutError as exc:
        future.cancel()
        raise RuntimeCiftGenerationTimeoutError(
            f"Self-hosted generation exceeded timeout_seconds={timeout_seconds}."
        ) from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    if not isinstance(result, GeneratedText):
        raise RuntimeCiftSelfHostedProviderError("generation operation returned an invalid result.")
    return result


def _tensor_field(encoded: BatchEncoding, field_name: str) -> torch.Tensor:
    value = encoded.data.get(field_name)
    if not isinstance(value, torch.Tensor):
        raise RuntimeCiftSelfHostedProviderError(f"Expected tokenizer field '{field_name}' to be a torch.Tensor.")
    return value


def _optional_tensor_field(encoded: BatchEncoding, field_name: str) -> torch.Tensor | None:
    value = encoded.data.get(field_name)
    if value is None:
        return None
    if not isinstance(value, torch.Tensor):
        raise RuntimeCiftSelfHostedProviderError(f"Expected tokenizer field '{field_name}' to be a torch.Tensor.")
    return value
