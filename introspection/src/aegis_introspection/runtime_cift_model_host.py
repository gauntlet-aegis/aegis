from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import Literal, Protocol, TypeAlias, runtime_checkable

from transformers import PreTrainedTokenizerBase

from aegis_introspection.activations import HiddenStateForwardPass, run_hidden_state_forward
from aegis_introspection.features import PoolingMethod
from aegis_introspection.model_loader import LoadedCausalLM, ModelLoadConfig, load_causal_lm
from aegis_introspection.probe import JsonValue
from aegis_introspection.runtime_cift_feature_extractor import (
    FeatureVector,
    RuntimeCiftFeatureExtractor,
    RuntimeMessageLike,
    RuntimeTurnLike,
    parse_runtime_cift_feature_key,
    readout_indices_from_turn,
    rendered_prompt_from_turn,
)

PromptRenderMode: TypeAlias = Literal["single_rendered_prompt", "chat_template"]
ChatMessage: TypeAlias = dict[str, str]


class RuntimeCiftModelHostError(ValueError):
    """Raised when a runtime turn cannot be rendered or hosted for CIFT extraction."""


class CausalLmLoader(Protocol):
    def load(self, config: ModelLoadConfig) -> LoadedCausalLM:
        """Load a causal language model once for hosted extraction."""


class ForwardPassLock(Protocol):
    def __enter__(self) -> object:
        """Acquire the forward-pass lock."""

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Release the forward-pass lock."""


@runtime_checkable
class ChatTemplateTokenizer(Protocol):
    def apply_chat_template(
        self,
        conversation: list[ChatMessage],
        tokenize: bool,
        add_generation_prompt: bool,
    ) -> str:
        """Render chat messages with the tokenizer's native chat template."""


@dataclass(frozen=True)
class RuntimePromptRenderConfig:
    mode: PromptRenderMode
    add_generation_prompt: bool


@dataclass(frozen=True)
class RuntimeCiftModelHostConfig:
    model: ModelLoadConfig
    prompt_rendering: RuntimePromptRenderConfig


@dataclass(frozen=True)
class TransformersCausalLmLoader:
    def load(self, config: ModelLoadConfig) -> LoadedCausalLM:
        return load_causal_lm(config=config)


@dataclass(frozen=True)
class _RenderedPromptMessage:
    role: str
    content: str


@dataclass(frozen=True)
class _RenderedPromptTurn:
    messages: tuple[RuntimeMessageLike, ...]
    metadata: Mapping[str, JsonValue]


@dataclass(frozen=True)
class _LockedLoadedModelHiddenStateForwardRunner:
    loaded_model: LoadedCausalLM
    forward_lock: ForwardPassLock

    def run(self, prompt: str) -> HiddenStateForwardPass:
        with self.forward_lock:
            return run_hidden_state_forward(loaded_model=self.loaded_model, prompt=prompt)


class RuntimeCiftModelHost:
    def __init__(self, config: RuntimeCiftModelHostConfig, loader: CausalLmLoader) -> None:
        self._config = config
        self._loader = loader
        self._load_lock = threading.Lock()
        self._forward_lock = threading.Lock()
        self._loaded_model: LoadedCausalLM | None = None

    def extract_feature_vector(self, turn: RuntimeTurnLike, feature_key: str) -> FeatureVector | None:
        parsed_key = parse_runtime_cift_feature_key(feature_key=feature_key)
        readout_token_indices = readout_indices_from_turn(turn=turn)
        if _requires_readout_window(pooling_method=parsed_key.pooling_method) and readout_token_indices is None:
            return None

        loaded_model = self.loaded_model()
        prompt = render_runtime_prompt(
            turn=turn,
            tokenizer=loaded_model.tokenizer,
            config=self._config.prompt_rendering,
        )
        rendered_turn = _RenderedPromptTurn(
            messages=(_RenderedPromptMessage(role="user", content=prompt),),
            metadata=turn.metadata,
        )
        extractor = RuntimeCiftFeatureExtractor(
            forward_runner=_LockedLoadedModelHiddenStateForwardRunner(
                loaded_model=loaded_model,
                forward_lock=self._forward_lock,
            )
        )
        return extractor.extract_feature_vector(turn=rendered_turn, feature_key=feature_key)

    def loaded_model(self) -> LoadedCausalLM:
        loaded_model = self._loaded_model
        if loaded_model is not None:
            return loaded_model

        with self._load_lock:
            loaded_model = self._loaded_model
            if loaded_model is not None:
                return loaded_model
            loaded_model = self._loader.load(config=self._config.model)
            self._loaded_model = loaded_model
            return loaded_model


def build_runtime_cift_model_host(config: RuntimeCiftModelHostConfig) -> RuntimeCiftModelHost:
    return RuntimeCiftModelHost(config=config, loader=TransformersCausalLmLoader())


def render_runtime_prompt(
    turn: RuntimeTurnLike,
    tokenizer: PreTrainedTokenizerBase,
    config: RuntimePromptRenderConfig,
) -> str:
    if config.mode == "single_rendered_prompt":
        return rendered_prompt_from_turn(turn=turn)
    if config.mode == "chat_template":
        return render_chat_template_prompt(
            turn=turn,
            tokenizer=tokenizer,
            add_generation_prompt=config.add_generation_prompt,
        )
    raise RuntimeCiftModelHostError(f"Unsupported prompt rendering mode '{config.mode}'.")


def render_chat_template_prompt(
    turn: RuntimeTurnLike,
    tokenizer: PreTrainedTokenizerBase,
    add_generation_prompt: bool,
) -> str:
    if not isinstance(tokenizer, ChatTemplateTokenizer):
        raise RuntimeCiftModelHostError("Tokenizer does not expose apply_chat_template.")
    rendered = tokenizer.apply_chat_template(
        conversation=messages_to_chat_template_input(turn=turn),
        tokenize=False,
        add_generation_prompt=add_generation_prompt,
    )
    if not isinstance(rendered, str):
        raise RuntimeCiftModelHostError("Tokenizer chat template returned a non-string prompt.")
    if rendered == "":
        raise RuntimeCiftModelHostError("Tokenizer chat template returned an empty prompt.")
    return rendered


def messages_to_chat_template_input(turn: RuntimeTurnLike) -> list[ChatMessage]:
    if len(turn.messages) == 0:
        raise RuntimeCiftModelHostError("Runtime CIFT chat-template rendering requires at least one message.")

    messages: list[ChatMessage] = []
    for index, message in enumerate(turn.messages):
        role = _non_empty_string(value=message.role, field_name=f"messages[{index}].role")
        content = _non_empty_string(value=message.content, field_name=f"messages[{index}].content")
        messages.append({"role": role, "content": content})
    return messages


def _requires_readout_window(pooling_method: PoolingMethod) -> bool:
    return pooling_method == "readout_window"


def _non_empty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise RuntimeCiftModelHostError(f"{field_name} must be a string.")
    if value == "":
        raise RuntimeCiftModelHostError(f"{field_name} must not be empty.")
    return value
