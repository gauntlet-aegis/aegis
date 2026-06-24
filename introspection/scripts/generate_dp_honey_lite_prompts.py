from __future__ import annotations

import argparse
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, TypeAlias, cast

SCRIPT_PATH = Path(__file__).resolve()
INTROSPECTION_ROOT = SCRIPT_PATH.parents[1]
REPOSITORY_ROOT = INTROSPECTION_ROOT.parent
SRC_PATH = INTROSPECTION_ROOT / "src"
AEGIS_SRC_PATH = REPOSITORY_ROOT / "src"
for path in (AEGIS_SRC_PATH, SRC_PATH):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from aegis.canaries.dp_honey import DPHoneyCanaryGenerator, build_dp_honey_ledger
from aegis_introspection.honeytokens import (
    CredentialType,
    DpHoneyLiteExampleSpec,
    DpHoneyLiteTemplateSet,
    RenderedHoneytokenPrompt,
    TokenOffset,
    TokenizedText,
    build_dp_honey_lite_dataset,
    dp_honey_lite_templates,
    generate_honeytoken,
    render_honeytoken_prompt,
    write_dp_honey_lite_jsonl,
)

HoneytokenBackend: TypeAlias = Literal["lite", "dp_honey"]


class OffsetTokenizer(Protocol):
    def __call__(
        self,
        text: str,
        *,
        return_offsets_mapping: bool,
        add_special_tokens: bool,
    ) -> Mapping[str, object]:
        ...


@dataclass(frozen=True)
class GenerateDpHoneyLitePromptsConfig:
    output_path: Path
    model_id: str
    revision: str
    local_files_only: bool
    seed: str
    examples_per_template: int
    readout_width: int
    template_set: DpHoneyLiteTemplateSet
    honeytoken_backend: HoneytokenBackend


_DEFAULT_OUTPUT_BY_TEMPLATE_SET: dict[DpHoneyLiteTemplateSet, Path] = {
    "v1": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_lite_v1.jsonl",
    "hard_v2": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_lite_v2.jsonl",
    "hard_v3": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_lite_v3.jsonl",
    "hard_v4": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_lite_v4.jsonl",
    "hard_v4_1": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_lite_v4_1.jsonl",
    "hard_v4_3_sealed": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_lite_v4_3_sealed.jsonl",
}
_DEFAULT_DP_HONEY_OUTPUT_BY_TEMPLATE_SET: dict[DpHoneyLiteTemplateSet, Path] = {
    "v1": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_runtime_v1.jsonl",
    "hard_v2": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_runtime_v2.jsonl",
    "hard_v3": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_runtime_v3.jsonl",
    "hard_v4": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_runtime_v4.jsonl",
    "hard_v4_1": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_runtime_v4_1.jsonl",
    "hard_v4_3_sealed": INTROSPECTION_ROOT / "data" / "prompts_dp_honey_runtime_v4_3_sealed.jsonl",
}
_DEFAULT_SEED_BY_TEMPLATE_SET: dict[DpHoneyLiteTemplateSet, str] = {
    "v1": "aegis-dp-honey-lite-v1",
    "hard_v2": "aegis-dp-honey-lite-v2",
    "hard_v3": "aegis-dp-honey-lite-v3",
    "hard_v4": "aegis-dp-honey-lite-v4",
    "hard_v4_1": "aegis-dp-honey-lite-v4-1",
    "hard_v4_3_sealed": "aegis-dp-honey-lite-v4-3-sealed",
}
_DEFAULT_DP_HONEY_SEED_BY_TEMPLATE_SET: dict[DpHoneyLiteTemplateSet, str] = {
    "v1": "aegis-dp-honey-runtime-v1",
    "hard_v2": "aegis-dp-honey-runtime-v2",
    "hard_v3": "aegis-dp-honey-runtime-v3",
    "hard_v4": "aegis-dp-honey-runtime-v4",
    "hard_v4_1": "aegis-dp-honey-runtime-v4-1",
    "hard_v4_3_sealed": "aegis-dp-honey-runtime-v4-3-sealed",
}
_DP_HONEY_CREDENTIAL_FORMATS: dict[str, str] = {
    "api_key": "openai-project-key",
    "database_uri": "database-password",
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate DP-HONEY-lite proxy-shaped prompt rows.")
    parser.add_argument(
        "--output",
        required=False,
    )
    parser.add_argument(
        "--template-set",
        required=False,
        choices=("v1", "hard_v2", "hard_v3", "hard_v4", "hard_v4_1", "hard_v4_3_sealed"),
        default="v1",
    )
    parser.add_argument("--model-id", required=False, default="Qwen/Qwen3-0.6B")
    parser.add_argument("--revision", required=False, default="main")
    parser.add_argument("--allow-download", action="store_true")
    parser.add_argument("--seed", required=False)
    parser.add_argument("--examples-per-template", required=False, type=int, default=4)
    parser.add_argument("--readout-width", required=False, type=int, default=6)
    parser.add_argument("--honeytoken-backend", required=False, choices=("lite", "dp_honey"), default="lite")
    return parser


def _parse_args(argv: Sequence[str]) -> GenerateDpHoneyLitePromptsConfig:
    namespace = _build_parser().parse_args(argv)
    template_set = cast(DpHoneyLiteTemplateSet, namespace.template_set)
    honeytoken_backend = cast(HoneytokenBackend, namespace.honeytoken_backend)
    output_path = (
        Path(str(namespace.output))
        if namespace.output is not None
        else _default_output_path(template_set=template_set, honeytoken_backend=honeytoken_backend)
    )
    seed = (
        str(namespace.seed)
        if namespace.seed is not None
        else _default_seed(template_set=template_set, honeytoken_backend=honeytoken_backend)
    )
    return GenerateDpHoneyLitePromptsConfig(
        output_path=output_path,
        model_id=str(namespace.model_id),
        revision=str(namespace.revision),
        local_files_only=not bool(namespace.allow_download),
        seed=seed,
        examples_per_template=int(namespace.examples_per_template),
        readout_width=int(namespace.readout_width),
        template_set=template_set,
        honeytoken_backend=honeytoken_backend,
    )


def _default_output_path(template_set: DpHoneyLiteTemplateSet, honeytoken_backend: HoneytokenBackend) -> Path:
    if honeytoken_backend == "lite":
        return _DEFAULT_OUTPUT_BY_TEMPLATE_SET[template_set]
    if honeytoken_backend == "dp_honey":
        return _DEFAULT_DP_HONEY_OUTPUT_BY_TEMPLATE_SET[template_set]
    raise ValueError(f"Unsupported honeytoken backend '{honeytoken_backend}'.")


def _default_seed(template_set: DpHoneyLiteTemplateSet, honeytoken_backend: HoneytokenBackend) -> str:
    if honeytoken_backend == "lite":
        return _DEFAULT_SEED_BY_TEMPLATE_SET[template_set]
    if honeytoken_backend == "dp_honey":
        return _DEFAULT_DP_HONEY_SEED_BY_TEMPLATE_SET[template_set]
    raise ValueError(f"Unsupported honeytoken backend '{honeytoken_backend}'.")


def _load_tokenizer(config: GenerateDpHoneyLitePromptsConfig) -> OffsetTokenizer:
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(
        config.model_id,
        revision=config.revision,
        trust_remote_code=True,
        local_files_only=config.local_files_only,
    )
    return cast(OffsetTokenizer, tokenizer)


def _integer_sequence(value: object, field_name: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise TypeError(f"Tokenizer field '{field_name}' must be a list.")
    integers: list[int] = []
    for index, item in enumerate(value):
        if not isinstance(item, int):
            raise TypeError(f"Tokenizer field '{field_name}' item {index} must be an integer.")
        integers.append(item)
    return tuple(integers)


def _offset_sequence(value: object, field_name: str) -> tuple[TokenOffset, ...]:
    if not isinstance(value, list):
        raise TypeError(f"Tokenizer field '{field_name}' must be a list.")
    offsets: list[TokenOffset] = []
    for index, item in enumerate(value):
        if not isinstance(item, tuple) and not isinstance(item, list):
            raise TypeError(f"Tokenizer field '{field_name}' item {index} must be a pair.")
        if len(item) != 2:
            raise TypeError(f"Tokenizer field '{field_name}' item {index} must contain two values.")
        start, end = item
        if not isinstance(start, int) or not isinstance(end, int):
            raise TypeError(f"Tokenizer field '{field_name}' item {index} must contain integers.")
        offsets.append(TokenOffset(start=start, end=end))
    return tuple(offsets)


def _tokenized_text(tokenizer: OffsetTokenizer, text: str) -> TokenizedText:
    encoded = tokenizer(text, return_offsets_mapping=True, add_special_tokens=True)
    return TokenizedText(
        input_ids=_integer_sequence(value=encoded.get("input_ids"), field_name="input_ids"),
        offsets=_offset_sequence(value=encoded.get("offset_mapping"), field_name="offset_mapping"),
    )


def _credential_type_for_index(index: int) -> CredentialType:
    if index % 2 == 0:
        return "api_key"
    return "database_uri"


def _dp_honey_runtime_token(credential_type: CredentialType, seed: str, index: int) -> str:
    ledger = build_dp_honey_ledger(
        session_id=seed,
        generator=DPHoneyCanaryGenerator(credential_formats=dict(_DP_HONEY_CREDENTIAL_FORMATS)),
    )
    honeytoken = ledger.plant(
        slot_name=f"cift_{credential_type}_{index:06d}",
        credential_type=credential_type,
        turn_index=index,
    )
    return honeytoken.value


def _honeytoken_for_backend(
    credential_type: CredentialType,
    seed: str,
    index: int,
    honeytoken_backend: HoneytokenBackend,
) -> str:
    if honeytoken_backend == "lite":
        return generate_honeytoken(
            credential_type=credential_type,
            seed=seed,
            index=index,
        )
    if honeytoken_backend == "dp_honey":
        return _dp_honey_runtime_token(
            credential_type=credential_type,
            seed=seed,
            index=index,
        )
    raise ValueError(f"Unsupported honeytoken backend '{honeytoken_backend}'.")


def _rendered_prompt_for_backend(
    rendered: RenderedHoneytokenPrompt,
    honeytoken_backend: HoneytokenBackend,
) -> RenderedHoneytokenPrompt:
    if honeytoken_backend == "lite":
        return rendered
    if honeytoken_backend == "dp_honey":
        return RenderedHoneytokenPrompt(
            template_id=rendered.template_id,
            label=rendered.label,
            family=rendered.family,
            text=rendered.text,
            tags=(*rendered.tags, "dp_honey_runtime"),
            secret_span=rendered.secret_span,
            query_span=rendered.query_span,
            payload_span=rendered.payload_span,
        )
    raise ValueError(f"Unsupported honeytoken backend '{honeytoken_backend}'.")


def _example_specs(
    tokenizer: OffsetTokenizer,
    config: GenerateDpHoneyLitePromptsConfig,
) -> tuple[DpHoneyLiteExampleSpec, ...]:
    if config.examples_per_template <= 0:
        raise ValueError("examples_per_template must be positive.")
    if config.readout_width <= 0:
        raise ValueError("readout_width must be positive.")

    specs: list[DpHoneyLiteExampleSpec] = []
    global_index = 0
    for template in dp_honey_lite_templates(template_set=config.template_set):
        for template_index in range(config.examples_per_template):
            credential_type = _credential_type_for_index(global_index)
            honeytoken = _honeytoken_for_backend(
                credential_type=credential_type,
                seed=config.seed,
                index=global_index,
                honeytoken_backend=config.honeytoken_backend,
            )
            rendered = _rendered_prompt_for_backend(
                rendered=render_honeytoken_prompt(template=template, secret=honeytoken),
                honeytoken_backend=config.honeytoken_backend,
            )
            specs.append(
                (
                    f"{template.template_id}_{template_index:03d}",
                    credential_type,
                    honeytoken,
                    rendered,
                    _tokenized_text(tokenizer=tokenizer, text=rendered.text),
                    config.readout_width,
                )
            )
            global_index += 1
    return tuple(specs)


def run_generation(config: GenerateDpHoneyLitePromptsConfig) -> None:
    tokenizer = _load_tokenizer(config)
    examples = build_dp_honey_lite_dataset(example_specs=_example_specs(tokenizer=tokenizer, config=config))
    write_dp_honey_lite_jsonl(path=config.output_path, examples=examples)

    label_counts = Counter(example.label for example in examples)
    family_count = len({example.family for example in examples})
    print(f"Wrote {len(examples)} DP-HONEY-lite examples to {config.output_path}")
    print(f"labels={dict(sorted(label_counts.items()))} families={family_count}")


def main(argv: Sequence[str]) -> None:
    run_generation(_parse_args(argv))


if __name__ == "__main__":
    main(tuple(sys.argv[1:]))
