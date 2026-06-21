from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
INTROSPECTION_ROOT = SCRIPT_PATH.parents[1]
SRC_PATH = INTROSPECTION_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from aegis_introspection.cift_holdout_evaluation import (  # noqa: E402
    CiftHoldoutEvaluationConfig,
    evaluate_cift_holdout,
    write_cift_holdout_evaluation_json,
    write_cift_holdout_evaluation_markdown,
)
from aegis_introspection.sealed_holdout import add_unseal_flag, assert_unsealed_paths  # noqa: E402


@dataclass(frozen=True)
class EvaluateCiftHoldoutCliConfig:
    artifact_path: Path
    model_bundle_path: Path
    output_json_path: Path
    output_markdown_path: Path
    evaluation_id: str
    holdout_dataset_id: str
    model_bundle_id: str
    allow_sealed_holdout: bool


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate a frozen CIFT model bundle on a sealed holdout artifact.")
    parser.add_argument(
        "--artifact",
        required=False,
        default=str(
            INTROSPECTION_ROOT / "data" / "activations" / "qwen3_0_6b_dp_honey_runtime_v4_3_sealed_selector_windows.pt"
        ),
    )
    parser.add_argument(
        "--model-bundle",
        required=False,
        default=str(
            INTROSPECTION_ROOT
            / "data"
            / "models"
            / "cift_qwen3_0_6b_dp_honey_runtime_v4_1_selector_window_layer_15_v1.pkl"
        ),
    )
    parser.add_argument(
        "--output-json",
        required=False,
        default=str(
            INTROSPECTION_ROOT
            / "data"
            / "reports"
            / "dp_honey_runtime_v4_3_sealed_selector_window_holdout_readout_window_layer_15_v1.json"
        ),
    )
    parser.add_argument(
        "--output-md",
        required=False,
        default=str(
            INTROSPECTION_ROOT
            / "data"
            / "reports"
            / "dp_honey_runtime_v4_3_sealed_selector_window_holdout_readout_window_layer_15_v1_summary.md"
        ),
    )
    parser.add_argument(
        "--evaluation-id",
        required=False,
        default="dp_honey_runtime_v4_3_sealed_selector_window_holdout_readout_window_layer_15_v1",
    )
    parser.add_argument(
        "--holdout-dataset-id",
        required=False,
        default="dp_honey_runtime_v4_3_sealed_selector_windows",
    )
    parser.add_argument(
        "--model-bundle-id",
        required=False,
        default="cift_qwen3_0_6b_dp_honey_runtime_v4_1_selector_window_layer_15_v1",
    )
    add_unseal_flag(parser)
    return parser


def _parse_args(argv: Sequence[str]) -> EvaluateCiftHoldoutCliConfig:
    namespace = _build_parser().parse_args(argv)
    return EvaluateCiftHoldoutCliConfig(
        artifact_path=Path(namespace.artifact),
        model_bundle_path=Path(namespace.model_bundle),
        output_json_path=Path(namespace.output_json),
        output_markdown_path=Path(namespace.output_md),
        evaluation_id=str(namespace.evaluation_id),
        holdout_dataset_id=str(namespace.holdout_dataset_id),
        model_bundle_id=str(namespace.model_bundle_id),
        allow_sealed_holdout=bool(namespace.allow_sealed_holdout),
    )


def _evaluation_config(config: EvaluateCiftHoldoutCliConfig) -> CiftHoldoutEvaluationConfig:
    return CiftHoldoutEvaluationConfig(
        artifact_path=config.artifact_path,
        model_bundle_path=config.model_bundle_path,
        evaluation_id=config.evaluation_id,
        holdout_dataset_id=config.holdout_dataset_id,
        model_bundle_id=config.model_bundle_id,
        allow_sealed_holdout=config.allow_sealed_holdout,
    )


def run_evaluation(config: EvaluateCiftHoldoutCliConfig) -> None:
    assert_unsealed_paths(
        paths=(config.artifact_path, config.output_json_path, config.output_markdown_path),
        allow_sealed_holdout=config.allow_sealed_holdout,
        context="CIFT holdout evaluation",
    )
    report = evaluate_cift_holdout(_evaluation_config(config))
    write_cift_holdout_evaluation_json(path=config.output_json_path, report=report)
    write_cift_holdout_evaluation_markdown(path=config.output_markdown_path, report=report)
    print(f"Wrote CIFT holdout report to {config.output_json_path}")
    print(f"Wrote CIFT holdout summary to {config.output_markdown_path}")
    print(f"Accuracy: {report.accuracy:.4f}")
    print(f"Macro F1: {report.macro_f1:.4f}")
    print(f"Errors: {len(report.errors)} / {report.example_count}")


def main(argv: Sequence[str]) -> None:
    run_evaluation(_parse_args(argv))


if __name__ == "__main__":
    main(tuple(sys.argv[1:]))
