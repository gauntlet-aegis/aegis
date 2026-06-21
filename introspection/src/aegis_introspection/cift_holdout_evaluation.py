from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from numpy.typing import NDArray
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

from aegis_introspection.binary_tasks import (
    BinaryTaskDefinition,
    activation_feature_tensor,
    build_binary_task_dataset,
    default_binary_task_definitions,
)
from aegis_introspection.cift_model_bundle import load_cift_model_bundle, predict_cift_model_bundle
from aegis_introspection.probe import JsonValue, tensor_to_float_matrix
from aegis_introspection.sealed_holdout import load_activation_artifact_with_unseal_policy


class CiftHoldoutEvaluationError(ValueError):
    """Raised when a frozen CIFT bundle cannot be evaluated on a holdout artifact."""


@dataclass(frozen=True)
class CiftHoldoutEvaluationConfig:
    artifact_path: Path
    model_bundle_path: Path
    evaluation_id: str
    holdout_dataset_id: str
    model_bundle_id: str
    allow_sealed_holdout: bool


@dataclass(frozen=True)
class CiftHoldoutPrediction:
    example_id: str
    family: str
    source_label: str
    true_label: str
    predicted_label: str
    positive_probability: float
    is_error: bool


@dataclass(frozen=True)
class CiftHoldoutEvaluationReport:
    schema_version: str
    evaluation_id: str
    evaluation_strategy: str
    holdout_dataset_id: str
    model_bundle_id: str
    source_model_id: str
    source_revision: str
    source_selected_device: str
    task_name: str
    positive_label: str
    activation_feature_key: str
    score_semantics: str
    decision_threshold: float
    label_names: tuple[str, ...]
    example_count: int
    accuracy: float
    macro_f1: float
    confusion_matrix: tuple[tuple[int, ...], ...]
    predictions: tuple[CiftHoldoutPrediction, ...]
    errors: tuple[CiftHoldoutPrediction, ...]


def evaluate_cift_holdout(config: CiftHoldoutEvaluationConfig) -> CiftHoldoutEvaluationReport:
    _validate_config(config)
    artifact = load_activation_artifact_with_unseal_policy(
        path=config.artifact_path,
        allow_sealed_holdout=config.allow_sealed_holdout,
        context="CIFT holdout evaluation",
    )
    bundle = load_cift_model_bundle(config.model_bundle_path)
    metadata = bundle.metadata
    _validate_source_compatibility(
        artifact_model_id=artifact["metadata"]["model_id"],
        artifact_revision=artifact["metadata"]["revision"],
        bundle_model_id=metadata.source_model_id,
        bundle_revision=metadata.source_revision,
    )
    definition = _task_definition(metadata.task_name)
    dataset = build_binary_task_dataset(artifact=artifact, definition=definition)
    feature_tensor = activation_feature_tensor(artifact=artifact, feature_key=metadata.activation_feature_key)
    selected_indices = tuple(artifact["example_ids"].index(example_id) for example_id in dataset.example_ids)
    feature_matrix = tensor_to_float_matrix(feature_tensor)[list(selected_indices)]
    bundle_predictions = predict_cift_model_bundle(bundle=bundle, feature_matrix=feature_matrix)
    true_labels = dataset.target_labels
    predicted_labels = tuple(prediction.predicted_label for prediction in bundle_predictions)
    label_names = metadata.label_names
    _validate_label_coverage(true_labels=true_labels, predicted_labels=predicted_labels, label_names=label_names)
    predictions = _prediction_rows(
        example_ids=dataset.example_ids,
        families=dataset.families,
        source_labels=dataset.source_labels,
        true_labels=true_labels,
        predicted_labels=predicted_labels,
        positive_probabilities=tuple(prediction.positive_probability for prediction in bundle_predictions),
    )
    return CiftHoldoutEvaluationReport(
        schema_version="cift_holdout_evaluation/v1",
        evaluation_id=config.evaluation_id,
        evaluation_strategy="one_shot_frozen_bundle_holdout",
        holdout_dataset_id=config.holdout_dataset_id,
        model_bundle_id=config.model_bundle_id,
        source_model_id=artifact["metadata"]["model_id"],
        source_revision=artifact["metadata"]["revision"],
        source_selected_device=artifact["metadata"]["selected_device"],
        task_name=metadata.task_name,
        positive_label=metadata.positive_label,
        activation_feature_key=metadata.activation_feature_key,
        score_semantics=metadata.score_semantics,
        decision_threshold=metadata.decision_threshold,
        label_names=label_names,
        example_count=len(true_labels),
        accuracy=float(accuracy_score(true_labels, predicted_labels)),
        macro_f1=float(f1_score(true_labels, predicted_labels, labels=list(label_names), average="macro")),
        confusion_matrix=_confusion_matrix(
            true_labels=true_labels, predicted_labels=predicted_labels, label_names=label_names
        ),
        predictions=predictions,
        errors=tuple(prediction for prediction in predictions if prediction.is_error),
    )


def cift_holdout_evaluation_to_json(report: CiftHoldoutEvaluationReport) -> dict[str, JsonValue]:
    return {
        "schema_version": report.schema_version,
        "evaluation_id": report.evaluation_id,
        "evaluation_strategy": report.evaluation_strategy,
        "holdout_dataset_id": report.holdout_dataset_id,
        "model_bundle_id": report.model_bundle_id,
        "source_model_id": report.source_model_id,
        "source_revision": report.source_revision,
        "source_selected_device": report.source_selected_device,
        "task_name": report.task_name,
        "positive_label": report.positive_label,
        "activation_feature_key": report.activation_feature_key,
        "score_semantics": report.score_semantics,
        "decision_threshold": report.decision_threshold,
        "label_names": list(report.label_names),
        "example_count": report.example_count,
        "accuracy": report.accuracy,
        "macro_f1": report.macro_f1,
        "confusion_matrix": [list(row) for row in report.confusion_matrix],
        "predictions": [_prediction_to_json(prediction) for prediction in report.predictions],
        "errors": [_prediction_to_json(prediction) for prediction in report.errors],
    }


def write_cift_holdout_evaluation_json(path: Path, report: CiftHoldoutEvaluationReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(cift_holdout_evaluation_to_json(report), file, indent=2)
        file.write("\n")


def render_cift_holdout_evaluation_markdown(report: CiftHoldoutEvaluationReport) -> str:
    lines = [
        "# CIFT One-Shot Frozen Bundle Holdout",
        "",
        "## Source",
        "",
        f"- Evaluation ID: `{report.evaluation_id}`",
        f"- Strategy: `{report.evaluation_strategy}`",
        f"- Holdout dataset: `{report.holdout_dataset_id}`",
        f"- Model bundle: `{report.model_bundle_id}`",
        f"- Model: `{report.source_model_id}`",
        f"- Revision: `{report.source_revision}`",
        f"- Extraction device: `{report.source_selected_device}`",
        f"- Task: `{report.task_name}`",
        f"- Positive label: `{report.positive_label}`",
        f"- Activation feature: `{report.activation_feature_key}`",
        f"- Score semantics: `{report.score_semantics}`",
        f"- Decision threshold: `{report.decision_threshold:.4f}`",
        "",
        "## Metrics",
        "",
        "| Examples | Accuracy | Macro F1 | Errors |",
        "|---:|---:|---:|---:|",
        f"| {report.example_count} | {report.accuracy:.4f} | {report.macro_f1:.4f} | {len(report.errors)} |",
        "",
        "## Confusion Matrix",
        "",
        "Rows are true labels; columns are predicted labels.",
        "",
        _render_confusion_matrix(report),
        "",
        "## Errors",
        "",
    ]
    if len(report.errors) == 0:
        lines.append("No holdout errors.")
    else:
        lines.extend(
            [
                "| Example | Family | True | Predicted | Positive Probability |",
                "|---|---|---|---|---:|",
            ]
        )
        for error in report.errors:
            lines.append(
                f"| `{error.example_id}` | `{error.family}` | `{error.true_label}` | "
                f"`{error.predicted_label}` | {error.positive_probability:.4f} |"
            )
    return "\n".join(lines) + "\n"


def write_cift_holdout_evaluation_markdown(path: Path, report: CiftHoldoutEvaluationReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_cift_holdout_evaluation_markdown(report), encoding="utf-8")


def _validate_config(config: CiftHoldoutEvaluationConfig) -> None:
    if config.evaluation_id == "":
        raise CiftHoldoutEvaluationError("evaluation_id must not be empty.")
    if config.holdout_dataset_id == "":
        raise CiftHoldoutEvaluationError("holdout_dataset_id must not be empty.")
    if config.model_bundle_id == "":
        raise CiftHoldoutEvaluationError("model_bundle_id must not be empty.")


def _validate_source_compatibility(
    artifact_model_id: str,
    artifact_revision: str,
    bundle_model_id: str,
    bundle_revision: str,
) -> None:
    if artifact_model_id != bundle_model_id:
        raise CiftHoldoutEvaluationError(
            f"Holdout artifact model_id '{artifact_model_id}' does not match bundle model_id '{bundle_model_id}'."
        )
    if artifact_revision != bundle_revision:
        raise CiftHoldoutEvaluationError(
            f"Holdout artifact revision '{artifact_revision}' does not match bundle revision '{bundle_revision}'."
        )


def _task_definition(task_name: str) -> BinaryTaskDefinition:
    matches = tuple(definition for definition in default_binary_task_definitions() if definition.name == task_name)
    if len(matches) != 1:
        raise CiftHoldoutEvaluationError(f"Unknown binary task '{task_name}'.")
    return matches[0]


def _validate_label_coverage(
    true_labels: tuple[str, ...],
    predicted_labels: tuple[str, ...],
    label_names: tuple[str, ...],
) -> None:
    expected_labels = set(label_names)
    observed_labels = set(true_labels).union(predicted_labels)
    if observed_labels != expected_labels:
        raise CiftHoldoutEvaluationError(
            f"Holdout labels {sorted(observed_labels)} do not match bundle labels {sorted(expected_labels)}."
        )


def _prediction_rows(
    example_ids: tuple[str, ...],
    families: tuple[str, ...],
    source_labels: tuple[str, ...],
    true_labels: tuple[str, ...],
    predicted_labels: tuple[str, ...],
    positive_probabilities: tuple[float, ...],
) -> tuple[CiftHoldoutPrediction, ...]:
    rows: list[CiftHoldoutPrediction] = []
    for example_id, family, source_label, true_label, predicted_label, positive_probability in zip(
        example_ids,
        families,
        source_labels,
        true_labels,
        predicted_labels,
        positive_probabilities,
        strict=True,
    ):
        rows.append(
            CiftHoldoutPrediction(
                example_id=example_id,
                family=family,
                source_label=source_label,
                true_label=true_label,
                predicted_label=predicted_label,
                positive_probability=positive_probability,
                is_error=predicted_label != true_label,
            )
        )
    return tuple(rows)


def _confusion_matrix(
    true_labels: tuple[str, ...],
    predicted_labels: tuple[str, ...],
    label_names: tuple[str, ...],
) -> tuple[tuple[int, ...], ...]:
    matrix: NDArray[np.int64] = confusion_matrix(true_labels, predicted_labels, labels=list(label_names))
    return tuple(tuple(int(value) for value in row) for row in matrix)


def _prediction_to_json(prediction: CiftHoldoutPrediction) -> dict[str, JsonValue]:
    return {
        "example_id": prediction.example_id,
        "family": prediction.family,
        "source_label": prediction.source_label,
        "true_label": prediction.true_label,
        "predicted_label": prediction.predicted_label,
        "positive_probability": prediction.positive_probability,
        "is_error": prediction.is_error,
    }


def _render_confusion_matrix(report: CiftHoldoutEvaluationReport) -> str:
    header = "| True \\ Predicted | " + " | ".join(f"`{label}`" for label in report.label_names) + " |"
    separator = "|---|" + "|".join("---:" for _ in report.label_names) + "|"
    rows = [header, separator]
    for label, row in zip(report.label_names, report.confusion_matrix, strict=True):
        rows.append(f"| `{label}` | " + " | ".join(str(value) for value in row) + " |")
    return "\n".join(rows)
