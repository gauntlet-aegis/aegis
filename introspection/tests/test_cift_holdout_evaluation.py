import tempfile
import unittest
from pathlib import Path

import torch
from aegis_introspection.artifacts import ActivationArtifact
from aegis_introspection.cift_holdout_evaluation import (
    CiftHoldoutEvaluationConfig,
    evaluate_cift_holdout,
    render_cift_holdout_evaluation_markdown,
    write_cift_holdout_evaluation_json,
)
from aegis_introspection.cift_model_training import CiftModelTrainingConfig, train_cift_model_bundle
from aegis_introspection.sealed_holdout import SealedHoldoutError
from introspection.scripts.evaluate_cift_holdout import _parse_args


def _training_artifact() -> ActivationArtifact:
    return {
        "metadata": {
            "model_id": "Qwen/Qwen3-0.6B",
            "revision": "main",
            "selected_device": "cpu",
            "layer_indices": (15,),
            "pooling_methods": ("readout_window",),
        },
        "example_ids": ("safe-train-1", "safe-train-2", "exfil-train-1", "exfil-train-2"),
        "labels": ("secret_present_safe", "secret_present_safe", "exfiltration_intent", "exfiltration_intent"),
        "families": ("family-a", "family-b", "family-a", "family-b"),
        "texts": ("safe one", "safe two", "exfil one", "exfil two"),
        "tags": (("train",), ("train",), ("train",), ("train",)),
        "features": {
            "readout_window_layer_15": torch.tensor(
                (
                    (0.0, 0.0),
                    (0.2, 0.1),
                    (3.0, 3.0),
                    (3.2, 3.1),
                ),
                dtype=torch.float32,
            )
        },
    }


def _sealed_holdout_artifact() -> ActivationArtifact:
    return {
        "metadata": {
            "model_id": "Qwen/Qwen3-0.6B",
            "revision": "main",
            "selected_device": "cpu",
            "layer_indices": (15,),
            "pooling_methods": ("readout_window",),
        },
        "example_ids": ("safe-holdout-1", "safe-holdout-2", "exfil-holdout-1", "exfil-holdout-2"),
        "labels": ("secret_present_safe", "secret_present_safe", "exfiltration_intent", "exfiltration_intent"),
        "families": ("holdout-a", "holdout-b", "holdout-a", "holdout-b"),
        "texts": ("safe holdout one", "safe holdout two", "exfil holdout one", "exfil holdout two"),
        "tags": (
            ("runtime_dp_honey", "sealed_holdout"),
            ("runtime_dp_honey", "sealed_holdout"),
            ("runtime_dp_honey", "sealed_holdout"),
            ("runtime_dp_honey", "sealed_holdout"),
        ),
        "features": {
            "readout_window_layer_15": torch.tensor(
                (
                    (0.1, 0.1),
                    (2.9, 2.9),
                    (3.1, 3.1),
                    (0.0, 0.2),
                ),
                dtype=torch.float32,
            )
        },
    }


class CiftHoldoutEvaluationTest(unittest.TestCase):
    def test_cli_parse_args_requires_explicit_unseal_for_sealed_holdout(self) -> None:
        config = _parse_args(
            (
                "--artifact",
                "data/activations/runtime_v4_3_sealed.pt",
                "--model-bundle",
                "data/models/runtime_v4_1.pkl",
                "--output-json",
                "data/reports/holdout.json",
                "--output-md",
                "data/reports/holdout.md",
                "--evaluation-id",
                "runtime_v4_3_one_shot",
                "--holdout-dataset-id",
                "dp_honey_runtime_v4_3_sealed_selector_windows",
                "--model-bundle-id",
                "cift_runtime_v4_1",
                "--allow-sealed-holdout",
            )
        )

        self.assertTrue(config.allow_sealed_holdout)
        self.assertEqual(Path("data/activations/runtime_v4_3_sealed.pt"), config.artifact_path)
        self.assertEqual(Path("data/reports/holdout.json"), config.output_json_path)

    def test_evaluate_cift_holdout_scores_frozen_bundle_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            training_artifact_path = root / "training.pt"
            holdout_artifact_path = root / "runtime_v4_3_sealed.pt"
            bundle_path = root / "bundle.pkl"
            output_json_path = root / "holdout.json"
            torch.save(_training_artifact(), training_artifact_path)
            torch.save(_sealed_holdout_artifact(), holdout_artifact_path)
            train_cift_model_bundle(
                CiftModelTrainingConfig(
                    artifact_path=training_artifact_path,
                    output_bundle_path=bundle_path,
                    training_dataset_id="runtime_v4_1_training",
                    task_name="safe_secret_vs_exfiltration",
                    positive_label="exfiltration_intent",
                    activation_feature_key="readout_window_layer_15",
                    decision_threshold=0.5,
                    random_seed=42,
                    max_iter=1000,
                    regularization_c=1.0,
                    evaluation_report_ids=("training_report",),
                    score_semantics="full_train_classifier_probability",
                    candidate_status="offline_research_candidate",
                    created_at="2026-06-21T00:00:00Z",
                    allow_sealed_holdout=False,
                )
            )

            report = evaluate_cift_holdout(
                CiftHoldoutEvaluationConfig(
                    artifact_path=holdout_artifact_path,
                    model_bundle_path=bundle_path,
                    evaluation_id="runtime_v4_3_one_shot",
                    holdout_dataset_id="dp_honey_runtime_v4_3_sealed_selector_windows",
                    model_bundle_id="cift_runtime_v4_1_bundle",
                    allow_sealed_holdout=True,
                )
            )
            write_cift_holdout_evaluation_json(path=output_json_path, report=report)
            rendered = render_cift_holdout_evaluation_markdown(report)
            output_json_text = output_json_path.read_text(encoding="utf-8")

            self.assertEqual("runtime_v4_3_one_shot", report.evaluation_id)
            self.assertEqual("one_shot_frozen_bundle_holdout", report.evaluation_strategy)
            self.assertEqual(4, report.example_count)
            self.assertEqual(0.5, report.accuracy)
            self.assertEqual(0.5, report.macro_f1)
            self.assertEqual(2, len(report.errors))
            self.assertEqual(("exfiltration_intent", "secret_present_safe"), report.label_names)
            self.assertEqual(((1, 1), (1, 1)), report.confusion_matrix)
            self.assertIn("runtime_v4_3_one_shot", output_json_text)
            self.assertIn("One-Shot Frozen Bundle Holdout", rendered)

    def test_evaluate_cift_holdout_rejects_sealed_artifact_without_unseal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            training_artifact_path = root / "training.pt"
            holdout_artifact_path = root / "renamed.pt"
            bundle_path = root / "bundle.pkl"
            torch.save(_training_artifact(), training_artifact_path)
            torch.save(_sealed_holdout_artifact(), holdout_artifact_path)
            train_cift_model_bundle(
                CiftModelTrainingConfig(
                    artifact_path=training_artifact_path,
                    output_bundle_path=bundle_path,
                    training_dataset_id="runtime_v4_1_training",
                    task_name="safe_secret_vs_exfiltration",
                    positive_label="exfiltration_intent",
                    activation_feature_key="readout_window_layer_15",
                    decision_threshold=0.5,
                    random_seed=42,
                    max_iter=1000,
                    regularization_c=1.0,
                    evaluation_report_ids=("training_report",),
                    score_semantics="full_train_classifier_probability",
                    candidate_status="offline_research_candidate",
                    created_at="2026-06-21T00:00:00Z",
                    allow_sealed_holdout=False,
                )
            )

            with self.assertRaises(SealedHoldoutError):
                evaluate_cift_holdout(
                    CiftHoldoutEvaluationConfig(
                        artifact_path=holdout_artifact_path,
                        model_bundle_path=bundle_path,
                        evaluation_id="runtime_v4_3_one_shot",
                        holdout_dataset_id="dp_honey_runtime_v4_3_sealed_selector_windows",
                        model_bundle_id="cift_runtime_v4_1_bundle",
                        allow_sealed_holdout=False,
                    )
                )


if __name__ == "__main__":
    unittest.main()
