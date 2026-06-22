"""DP-HONEY: synthetic, non-functional honeytoken generator.

.. warning::

   Every value this package emits is **synthetic** and **shape-only**. Outputs
   are format-compatible with real secrets (they "look like" AWS keys, JWTs,
   GitHub tokens, and so on) but are **never** provider-valid, signed,
   decryptable, authenticated, or usable credentials. Do not treat any output
   as a real secret, and never train this package on real credentials.

Public API (expanded as the package is built):

* Registry: :func:`list_formats`, :func:`list_format_slugs`, :func:`get_format`
* Grammar:  :class:`FormatSpec`, :class:`Literal`, :class:`Variable`
* Errors:   :class:`DPHoneyError` and its subclasses
"""

from __future__ import annotations

from .bigram import (
    BigramHoneytokenModel,
    build_model,
    generate_honeytokens,
    train_model,
)
from .conformal import ConformalThreshold, calibrate_fuzzy_threshold, is_fuzzy_outlier
from .errors import (
    CountLimitError,
    DPHoneyError,
    EmptyCorpusError,
    FormatRepairError,
    FormatSpecMismatchError,
    InvalidPrivacyParameter,
    ModelArtifactDecodeError,
    ModelArtifactExistsError,
    ModelSchemaError,
    PlantedScanConfigurationError,
    UnknownFormatError,
)
from .formats import REGISTRY_VERSION, get_format, list_format_slugs, list_formats
from .grammar import FormatSpec, Literal, Variable
from .model_io import SCHEMA_VERSION, load_model, model_to_dict, save_model
from .realism import REPORT_MAX, compute_report
from .scanner import PlantedHoneytoken, PlantedMatch, PlantedScanResult, planted_fuzzy_similarity, scan_planted_values

__version__ = "0.1.0"

__all__ = [
    "REGISTRY_VERSION",
    "REPORT_MAX",
    "SCHEMA_VERSION",
    "BigramHoneytokenModel",
    "ConformalThreshold",
    "CountLimitError",
    "DPHoneyError",
    "EmptyCorpusError",
    "FormatRepairError",
    "FormatSpec",
    "FormatSpecMismatchError",
    "InvalidPrivacyParameter",
    "Literal",
    "ModelArtifactDecodeError",
    "ModelArtifactExistsError",
    "ModelSchemaError",
    "PlantedHoneytoken",
    "PlantedMatch",
    "PlantedScanConfigurationError",
    "PlantedScanResult",
    "UnknownFormatError",
    "Variable",
    "__version__",
    "build_model",
    "calibrate_fuzzy_threshold",
    "compute_report",
    "generate_honeytokens",
    "get_format",
    "is_fuzzy_outlier",
    "list_format_slugs",
    "list_formats",
    "load_model",
    "model_to_dict",
    "planted_fuzzy_similarity",
    "save_model",
    "scan_planted_values",
    "train_model",
]
