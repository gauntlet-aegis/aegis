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
    UnknownFormatError,
)
from .formats import REGISTRY_VERSION, get_format, list_format_slugs, list_formats
from .grammar import FormatSpec, Literal, Variable
from .model_io import SCHEMA_VERSION, load_model, model_to_dict, save_model
from .realism import REPORT_MAX, compute_report

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # registry
    "REGISTRY_VERSION",
    "list_formats",
    "list_format_slugs",
    "get_format",
    # grammar
    "FormatSpec",
    "Literal",
    "Variable",
    # generation
    "generate_honeytokens",
    "build_model",
    "train_model",
    "BigramHoneytokenModel",
    # artifact IO
    "SCHEMA_VERSION",
    "save_model",
    "load_model",
    "model_to_dict",
    # realism
    "compute_report",
    "REPORT_MAX",
    # errors
    "DPHoneyError",
    "UnknownFormatError",
    "InvalidPrivacyParameter",
    "EmptyCorpusError",
    "FormatRepairError",
    "CountLimitError",
    "ModelArtifactDecodeError",
    "ModelSchemaError",
    "FormatSpecMismatchError",
    "ModelArtifactExistsError",
]
