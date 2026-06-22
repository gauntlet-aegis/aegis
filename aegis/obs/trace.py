"""Trace sink + log hygiene (PDF non-functional reqs: log hygiene, trace fallback).

Every evaluated turn appends one JSON line here for audit and dashboard replay. Raw secrets are
redacted before they touch disk unless the run is explicitly in local-test mode. This is the
local fallback that lets the demo and report run without any hosted observability (Braintrust).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel

# Conservative credential shapes used only for log redaction (the secret-pattern *detector* is
# richer; this is a last-line hygiene net so a stray secret never lands in a trace file).
_REDACT_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                       # AWS access key id
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                    # OpenAI-style key
    re.compile(r"sk_live_[A-Za-z0-9]{16,}"),               # Stripe live key
    re.compile(r"ghp_[A-Za-z0-9]{36}"),                    # GitHub PAT
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{16,}"),       # OAuth bearer
]

REDACTED = "[REDACTED]"


def redact(text: str, *, known_secrets: Iterable[str] = ()) -> str:
    """Replace known secret values and credential-shaped substrings with ``[REDACTED]``."""
    if not text:
        return text
    for secret in known_secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    for pat in _REDACT_PATTERNS:
        text = pat.sub(REDACTED, text)
    return text


def contains_secret_shape(text: str) -> bool:
    """True if any credential-shaped substring survives in ``text`` (used by the broker guard)."""
    return any(pat.search(text or "") for pat in _REDACT_PATTERNS)


class TraceSink:
    """Append-only JSONL writer. One line per event/decision record.

    With ``local_test_mode=False`` (the default), string fields are passed through
    :func:`redact` before writing. The dashboard and ``run_demo``/``run_eval`` read these files.
    """

    def __init__(self, path: str | Path, *, local_test_mode: bool = False,
                 known_secrets: Iterable[str] = ()) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.local_test_mode = local_test_mode
        self.known_secrets = list(known_secrets)

    def write(self, record: BaseModel | dict) -> None:
        data = record.model_dump(mode="json") if isinstance(record, BaseModel) else dict(record)
        if not self.local_test_mode:
            data = _redact_obj(data, self.known_secrets)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(data, default=str) + "\n")

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]


def _redact_obj(obj, known_secrets):
    if isinstance(obj, str):
        return redact(obj, known_secrets=known_secrets)
    if isinstance(obj, dict):
        return {k: _redact_obj(v, known_secrets) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v, known_secrets) for v in obj]
    return obj
