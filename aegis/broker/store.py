"""FakeSecretStore — a local, demo-only secret store (PDF section 6.5).

This is NOT a production secret manager. It exists so the demo, tests, and eval can exercise the
broker's resolve/leak-detection paths with realistic-looking but fake credentials. It backs onto a
seed dict, an optional JSON file, and/or environment variables of the form
``AEGIS_SECRET_<SERVICE>_<NAME>``. Never load real production secrets into it.

Secrets are keyed by ``"<service>/<name>"`` to mirror the ``secret://<service>/<name>`` handle.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


def _key(service: str, name: str) -> str:
    return f"{service}/{name}"


class FakeSecretStore:
    """An in-memory map of fake credentials, for tests and demos only.

    Args:
        seed: optional ``{"service/name": value}`` dict (also accepts already-joined keys).
        json_path: optional path to a JSON file holding a flat ``{"service/name": value}`` map.
        env_prefix: if set, environment variables named ``<env_prefix><SERVICE>_<NAME>`` are
            loaded; the service/name are lower-cased and the split is on the LAST underscore so
            multi-word services round-trip predictably (e.g. ``AEGIS_SECRET_GITHUB_TOKEN`` ->
            ``github/token``).
    """

    def __init__(
        self,
        seed: dict[str, str] | None = None,
        *,
        json_path: str | Path | None = None,
        env_prefix: str | None = None,
    ) -> None:
        self._secrets: dict[str, str] = {}
        if seed:
            self._secrets.update({k: str(v) for k, v in seed.items()})
        if json_path:
            self._load_json(json_path)
        if env_prefix:
            self._load_env(env_prefix)

    def _load_json(self, json_path: str | Path) -> None:
        path = Path(json_path)
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            self._secrets.update({str(k): str(v) for k, v in data.items()})

    def _load_env(self, env_prefix: str) -> None:
        for env_name, value in os.environ.items():
            if not env_name.startswith(env_prefix):
                continue
            tail = env_name[len(env_prefix):]
            if "_" not in tail:
                continue
            service, name = tail.rsplit("_", 1)
            self._secrets[_key(service.lower(), name.lower())] = value

    def get(self, service: str, name: str) -> str | None:
        """Return the real fake-secret for ``service``/``name``, or ``None`` if unknown."""
        return self._secrets.get(_key(service, name))

    def all_values(self) -> list[str]:
        """Every secret value held, for redaction / leak-detection. Skips empty values."""
        return [v for v in self._secrets.values() if v]
