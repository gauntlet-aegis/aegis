"""Runtime configuration for the local Aegis proxy."""

import os


UPSTREAM_URL = os.getenv("AEGIS_UPSTREAM_URL", "http://localhost:8080").rstrip("/")
AEGIS_PORT = int(os.getenv("AEGIS_PORT", "9000"))
