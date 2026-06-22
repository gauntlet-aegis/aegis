#!/usr/bin/env python
"""Launch the Aegis dashboard.

Runs the Streamlit app (``dashboard/app.py``) via the project venv's ``streamlit`` binary. The
dashboard drives the Aegis SDK / eval harness in-process, so it needs no network, no live LLM, and
no trace artifacts.

Usage (from the repo root, with the venv's interpreter):

    .venv/bin/python scripts/run_dashboard.py

Equivalent direct invocation:

    .venv/bin/streamlit run dashboard/app.py

Any extra CLI args are forwarded to ``streamlit run`` (e.g. ``--server.port 8765``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
APP = REPO_ROOT / "dashboard" / "app.py"


def main() -> None:
    """Exec ``streamlit run dashboard/app.py`` from the venv hosting this interpreter."""
    streamlit = Path(sys.executable).with_name("streamlit")
    binary = str(streamlit) if streamlit.exists() else "streamlit"
    args = [binary, "run", str(APP), *sys.argv[1:]]
    os.execvp(binary, args)


if __name__ == "__main__":
    main()
