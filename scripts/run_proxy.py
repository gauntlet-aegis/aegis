"""Launch the Sentinel proxy + dashboard.

Usage:
  PYTORCH_ENABLE_MPS_FALLBACK=1 .venv/bin/python scripts/run_proxy.py
  SENTINEL_MODE=blackbox .venv/bin/python scripts/run_proxy.py --config configs/blackbox.yaml
"""

from __future__ import annotations

import argparse

import uvicorn

from sentinel.config import load_settings
from sentinel.proxy.app import create_app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    args = parser.parse_args()

    settings = load_settings(args.config)
    app = create_app(settings)
    print(f"Sentinel [{settings.mode}] on http://{settings.host}:{settings.port}  (dashboard at /)")
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
