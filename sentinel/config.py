"""Configuration: a Pydantic settings object loaded from a YAML file with env overrides.

One config drives both white-box and black-box mode (PRD §4.1 — a toggle, not a second system).
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from sentinel.events.schema import Mode

REPO_ROOT = Path(__file__).resolve().parent.parent


class BlackBoxConfig(BaseModel):
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    api_key_env: str = "OPENAI_API_KEY"  # name of the env var holding the key


class CIFTConfig(BaseModel):
    stats_path: str = "data/cift/stats.pt"
    probe_path: str = "data/cift/probe.pt"
    threshold: float = 0.5


class DPHoneyConfig(BaseModel):
    models_path: str = "data/honey/models.pkl"
    threshold_path: str = "data/honey/threshold.json"
    epsilon: float = 1.0
    alpha: float = 0.05  # conformal miscoverage target


class NimbusConfig(BaseModel):
    critic_path: str = "data/nimbus/critic.pt"
    budget_bits: float = 16.0
    n_neg: int = 63


class Settings(BaseModel):
    mode: Mode = Mode.WHITEBOX
    model_id: str = "Qwen/Qwen2.5-1.5B-Instruct"
    device: str = "mps"
    max_new_tokens: int = 256
    host: str = "127.0.0.1"
    port: int = 8000
    event_dir: str = ".aegis/events"

    blackbox: BlackBoxConfig = Field(default_factory=BlackBoxConfig)
    cift: CIFTConfig = Field(default_factory=CIFTConfig)
    dp_honey: DPHoneyConfig = Field(default_factory=DPHoneyConfig)
    nimbus: NimbusConfig = Field(default_factory=NimbusConfig)

    def api_key(self) -> str | None:
        return os.environ.get(self.blackbox.api_key_env)


def load_settings(config_path: str | None = None) -> Settings:
    """Load settings from YAML (default: configs/default.yaml), then apply env overrides."""
    path = Path(config_path) if config_path else REPO_ROOT / "configs" / "default.yaml"
    data: dict = {}
    if path.exists():
        data = yaml.safe_load(path.read_text()) or {}

    # Env overrides for the few things you flip at run time.
    if (m := os.environ.get("SENTINEL_MODE")):
        data["mode"] = m
    if (p := os.environ.get("SENTINEL_PORT")):
        data["port"] = int(p)
    if (d := os.environ.get("SENTINEL_DEVICE")):
        data["device"] = d

    return Settings.model_validate(data)
