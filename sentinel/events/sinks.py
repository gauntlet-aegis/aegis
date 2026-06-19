"""Durable sinks for the event stream. JSONL is the demo-day replay/backup insurance."""

from __future__ import annotations

import json
from pathlib import Path


class JSONLSink:
    """Append every TurnEvent (as a dict) to a JSONL file."""

    def __init__(self, event_dir: str) -> None:
        self.dir = Path(event_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "events.jsonl"

    def __call__(self, event: dict) -> None:
        with self.path.open("a") as f:
            f.write(json.dumps(event) + "\n")

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]
