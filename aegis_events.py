from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
from pathlib import Path
from threading import Lock
from time import perf_counter
from typing import Any

from aegis_tap import Context


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@dataclass
class Observation:
    id: int
    created_at: str
    request_payload: dict[str, Any]
    raw_context: Context
    seen_context: Context
    upstream_url: str
    started_at: float = field(default_factory=perf_counter)
    upstream_status: int | None = None
    upstream_content_type: str = ""
    response_bytes: int = 0
    error: str = ""
    latency_ms_value: int | None = None
    persist_path: Path | None = None

    @property
    def latency_ms(self) -> int | None:
        return self.latency_ms_value

    def summary(self) -> dict[str, Any]:
        messages = _messages(self.request_payload)
        return {
            "id": self.id,
            "created_at": self.created_at,
            "model": str(self.request_payload.get("model") or ""),
            "message_count": len(messages),
            "roles": [str(message.get("role") or "unknown") for message in messages],
            "preview": _last_user_message(messages),
            "upstream_status": self.upstream_status,
            "latency_ms": self.latency_ms,
            "response_bytes": self.response_bytes,
            "error": self.error,
        }

    def detail(self) -> dict[str, Any]:
        data = self.summary()
        data.update({
            "request": self.request_payload,
            "messages": _messages(self.request_payload),
            "request_params": {
                key: value
                for key, value in self.request_payload.items()
                if key != "messages"
            },
            "upstream_url": self.upstream_url,
            "upstream_content_type": self.upstream_content_type,
        })
        return data


class ObservationStore:
    def __init__(self, limit: int = 100, event_dir: str | Path | None = None) -> None:
        self._events: deque[Observation] = deque(maxlen=limit)
        self._next_id = 1
        self._event_dir = Path(event_dir) if event_dir else None
        self._lock = Lock()
        if self._event_dir is not None:
            self._load()

    def start(self, payload: dict[str, Any], raw: Context, seen: Context, upstream_url: str) -> Observation:
        with self._lock:
            event = Observation(
                id=self._next_id,
                created_at=_now(),
                request_payload=payload,
                raw_context=raw,
                seen_context=seen,
                upstream_url=upstream_url,
            )
            event.persist_path = self._path_for(event)
            self._next_id += 1
            self._events.append(event)
            return event

    def finish(
        self,
        event: Observation,
        *,
        status: int,
        content_type: str = "",
        response_bytes: int = 0,
        error: str = "",
    ) -> None:
        with self._lock:
            event.upstream_status = status
            event.upstream_content_type = content_type
            event.response_bytes = response_bytes
            event.error = error
            event.latency_ms_value = round((perf_counter() - event.started_at) * 1000)
            self._persist(event)

    def summaries(self) -> list[dict[str, Any]]:
        with self._lock:
            return [event.summary() for event in reversed(self._events)]

    def detail(self, event_id: int) -> dict[str, Any] | None:
        with self._lock:
            for event in self._events:
                if event.id == event_id:
                    return event.detail()
        return None

    def _load(self) -> None:
        if self._event_dir is None or not self._event_dir.exists():
            return

        loaded: list[Observation] = []
        max_id = 0
        for path in sorted(self._event_dir.glob("*.json")):
            event = self._load_file(path)
            if event is None:
                continue
            loaded.append(event)
            max_id = max(max_id, event.id)

        maxlen = self._events.maxlen
        for event in loaded[-maxlen:] if maxlen is not None else loaded:
            self._events.append(event)
        self._next_id = max_id + 1

    def _load_file(self, path: Path) -> Observation | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            event_id = int(data["id"])
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

        request = data.get("request")
        if not isinstance(request, dict):
            return None

        empty_context = Context(system_prompt="", credentials={}, untrusted_content="", user_query="")
        event = Observation(
            id=event_id,
            created_at=str(data.get("created_at") or ""),
            request_payload=request,
            raw_context=empty_context,
            seen_context=empty_context,
            upstream_url=str(data.get("upstream_url") or ""),
            upstream_status=_optional_int(data.get("upstream_status")),
            upstream_content_type=str(data.get("upstream_content_type") or ""),
            response_bytes=_optional_int(data.get("response_bytes")) or 0,
            error=str(data.get("error") or ""),
            latency_ms_value=_optional_int(data.get("latency_ms")),
            persist_path=path,
        )
        return event

    def _persist(self, event: Observation) -> None:
        if event.persist_path is None:
            return

        try:
            event.persist_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = event.persist_path.with_suffix(".json.tmp")
            tmp_path.write_text(
                json.dumps(event.detail(), indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            tmp_path.replace(event.persist_path)
        except OSError:
            return

    def _path_for(self, event: Observation) -> Path | None:
        if self._event_dir is None:
            return None
        safe_created_at = event.created_at.replace("+00:00", "Z").replace(":", "-")
        return self._event_dir / f"{safe_created_at}-{event.id:06d}.json"


def _messages(payload: dict[str, Any]) -> list[dict[str, Any]]:
    messages = payload.get("messages")
    return [message for message in messages if isinstance(message, dict)] if isinstance(messages, list) else []


def _last_user_message(messages: list[dict[str, Any]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            return _content_text(message.get("content"))
    return ""


def _content_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    return str(content)


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
