from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
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
    def __init__(self, limit: int = 100) -> None:
        self._events: deque[Observation] = deque(maxlen=limit)
        self._next_id = 1
        self._lock = Lock()

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

    def summaries(self) -> list[dict[str, Any]]:
        with self._lock:
            return [event.summary() for event in reversed(self._events)]

    def detail(self, event_id: int) -> dict[str, Any] | None:
        with self._lock:
            for event in self._events:
                if event.id == event_id:
                    return event.detail()
        return None


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
