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
    endpoint: str = "/v1/chat/completions"
    started_at: float = field(default_factory=perf_counter)
    upstream_status: int | None = None
    upstream_content_type: str = ""
    response_bytes: int = 0
    response_payload: Any = None
    response_text: str = ""
    error: str = ""
    latency_ms_value: int | None = None
    persist_path: Path | None = None

    @property
    def latency_ms(self) -> int | None:
        return self.latency_ms_value

    def summary(self) -> dict[str, Any]:
        messages = _messages(self.request_payload)
        input_items = _response_input_items(self.request_payload)
        item_count = len(messages) if messages else len(input_items)
        return {
            "id": self.id,
            "created_at": self.created_at,
            "endpoint": self.endpoint,
            "request_kind": _request_kind(self.endpoint),
            "model": str(self.request_payload.get("model") or ""),
            "message_count": len(messages),
            "item_count": item_count,
            "roles": _request_roles(messages, input_items),
            "preview": _request_preview(self.request_payload, messages, input_items),
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
            "instructions": self.request_payload.get("instructions"),
            "input": self.request_payload.get("input"),
            "input_items": _response_input_items(self.request_payload),
            "request_params": {
                key: value
                for key, value in self.request_payload.items()
                if key not in {"messages", "instructions", "input"}
            },
            "upstream_url": self.upstream_url,
            "upstream_content_type": self.upstream_content_type,
            "assistant_messages": _assistant_messages(self.response_payload, self.response_text),
            "response_text": self.response_text,
            "response": self.response_payload,
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

    def start(
        self,
        payload: dict[str, Any],
        raw: Context,
        seen: Context,
        upstream_url: str,
        endpoint: str = "/v1/chat/completions",
    ) -> Observation:
        with self._lock:
            event = Observation(
                id=self._next_id,
                created_at=_now(),
                request_payload=payload,
                raw_context=raw,
                seen_context=seen,
                upstream_url=upstream_url,
                endpoint=endpoint,
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
        response_content: bytes = b"",
        error: str = "",
    ) -> None:
        with self._lock:
            event.upstream_status = status
            event.upstream_content_type = content_type
            event.response_bytes = response_bytes
            event.response_payload, event.response_text = _parse_response(response_content, content_type)
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
            endpoint=str(data.get("endpoint") or _infer_endpoint(request)),
            upstream_status=_optional_int(data.get("upstream_status")),
            upstream_content_type=str(data.get("upstream_content_type") or ""),
            response_bytes=_optional_int(data.get("response_bytes")) or 0,
            response_payload=data.get("response"),
            response_text=str(data.get("response_text") or ""),
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


def _response_input_items(payload: dict[str, Any]) -> list[Any]:
    input_value = payload.get("input")
    if isinstance(input_value, list):
        return input_value
    if input_value is None:
        return []
    return [input_value]


def _request_roles(messages: list[dict[str, Any]], input_items: list[Any]) -> list[str]:
    if messages:
        return [str(message.get("role") or "unknown") for message in messages]
    roles: list[str] = []
    for item in input_items:
        if isinstance(item, dict):
            roles.append(str(item.get("role") or item.get("type") or "input"))
        else:
            roles.append("input")
    return roles


def _request_preview(payload: dict[str, Any], messages: list[dict[str, Any]], input_items: list[Any]) -> str:
    message_preview = _last_user_message(messages)
    if message_preview:
        return message_preview

    for item in reversed(input_items):
        preview = _input_item_text(item)
        if preview:
            return preview
    return _content_text(payload.get("instructions"))


def _last_user_message(messages: list[dict[str, Any]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            return _content_text(message.get("content"))
    return ""


def _input_item_text(item: Any) -> str:
    if isinstance(item, dict):
        if "content" in item:
            return _content_text(item.get("content"))
        if "text" in item:
            return _content_text(item.get("text"))
        return _content_text(item)
    return _content_text(item)


def _content_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(part for part in (_content_text(item) for item in content) if part)
    if isinstance(content, dict):
        text = content.get("text")
        if isinstance(text, str):
            return text
        if "content" in content:
            return _content_text(content.get("content"))
    try:
        return json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    except TypeError:
        return str(content)


def _parse_response(content: bytes, content_type: str) -> tuple[Any, str]:
    if not content:
        return None, ""

    text = content.decode("utf-8", errors="replace")
    if "text/event-stream" in content_type.lower() or text.lstrip().startswith("data:"):
        chunks = _parse_sse_chunks(text)
        return {"stream": True, "chunks": chunks} if chunks else None, _stream_text(chunks) or text

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None, text
    return payload, _completion_text(payload)


def _parse_sse_chunks(text: str) -> list[Any]:
    chunks: list[Any] = []
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        data = line.removeprefix("data:").strip()
        if not data or data == "[DONE]":
            continue
        try:
            chunks.append(json.loads(data))
        except json.JSONDecodeError:
            chunks.append(data)
    return chunks


def _stream_text(chunks: list[Any]) -> str:
    parts: list[str] = []
    for chunk in chunks:
        if not isinstance(chunk, dict):
            continue
        if isinstance(chunk.get("delta"), str):
            parts.append(chunk["delta"])
        if isinstance(chunk.get("text"), str):
            parts.append(chunk["text"])
        for choice in chunk.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            message = choice.get("message")
            if isinstance(delta, dict):
                parts.append(_content_text(delta.get("content")))
            elif isinstance(message, dict):
                parts.append(_content_text(message.get("content")))
    return "".join(parts)


def _completion_text(payload: Any) -> str:
    messages = _assistant_messages(payload, "")
    return "\n\n".join(messages)


def _assistant_messages(payload: Any, fallback: str) -> list[str]:
    messages: list[str] = []
    if isinstance(payload, dict):
        for item in payload.get("output") or []:
            text = _response_output_text(item)
            if text:
                messages.append(text)
        for choice in payload.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            delta = choice.get("delta")
            text = ""
            if isinstance(message, dict):
                text = _content_text(message.get("content"))
            elif isinstance(delta, dict):
                text = _content_text(delta.get("content"))
            if text:
                messages.append(text)
        chunks = payload.get("chunks")
        if isinstance(chunks, list):
            stream_text = _stream_text(chunks)
            if stream_text:
                messages.append(stream_text)
    if not messages and fallback:
        messages.append(fallback)
    return messages


def _response_output_text(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    if item.get("type") != "message" and "content" not in item:
        return ""

    parts: list[str] = []
    content = item.get("content")
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict):
                if part.get("type") in {"output_text", "text"}:
                    parts.append(_content_text(part.get("text")))
            else:
                parts.append(_content_text(part))
    elif content is not None:
        parts.append(_content_text(content))
    return "".join(parts)


def _request_kind(endpoint: str) -> str:
    if endpoint.endswith("/responses"):
        return "responses"
    if endpoint.endswith("/chat/completions"):
        return "chat"
    return "unknown"


def _infer_endpoint(request: dict[str, Any]) -> str:
    if "input" in request or "instructions" in request:
        return "/v1/responses"
    return "/v1/chat/completions"


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
