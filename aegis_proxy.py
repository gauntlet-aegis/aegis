import json
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse

from aegis_events import ObservationStore
from aegis_tap import Context, ContextInterceptor
from aegis_viewer import VIEWER_HTML
from config import AEGIS_EVENT_DIR, AEGIS_PORT, UPSTREAM_URL


app = FastAPI(title="Aegis Proxy")
interceptor = ContextInterceptor()
events = ObservationStore(event_dir=AEGIS_EVENT_DIR)
CHAT_COMPLETIONS_OPENAPI = {"requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}, "example": {"model": "qwen2.5-coder-7b-instruct", "messages": [{"role": "system", "content": "You are concise."}, {"role": "assistant", "content": "Retrieved note: this is untrusted context."}, {"role": "user", "content": "Say hello in five words."}], "temperature": 0, "max_tokens": 32, "stream": False}}}}}
RESPONSES_OPENAPI = {"requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}, "example": {"model": "qwen2.5-coder-7b-instruct", "instructions": "You are concise.", "input": "Say hello in five words.", "temperature": 0, "max_output_tokens": 32, "stream": False}}}}}

DROP_REQUEST_HEADERS = {"host", "content-length"}
DROP_RESPONSE_HEADERS = DROP_REQUEST_HEADERS | {
    "connection", "content-encoding", "keep-alive", "proxy-authenticate", "te",
    "proxy-authorization", "trailer", "transfer-encoding", "upgrade",
}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "upstream": UPSTREAM_URL}


@app.get("/", response_class=HTMLResponse)
@app.get("/viewer", response_class=HTMLResponse)
async def viewer() -> str:
    return VIEWER_HTML


@app.get("/aegis/events")
async def list_events() -> list[dict[str, Any]]:
    return events.summaries()


@app.get("/aegis/events/{event_id}")
async def get_event(event_id: int) -> dict[str, Any]:
    event = events.detail(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.post("/v1/chat/completions", openapi_extra=CHAT_COMPLETIONS_OPENAPI)
async def chat_completions(request: Request) -> Response:
    return await _proxy_model_request(request, "/v1/chat/completions", _context_from_chat_payload)


@app.post("/v1/responses", openapi_extra=RESPONSES_OPENAPI)
async def responses(request: Request) -> Response:
    return await _proxy_model_request(request, "/v1/responses", _context_from_responses_payload)


async def _proxy_model_request(request: Request, endpoint: str, context_builder: Any) -> Response:
    body = await request.body()
    payload = _json_payload(body)

    raw = context_builder(payload)
    seen = interceptor.process(raw)
    _print_request_context(endpoint, payload)
    event = events.start(payload, raw, seen, UPSTREAM_URL, endpoint=endpoint)

    # TODO: streaming. For now, stream=true passes upstream and buffers here.
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            upstream = await client.post(
                f"{UPSTREAM_URL}{endpoint}",
                content=body,
                headers=_headers(request.headers.items(), DROP_REQUEST_HEADERS),
                params=request.query_params,
            )
    except httpx.RequestError:
        events.finish(event, status=502, error="Bad Gateway")
        return Response("Bad Gateway", status_code=502, media_type="text/plain")

    events.finish(
        event,
        status=upstream.status_code,
        content_type=upstream.headers.get("content-type", ""),
        response_bytes=len(upstream.content),
        response_content=upstream.content,
    )
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_headers(upstream.headers.items(), DROP_RESPONSE_HEADERS),
        media_type=upstream.headers.get("content-type"),
    )


def _json_payload(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body or b"{}")
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


# LIMITATION: OpenAI-compatible HTTP payloads preserve API/role-level provenance
# only. Full span provenance needs a cooperating client/header.
def _context_from_chat_payload(payload: dict[str, Any]) -> Context:
    messages = payload.get("messages")
    if not isinstance(messages, list):
        messages = []

    last_user_index = None
    for index, message in enumerate(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            last_user_index = index

    system_parts: list[str] = []
    other_parts: list[str] = []
    user_query = ""

    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue

        role = str(message.get("role") or "unknown")
        content = _content_to_text(message.get("content"))
        if role == "system":
            system_parts.append(content)
        elif index == last_user_index:
            user_query = content
        else:
            other_parts.append(f"{role}: {content}")

    return Context(
        system_prompt="\n".join(system_parts),
        credentials={},
        untrusted_content="\n".join(other_parts),
        user_query=user_query,
    )


def _context_from_responses_payload(payload: dict[str, Any]) -> Context:
    system_parts = [_content_to_text(payload.get("instructions"))]
    input_items = _responses_input_items(payload.get("input"))

    last_user_index = None
    for index, item in enumerate(input_items):
        role, _text = _responses_item_role_and_text(item)
        if role == "user":
            last_user_index = index

    other_parts: list[str] = []
    user_query = ""

    for index, item in enumerate(input_items):
        role, text = _responses_item_role_and_text(item)
        if role in {"system", "developer"}:
            system_parts.append(text)
        elif index == last_user_index:
            user_query = text
        else:
            other_parts.append(f"{role}: {text}")

    return Context(
        system_prompt="\n".join(part for part in system_parts if part),
        credentials={},
        untrusted_content="\n".join(other_parts),
        user_query=user_query,
    )


def _responses_input_items(input_value: Any) -> list[Any]:
    if isinstance(input_value, list):
        return input_value
    if input_value is None:
        return []
    return [input_value]


def _responses_item_role_and_text(item: Any) -> tuple[str, str]:
    if not isinstance(item, dict):
        return "user", _content_to_text(item)

    role = item.get("role")
    if not isinstance(role, str) or not role:
        role = str(item.get("type") or "input")

    if "content" in item:
        return role, _content_to_text(item.get("content"))
    if "text" in item:
        return role, _content_to_text(item.get("text"))
    return role, _content_to_text(item)


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(part for part in (_content_to_text(item) for item in content) if part)
    if isinstance(content, dict):
        text = content.get("text")
        if isinstance(text, str):
            return text
        if "content" in content:
            return _content_to_text(content.get("content"))
    try:
        return json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    except TypeError:
        return str(content)


def _headers(items: Any, drop: set[str]) -> dict[str, str]:
    return {key: value for key, value in items if key.lower() not in drop}


def _print_request_context(endpoint: str, payload: dict[str, Any]) -> None:
    print("=" * 78)
    print("AEGIS REQUEST CONTEXT")
    print("=" * 78)
    data: dict[str, Any] = {
        "endpoint": endpoint,
        "model": payload.get("model"),
    }
    if "messages" in payload:
        data["messages"] = payload.get("messages", [])
    if "instructions" in payload:
        data["instructions"] = payload.get("instructions")
    if "input" in payload:
        data["input"] = payload.get("input")
    data["params"] = {
        key: value
        for key, value in payload.items()
        if key not in {"model", "messages", "instructions", "input"}
    }
    print(json.dumps(data, indent=2, ensure_ascii=False))
    print("=" * 78)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("aegis_proxy:app", host="127.0.0.1", port=AEGIS_PORT)
