import json
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response

from aegis_tap import Context, ContextInterceptor, view
from config import AEGIS_PORT, UPSTREAM_URL


app = FastAPI(title="Aegis Proxy")
interceptor = ContextInterceptor()
CHAT_COMPLETIONS_OPENAPI = {"requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}, "example": {"model": "qwen2.5-coder-7b-instruct", "messages": [{"role": "system", "content": "You are concise."}, {"role": "assistant", "content": "Retrieved note: this is untrusted context."}, {"role": "user", "content": "Say hello in five words."}], "temperature": 0, "max_tokens": 32, "stream": False}}}}}

DROP_REQUEST_HEADERS = {"host", "content-length"}
DROP_RESPONSE_HEADERS = DROP_REQUEST_HEADERS | {
    "connection", "content-encoding", "keep-alive", "proxy-authenticate", "te",
    "proxy-authorization", "trailer", "transfer-encoding", "upgrade",
}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "upstream": UPSTREAM_URL}


@app.post("/v1/chat/completions", openapi_extra=CHAT_COMPLETIONS_OPENAPI)
async def chat_completions(request: Request) -> Response:
    body = await request.body()
    payload = _json_payload(body)

    raw = _context_from_payload(payload)
    seen = interceptor.process(raw)
    view(raw, seen, interceptor)

    # TODO: streaming. For now, stream=true passes upstream and buffers here.
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            upstream = await client.post(
                f"{UPSTREAM_URL}/v1/chat/completions",
                content=body,
                headers=_headers(request.headers.items(), DROP_REQUEST_HEADERS),
                params=request.query_params,
            )
    except httpx.RequestError:
        return Response("Bad Gateway", status_code=502, media_type="text/plain")

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


# LIMITATION: OpenAI chat payloads preserve role-level provenance only. Full span
# provenance needs a cooperating client/header; role granularity is enough for v1.
def _context_from_payload(payload: dict[str, Any]) -> Context:
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


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    try:
        return json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    except TypeError:
        return str(content)


def _headers(items: Any, drop: set[str]) -> dict[str, str]:
    return {key: value for key, value in items if key.lower() not in drop}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("aegis_proxy:app", host="127.0.0.1", port=AEGIS_PORT)
