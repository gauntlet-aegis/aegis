"""FastAPI proxy: OpenAI-compatible chat endpoint + SSE event stream + embedded dashboard.

Clients point their base URL here and change nothing else. Each proxied turn runs the full
detection pipeline and emits a TurnEvent to the dashboard over SSE.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse

from sentinel.config import REPO_ROOT, Settings, load_settings
from sentinel.events.bus import EventBus
from sentinel.events.sinks import JSONLSink
from sentinel.model.host import make_host
from sentinel.proxy.orchestrator import Orchestrator

DASHBOARD = REPO_ROOT / "dashboard" / "index.html"


def create_app(settings: Settings | None = None, detectors: dict | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from sentinel.proxy.bootstrap import build_detectors

        host = make_host(settings)
        det = detectors if detectors is not None else build_detectors(settings)
        app.state.settings = settings
        app.state.bus = EventBus()
        app.state.bus.add_sink(JSONLSink(settings.event_dir))
        app.state.orch = Orchestrator(settings, host, detectors=det)
        yield

    app = FastAPI(title="Sentinel", lifespan=lifespan)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "mode": settings.mode, "model": settings.model_id}

    @app.get("/", response_class=HTMLResponse)
    async def index():
        if DASHBOARD.exists():
            return HTMLResponse(DASHBOARD.read_text())
        return HTMLResponse("<h1>Sentinel</h1><p>dashboard/index.html not found</p>")

    @app.get("/events")
    async def events(request: Request):
        bus: EventBus = app.state.bus

        async def gen():
            for ev in bus.recent():
                yield {"event": "turn", "data": json.dumps(ev)}
            q = bus.subscribe()
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        ev = await asyncio.wait_for(q.get(), timeout=15.0)
                        yield {"event": "turn", "data": json.dumps(ev)}
                    except asyncio.TimeoutError:
                        yield {"event": "ping", "data": "{}"}
            finally:
                bus.unsubscribe(q)

        return EventSourceResponse(gen())

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        body = await request.json()
        messages = body.get("messages", [])
        ext = body.get("x_sentinel", {}) or {}

        conversation_id = (
            request.headers.get("X-Sentinel-Conversation")
            or ext.get("conversation_id")
            or str(uuid.uuid4())
        )
        attack_label = request.headers.get("X-Sentinel-Attack") or ext.get("attack_label")
        real_secrets = ext.get("real_secrets") or {}

        orch: Orchestrator = app.state.orch
        st = orch.store.get(conversation_id)
        turn_index = st.turn_count

        text, event = await asyncio.to_thread(
            orch.handle,
            conversation_id,
            turn_index,
            messages,
            attack_label=attack_label,
            real_secrets=real_secrets,
        )
        st.turn_count += 1
        await app.state.bus.publish(event)

        return JSONResponse(
            {
                "id": f"chatcmpl-{event.turn_id}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": settings.model_id,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": "stop",
                    }
                ],
                "x_sentinel": {
                    "action": event.action,
                    "caught_by": event.caught_by,
                    "landed": event.landed,
                    "conversation_id": conversation_id,
                    "turn_index": turn_index,
                },
            }
        )

    return app
