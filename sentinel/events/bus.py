"""In-process async pub/sub that fans each TurnEvent out to SSE subscribers + durable sinks.

Publishing is async and happens from the request coroutine (after the blocking forward pass has
run in a threadpool), so we never touch an asyncio.Queue from a foreign thread.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable

from sentinel.events.schema import TurnEvent

Sink = Callable[[dict], None]


class EventBus:
    def __init__(self, history: int = 200) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._sinks: list[Sink] = []
        self._recent: deque[dict] = deque(maxlen=history)

    def add_sink(self, sink: Sink) -> None:
        self._sinks.append(sink)

    async def publish(self, event: TurnEvent) -> None:
        d = event.model_dump(mode="json")
        self._recent.append(d)
        for sink in self._sinks:
            sink(d)
        for q in list(self._subscribers):
            q.put_nowait(d)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def recent(self) -> list[dict]:
        return list(self._recent)
