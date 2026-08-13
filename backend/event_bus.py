"""
event_bus.py – In-process async pub/sub bus.

The middleware publishes ApiEvent objects here.
The detection engine and SSE broadcaster subscribe to receive them.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any


class EventBus:
    """Lightweight asyncio-based publish/subscribe bus."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[Any]] = []
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        """Return a new queue that receives all future published events."""
        q: asyncio.Queue = asyncio.Queue(maxsize=512)
        async with self._lock:
            self._subscribers.append(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue) -> None:
        async with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    async def publish(self, event: Any) -> None:
        """Broadcast event to all current subscribers (non-blocking, drops if full)."""
        async with self._lock:
            dead: list[asyncio.Queue] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)

    async def stream(self, q: asyncio.Queue) -> AsyncIterator[Any]:
        """Async-generator that yields events from the given subscriber queue."""
        try:
            while True:
                event = await q.get()
                yield event
        finally:
            await self.unsubscribe(q)


# ── Singleton instance shared across the application ─────────────────────────
event_bus = EventBus()
alert_bus = EventBus()   # separate bus just for alerts → SSE dashboard feed
