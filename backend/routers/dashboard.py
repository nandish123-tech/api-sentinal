"""
routers/dashboard.py – Dashboard and admin API endpoints.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import AsyncIterator

from fastapi import APIRouter, Query
from sse_starlette.sse import EventSourceResponse

from config import settings
from event_bus import alert_bus
from inventory import inventory_manager
from models import (
    ApiEvent, DashboardStats, InventoryEntry, SentinelAlert,
)
from store import AlertStore, EventStore, InventoryStore

router = APIRouter(prefix="/api/v1", tags=["dashboard"])


# ── Inventory ────────────────────────────────────────────────────────────────

@router.get("/inventory", response_model=list[InventoryEntry])
async def get_inventory():
    """Return the full live API inventory with classification."""
    return await InventoryStore.all()


# ── Alerts ───────────────────────────────────────────────────────────────────

@router.get("/alerts", response_model=list[SentinelAlert])
async def get_alerts(
    limit: int = Query(default=100, le=500),
    alert_type: str | None = Query(default=None),
):
    """Return recent security alerts, optionally filtered by type."""
    return await AlertStore.recent(limit=limit, alert_type=alert_type)


# ── Events ───────────────────────────────────────────────────────────────────

@router.get("/events", response_model=list[ApiEvent])
async def get_events(limit: int = Query(default=100, le=500)):
    """Return recent API events."""
    return await EventStore.recent(limit=limit)


# ── Stats ────────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=DashboardStats)
async def get_stats():
    """Return aggregated dashboard statistics."""
    (
        total_events,
        total_alerts,
        blocked,
        epm,
        by_type,
        by_severity,
        shadow,
        deprecated_active,
        all_inventory,
    ) = await asyncio.gather(
        EventStore.total_count(),
        AlertStore.total_count(),
        EventStore.blocked_count(),
        EventStore.events_per_minute(),
        AlertStore.count_by_type(),
        AlertStore.count_by_severity(),
        InventoryStore.shadow_count(),
        InventoryStore.deprecated_active_count(),
        InventoryStore.all(),
    )

    # Top 5 riskiest routes
    sorted_inv = sorted(all_inventory, key=lambda e: e.risk_score_avg, reverse=True)
    top_risky = [
        {
            "route":      e.route_template,
            "method":     e.method,
            "risk":       e.risk_score_avg,
            "status":     e.status.value,
            "req_count":  e.request_count,
        }
        for e in sorted_inv[:5]
    ]

    coverage = await InventoryStore.coverage_percent(inventory_manager.declared_count)

    return DashboardStats(
        total_events=total_events,
        total_alerts=total_alerts,
        bola_alerts=by_type.get("BOLA", 0) + by_type.get("ENUMERATION", 0),
        shadow_apis=shadow,
        deprecated_active=deprecated_active,
        blocked_requests=blocked,
        events_per_minute=epm,
        inventory_coverage=coverage,
        top_risky_routes=top_risky,
        alert_type_counts=by_type,
        severity_counts=by_severity,
    )


# ── SSE Real-time Alert Stream ────────────────────────────────────────────────

@router.get("/stream")
async def stream_alerts(request):
    """Server-Sent Events: push new alerts to the dashboard in real time."""

    async def _generator() -> AsyncIterator[dict]:
        q = await alert_bus.subscribe()
        try:
            # Send a heartbeat every 15 s to keep connection alive
            while True:
                try:
                    alert: SentinelAlert = await asyncio.wait_for(q.get(), timeout=15)
                    payload = alert.model_dump(mode="json")
                    yield {"event": "alert", "data": json.dumps(payload)}
                except asyncio.TimeoutError:
                    yield {"event": "heartbeat", "data": "ping"}
                # Check if client disconnected
                if await request.is_disconnected():
                    break
        finally:
            await alert_bus.unsubscribe(q)

    return EventSourceResponse(_generator())


# ── Admin: reload contract ────────────────────────────────────────────────────

@router.post("/admin/reload-contract")
async def reload_contract():
    """Hot-reload the declared OpenAPI contract."""
    count = inventory_manager.load_contract(settings.openapi_contract_path)
    return {"status": "reloaded", "routes_loaded": count, "timestamp": datetime.utcnow().isoformat()}


# ── Admin: ownership map ──────────────────────────────────────────────────────

@router.get("/admin/ownership")
async def get_ownership():
    """Return all entries in the ownership map (for debugging)."""
    from ownership import ownership_map
    return ownership_map.all_entries()
