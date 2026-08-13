"""
middleware.py – SentinelMiddleware: intercepts every HTTP request.

Responsibilities:
  • Extract principal identity (X-User-ID header or JWT Bearer sub)
  • Normalize path to route template
  • Time the request
  • Emit ApiEvent to the detection engine (sync, for blocking support)
  • Return HTTP 403 when decision == BLOCK and enforcement_mode is True
"""

from __future__ import annotations

import re
import time
import uuid
from datetime import datetime

from jose import jwt, JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from config import settings
from engine import detection_engine
from inventory import normalize_route, extract_object_info
from models import ApiEvent, Decision

# Paths that the sentinel should never intercept
_SKIP_PATHS = {
    "/health", "/docs", "/openapi.json", "/redoc", "/favicon.ico",
    # Sentinel's own dashboard data endpoints
    "/api/v1/inventory", "/api/v1/alerts", "/api/v1/events",
    "/api/v1/stats", "/api/v1/stream",
}
# Skip static files and Sentinel admin routes (hot-reload, ownership view)
_SKIP_PREFIXES = ("/api/v1/admin", "/static", "/_", "/@", "/node_modules")


def _extract_principal(request: Request) -> str:
    """Try X-User-ID header first, then JWT Bearer token."""
    uid = request.headers.get("X-User-ID")
    if uid:
        return uid

    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:]
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
            return str(payload.get("sub", "anonymous"))
        except JWTError:
            pass

    return "anonymous"


class SentinelMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # ── Skip sentinel paths ───────────────────────────────────────────────
        if path in _SKIP_PATHS or any(path.startswith(p) for p in _SKIP_PREFIXES):
            return await call_next(request)

        # ── Build event skeleton ──────────────────────────────────────────────
        principal_id   = _extract_principal(request)
        route_template = normalize_route(path)
        object_type, object_id = extract_object_info(path)
        start_ns       = time.perf_counter_ns()

        event = ApiEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            principal_id=principal_id,
            method=request.method,
            path=path,
            route_template=route_template,
            object_type=object_type,
            object_id=object_id,
            user_agent=request.headers.get("User-Agent", ""),
            client_ip=request.client.host if request.client else "unknown",
        )

        # ── Run detection engine synchronously to support blocking ────────────
        event = await detection_engine.process_event_sync(event)

        # ── Block if needed ───────────────────────────────────────────────────
        if event.decision == Decision.BLOCK:
            return JSONResponse(
                status_code=403,
                content={
                    "status":     "BLOCKED",
                    "reason":     "API Sentinel: request blocked",
                    "alert_type": event.signals[0] if event.signals else "anomaly",
                    "signals":    event.signals,
                    "risk_score": event.risk_score,
                    "event_id":   event.id,
                },
            )

        # ── Forward to the actual handler ──────────────────────────────────────
        response: Response = await call_next(request)

        # ── Update event with response data ───────────────────────────────────
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
        event.status_code = response.status_code
        event.latency_ms  = round(elapsed_ms, 2)

        return response
